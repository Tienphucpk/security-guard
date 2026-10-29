"""
Rule Engine Module
Quản lý và thực thi tuần tự tất cả các luật phát hiện an ninh đối với từng log request.
"""

from typing import List, Dict, Any, Optional
import os
import json

from rules.rule_base import BaseDetectionRule
from .risk_scorer import RiskScorer
from .detectors.brute_force import BruteForceDetector
from .detectors.scanner import ScannerDetector
from .detectors.abnormal_traffic import AbnormalTrafficDetector
from .detectors.suspicious_url import SuspiciousUrlDetector
from .detectors.sql_injection import SqlInjectionDetector
from .detectors.xss import XssDetector
from .detectors.path_traversal import PathTraversalDetector
from .detectors.command_injection import CommandInjectionDetector


class RuleEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../rules")
        )
        self.detectors: List[BaseDetectionRule] = []
        self._initialize_detectors()

    def _initialize_detectors(self):
        """Khởi tạo danh sách các bộ dò luật"""
        self.brute_force = BruteForceDetector()
        self.scanner = ScannerDetector()
        self.abnormal_traffic = AbnormalTrafficDetector()
        self.suspicious_url = SuspiciousUrlDetector()
        self.sql_injection = SqlInjectionDetector()
        self.xss = XssDetector()
        self.path_traversal = PathTraversalDetector()
        self.command_injection = CommandInjectionDetector()

        self.detectors = [
            self.brute_force,
            self.scanner,
            self.abnormal_traffic,
            self.suspicious_url,
            self.sql_injection,
            self.xss,
            self.path_traversal,
            self.command_injection
        ]

    def reload_rules(self):
        """Reload detector configurations from JSON rule files"""
        self._initialize_detectors()

    def set_rule_enabled(self, rule_id_or_code: str, enabled: bool):
        """Bật/tắt 1 rule theo mã hoặc ID"""
        for d in self.detectors:
            if d.rule_id.lower() == rule_id_or_code.lower() or d.category.lower() == rule_id_or_code.lower():
                d.enabled = enabled

    def analyze(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Chạy toàn bộ các rule trên bản ghi log.
        KHÔNG dừng ở rule đầu tiên, thu thập tất cả detections.
        """
        detections: List[Dict[str, Any]] = []

        for detector in self.detectors:
            try:
                res = detector.evaluate(log_entry)
                if res:
                    detections.append(res)
            except Exception as e:
                # Log exception quietly, do not crash engine
                print(f"[RULE ENGINE ERROR] Detector {detector.name} error: {e}")

        # Tính toán điểm rủi ro tổng hợp
        risk_score, severity = RiskScorer.calculate(detections)
        is_detected = len(detections) > 0

        return {
            "detected": is_detected,
            "risk_score": risk_score,
            "severity": severity,
            "detections": detections
        }

    def reset_state(self):
        """Reset historical sliding windows (dùng trong test)"""
        self.brute_force.reset_history()
        self.abnormal_traffic.reset_history()
