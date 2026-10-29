"""
Vulnerability Scanner Detector
Phát hiện các công cụ dò quét bảo mật tự động thông qua User-Agent và đặc trưng request.
"""

from typing import Dict, Any, Optional, List
import os
import json

from rules.rule_base import BaseDetectionRule


class ScannerDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/scanner.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-SCAN-001"),
            name=cfg.get("name", "Security Scanner Detection"),
            severity=cfg.get("severity", "HIGH"),
            score=cfg.get("score", 60.0),
            enabled=cfg.get("enabled", True),
            category="SCANNER_DETECTION",
            description=cfg.get("description", "Vulnerability scanner signature detected")
        )

        raw_signatures = cfg.get("signatures", [
            "sqlmap",
            "nikto",
            "nmap",
            "dirbuster",
            "gobuster",
            "wpscan",
            "masscan"
        ])
        self.signatures = [s.lower().strip() for s in raw_signatures]

    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        # Check User-Agent
        ua_raw = log_entry.get("userAgent") or log_entry.get("user_agent") or ""
        normalized_ua = self.normalize_str(ua_raw)

        for sig in self.signatures:
            if sig in normalized_ua:
                return {
                    "rule_id": self.rule_id,
                    "type": "SCANNER_DETECTION",
                    "severity": self.severity,
                    "score": self.score,
                    "reason": f"Automated security scanner detected in User-Agent: '{sig}'",
                    "matched_pattern": sig
                }

        return None
