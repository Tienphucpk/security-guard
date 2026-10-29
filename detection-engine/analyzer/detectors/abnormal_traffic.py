"""
Abnormal Traffic Rate Detector
Phát hiện tần suất request đột biến từ cùng một địa chỉ IP.
"""

import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from collections import defaultdict
import os
import json

from rules.rule_base import BaseDetectionRule


class AbnormalTrafficDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/abnormal_traffic.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-TRAFFIC-001"),
            name=cfg.get("name", "Abnormal Traffic Rate Detection"),
            severity=cfg.get("severity", "MEDIUM"),
            score=cfg.get("score", 40.0),
            enabled=cfg.get("enabled", True),
            category="ABNORMAL_TRAFFIC",
            description=cfg.get("description", "High frequency traffic spike from single IP")
        )

        self.threshold = int(cfg.get("threshold", 100))
        self.window_seconds = float(cfg.get("window_seconds", 60))
        self.history: Dict[str, List[float]] = defaultdict(list)

    def _parse_timestamp(self, ts_raw: Any) -> float:
        if isinstance(ts_raw, (int, float)):
            return float(ts_raw)
        if isinstance(ts_raw, str):
            try:
                clean_ts = ts_raw.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                return dt.timestamp()
            except Exception:
                pass
        return time.time()

    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        # Exclude internal telemetry & health polling endpoints to avoid false positives in development
        raw_url = str(log_entry.get("url") or "").lower().split("?")[0]
        if raw_url in ["/api/health", "/api/logs", "/api/logs/stats", "/api/alerts", "/api/alerts/stats"]:
            return None

        ip = str(log_entry.get("ip") or "127.0.0.1").strip()
        req_time = self._parse_timestamp(log_entry.get("timestamp"))

        current_history = [
            t for t in self.history[ip]
            if (req_time - t) <= self.window_seconds
        ]
        current_history.append(req_time)
        self.history[ip] = current_history

        # If count strictly exceeds or reaches threshold:
        # Prompt says: "> 100 requests / 60 seconds / IP"
        if len(current_history) > self.threshold:
            return {
                "rule_id": self.rule_id,
                "type": "ABNORMAL_TRAFFIC",
                "severity": self.severity,
                "score": self.score,
                "reason": (
                    f"Traffic anomaly: {len(current_history)} requests in {int(self.window_seconds)}s "
                    f"from IP {ip} (Threshold: >{self.threshold})"
                ),
                "matched_pattern": f"{len(current_history)} reqs / {int(self.window_seconds)}s"
            }

        return None

    def reset_history(self):
        self.history.clear()
