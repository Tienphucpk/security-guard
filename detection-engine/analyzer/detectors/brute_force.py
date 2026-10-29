"""
Brute Force Attack Detector
Phát hiện nhiều lần đăng nhập thất bại liên tiếp từ cùng một địa chỉ IP.
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from collections import defaultdict
import os
import json

from rules.rule_base import BaseDetectionRule


class BruteForceDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        # Try loading from rules/brute_force.json if not passed
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/brute_force.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-BF-001"),
            name=cfg.get("name", "Brute Force Login Detection"),
            severity=cfg.get("severity", "HIGH"),
            score=cfg.get("score", 70.0),
            enabled=cfg.get("enabled", True),
            category="BRUTE_FORCE",
            description=cfg.get("description", "Multiple failed login attempts from same IP")
        )

        self.threshold = int(cfg.get("threshold", 5))
        self.window_seconds = float(cfg.get("window_seconds", 300))
        self.target_path = cfg.get("target_path", "/login").lower()
        self.failure_status_codes = set(cfg.get("failure_status_codes", [401]))

        # In-memory sliding window history: ip -> list of timestamps
        self.history: Dict[str, List[float]] = defaultdict(list)

    def _parse_timestamp(self, ts_raw: Any) -> float:
        if isinstance(ts_raw, (int, float)):
            return float(ts_raw)
        if isinstance(ts_raw, str):
            try:
                # ISO format parse
                clean_ts = ts_raw.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                return dt.timestamp()
            except Exception:
                pass
        return time.time()

    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        ip = str(log_entry.get("ip") or "127.0.0.1").strip()
        method = str(log_entry.get("method") or "GET").upper()
        raw_url = str(log_entry.get("url") or "")
        normalized_url = self.normalize_str(raw_url).split("?")[0]
        status_code = int(log_entry.get("statusCode") or log_entry.get("status_code") or 200)

        # Check if request is a failed login attempt (POST to login with status 401)
        is_login = (self.target_path in normalized_url) and (method == "POST")
        is_failure = status_code in self.failure_status_codes

        if not (is_login and is_failure):
            return None

        req_time = self._parse_timestamp(log_entry.get("timestamp"))

        # Prune expired timestamps for this IP
        current_history = [
            t for t in self.history[ip]
            if (req_time - t) <= self.window_seconds
        ]
        current_history.append(req_time)
        self.history[ip] = current_history

        if len(current_history) >= self.threshold:
            return {
                "rule_id": self.rule_id,
                "type": "BRUTE_FORCE",
                "severity": self.severity,
                "score": self.score,
                "reason": (
                    f"Detected {len(current_history)} failed login attempts from IP {ip} "
                    f"within {int(self.window_seconds)}s (Threshold: {self.threshold})"
                ),
                "matched_pattern": f"{len(current_history)} failed attempts"
            }

        return None

    def reset_history(self):
        """Helper to reset IP history for testing"""
        self.history.clear()
