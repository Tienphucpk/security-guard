"""
Suspicious URL and Sensitive Probe Detector
Phát hiện các truy vấn đến file nhạy cảm (.env, .git, config, admin endpoints).
"""

from typing import Dict, Any, Optional, List
import os
import json

from rules.rule_base import BaseDetectionRule


class SuspiciousUrlDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/suspicious_url.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-URL-001"),
            name=cfg.get("name", "Suspicious URL and Sensitive Probe Detection"),
            severity=cfg.get("severity", "MEDIUM"),
            score=cfg.get("score", 35.0),
            enabled=cfg.get("enabled", True),
            category="SUSPICIOUS_URL",
            description=cfg.get("description", "Sensitive file probe or administrative exposure attempt")
        )

        raw_patterns = cfg.get("patterns", [
            "/.env",
            "/.git/head",
            "/.git/config",
            "/wp-login.php",
            "/web.config",
            "/config.php",
            "/phpinfo.php",
            "/.ds_store",
            "/server-status"
        ])
        self.patterns = [p.lower().strip() for p in raw_patterns]

    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        raw_url = str(log_entry.get("url") or "")
        normalized_url = self.normalize_str(raw_url).split("?")[0]

        for pat in self.patterns:
            if pat in normalized_url:
                return {
                    "rule_id": self.rule_id,
                    "type": "SUSPICIOUS_URL",
                    "severity": self.severity,
                    "score": self.score,
                    "reason": f"Probe to sensitive path or administrative endpoint: '{pat}'",
                    "matched_pattern": pat
                }

        return None
