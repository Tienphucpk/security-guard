"""
Cross-Site Scripting (XSS) Detector
Phát hiện các thẻ script và mã thực thi JavaScript độc hại trong URL, query, và payload.
"""

from typing import Dict, Any, Optional, List
import re
import os
import json

from rules.rule_base import BaseDetectionRule


class XssDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/xss.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-XSS-001"),
            name=cfg.get("name", "Cross-Site Scripting (XSS) Detection"),
            severity=cfg.get("severity", "HIGH"),
            score=cfg.get("score", 75.0),
            enabled=cfg.get("enabled", True),
            category="XSS",
            description=cfg.get("description", "Cross-Site Scripting signature matched in URL/payload")
        )

        raw_patterns = cfg.get("patterns", [
            "<script>",
            "</script>",
            "onload=",
            "onerror=",
            "javascript:",
            "<iframe",
            "<svg",
            "document.cookie"
        ])
        self.patterns = [p.lower().strip() for p in raw_patterns]

        # Regex for tags with attributes e.g. <script src=...>, <img ... onerror=...>, <svg/onload=...>
        self.regex_patterns = [
            re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE),
            re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
            re.compile(r"<\s*iframe\b[^>]*>", re.IGNORECASE),
            re.compile(r"<\s*svg\b[^>]*>", re.IGNORECASE),
            re.compile(r"\bon\w+\s*=", re.IGNORECASE),
            re.compile(r"javascript\s*:", re.IGNORECASE),
            re.compile(r"document\.cookie", re.IGNORECASE)
        ]

    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        raw_url = str(log_entry.get("url") or "")
        normalized_url = self.normalize_str(raw_url)

        body_raw = str(log_entry.get("body") or "")
        normalized_body = self.normalize_str(body_raw)

        inspect_targets = [normalized_url]
        if normalized_body:
            inspect_targets.append(normalized_body)

        for target in inspect_targets:
            # 1. Exact string patterns
            for pat in self.patterns:
                if pat in target:
                    return {
                        "rule_id": self.rule_id,
                        "type": "XSS",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Cross-Site Scripting tag/handler detected: '{pat}'",
                        "matched_pattern": pat
                    }

            # 2. Regex check
            for rx in self.regex_patterns:
                match = rx.search(target)
                if match:
                    return {
                        "rule_id": self.rule_id,
                        "type": "XSS",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Cross-Site Scripting syntax pattern detected: '{match.group(0)}'",
                        "matched_pattern": match.group(0)
                    }

        return None
