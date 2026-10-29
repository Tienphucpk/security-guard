"""
SQL Injection Detector
Phát hiện các mẫu tấn công SQL Injection trong URL, query parameters và payload.
"""

from typing import Dict, Any, Optional, List
import re
import os
import json

from rules.rule_base import BaseDetectionRule


class SqlInjectionDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/sql_injection.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-SQLI-001"),
            name=cfg.get("name", "SQL Injection Signature Detection"),
            severity=cfg.get("severity", "HIGH"),
            score=cfg.get("score", 80.0),
            enabled=cfg.get("enabled", True),
            category="SQL_INJECTION",
            description=cfg.get("description", "SQL Injection signature matched in URL/payload")
        )

        raw_patterns = cfg.get("patterns", [
            "union select",
            "union all select",
            "' or '1'='1",
            "' or 1=1",
            "\" or \"1\"=\"1",
            "information_schema.",
            "sleep(",
            "benchmark(",
            "waitfor delay"
        ])
        self.patterns = [p.lower().strip() for p in raw_patterns]

        # Regex patterns for flexible SQLi variants (e.g. ' OR 1=1, ' OR 'x'='x, -- comment)
        self.regex_patterns = [
            re.compile(r"'\s*or\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.IGNORECASE),
            re.compile(r"\"\s*or\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.IGNORECASE),
            re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE),
            re.compile(r"information_schema(?:\.|\s)", re.IGNORECASE),
            re.compile(r"(?:sleep|benchmark)\s*\(", re.IGNORECASE),
            re.compile(r"waitfor\s+delay", re.IGNORECASE)
        ]

    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        # Inspect url, query parameters, and body
        raw_url = str(log_entry.get("url") or "")
        normalized_url = self.normalize_str(raw_url)

        body_raw = str(log_entry.get("body") or "")
        normalized_body = self.normalize_str(body_raw)

        inspect_targets = [normalized_url]
        if normalized_body:
            inspect_targets.append(normalized_body)

        for target in inspect_targets:
            # 1. Exact pattern substring check
            for pat in self.patterns:
                if pat in target:
                    return {
                        "rule_id": self.rule_id,
                        "type": "SQL_INJECTION",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Matched SQL injection pattern: '{pat}'",
                        "matched_pattern": pat
                    }

            # 2. Regex check for variations
            for rx in self.regex_patterns:
                match = rx.search(target)
                if match:
                    return {
                        "rule_id": self.rule_id,
                        "type": "SQL_INJECTION",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Matched SQL injection syntax pattern: '{match.group(0)}'",
                        "matched_pattern": match.group(0)
                    }

        return None
