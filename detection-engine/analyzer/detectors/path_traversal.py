"""
Path Traversal Detector
Phát hiện các hành vi leo thang thư mục (Directory Traversal) và đọc tệp nội bộ (LFI).
"""

from typing import Dict, Any, Optional, List
import re
import os
import json
import urllib.parse

from rules.rule_base import BaseDetectionRule


class PathTraversalDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/path_traversal.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-TRAV-001"),
            name=cfg.get("name", "Path Traversal & Directory Climbing Detection"),
            severity=cfg.get("severity", "HIGH"),
            score=cfg.get("score", 75.0),
            enabled=cfg.get("enabled", True),
            category="PATH_TRAVERSAL",
            description=cfg.get("description", "Directory traversal or local file inclusion patterns detected")
        )

        raw_patterns = cfg.get("patterns", [
            "../",
            "..\\",
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%5c",
            "..%5c",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "windows/win.ini",
            "windows\\win.ini",
            "boot.ini",
            "system.ini"
        ])
        self.patterns = [p.lower().strip() for p in raw_patterns]

        # Regex patterns for subtle or encoded traversal variants
        self.regex_patterns = [
            re.compile(r"(?:\.\./|\.\.\\){2,}", re.IGNORECASE),
            re.compile(r"(?:%2e%2e(?:%2f|/|%5c|\\)){1,}", re.IGNORECASE),
            re.compile(r"(?:\.\.(?:%2f|%5c)){1,}", re.IGNORECASE),
            re.compile(r"(?:/|\\)etc(?:/|\\)(?:passwd|shadow|hosts)", re.IGNORECASE),
            re.compile(r"(?:/|\\)windows(?:/|\\)(?:win\.ini|system\.ini)", re.IGNORECASE),
            re.compile(r"boot\.ini", re.IGNORECASE)
        ]

    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        raw_url = str(log_entry.get("url") or "")
        normalized_url = self.normalize_str(raw_url)
        decoded_url = urllib.parse.unquote(raw_url).lower()

        body_raw = str(log_entry.get("body") or "")
        normalized_body = self.normalize_str(body_raw)

        inspect_targets = [raw_url.lower(), normalized_url, decoded_url]
        if normalized_body:
            inspect_targets.append(normalized_body)

        for target in inspect_targets:
            # 1. Exact pattern substring check
            for pat in self.patterns:
                if pat in target:
                    return {
                        "rule_id": self.rule_id,
                        "type": "PATH_TRAVERSAL",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Matched Path Traversal pattern: {pat}",
                        "matched_pattern": pat
                    }

            # 2. Regex check for traversal sequences
            for reg in self.regex_patterns:
                m = reg.search(target)
                if m:
                    return {
                        "rule_id": self.rule_id,
                        "type": "PATH_TRAVERSAL",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Matched Path Traversal regex pattern: {m.group(0)}",
                        "matched_pattern": m.group(0)
                    }

        return None
