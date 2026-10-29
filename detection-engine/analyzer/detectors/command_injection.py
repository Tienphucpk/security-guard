"""
OS Command Injection Detector
Phát hiện các hành vi chèn lệnh hệ điều hành (Command Injection) và thực thi mã từ xa (RCE).
"""

from typing import Dict, Any, Optional, List
import re
import os
import json
import urllib.parse

from rules.rule_base import BaseDetectionRule


class CommandInjectionDetector(BaseDetectionRule):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if not cfg:
            cfg_path = os.path.join(os.path.dirname(__file__), "../../rules/command_injection.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

        super().__init__(
            rule_id=cfg.get("rule_code", "RULE-CMDI-001"),
            name=cfg.get("name", "OS Command Injection & Remote Code Execution Detection"),
            severity=cfg.get("severity", "CRITICAL"),
            score=cfg.get("score", 85.0),
            enabled=cfg.get("enabled", True),
            category="COMMAND_INJECTION",
            description=cfg.get("description", "Command injection or shell command substitution detected")
        )

        raw_patterns = cfg.get("patterns", [
            "; whoami",
            "; id",
            "; cat ",
            "; uname",
            "| whoami",
            "| id",
            "| cat ",
            "&& whoami",
            "&& id",
            "&& cat ",
            "powershell -enc",
            "powershell.exe",
            "cmd.exe /c",
            "/bin/bash",
            "/bin/sh"
        ])
        self.patterns = [p.lower().strip() for p in raw_patterns]

        # Regex patterns for shell chaining and subshell execution
        self.regex_patterns = [
            re.compile(r"[;|`&]\s*(?:whoami|id|cat|uname|ls|dir|pwd|type|net\s+user|curl|wget)\b", re.IGNORECASE),
            re.compile(r"\$\((?:whoami|id|cat|uname|ls|dir|pwd|curl|wget)[^)]*\)", re.IGNORECASE),
            re.compile(r"`(?:whoami|id|cat|uname|ls|dir|pwd|curl|wget)[^`]*`", re.IGNORECASE),
            re.compile(r"powershell(?:\.exe)?\s+(?:-enc|-command|-e)\b", re.IGNORECASE),
            re.compile(r"cmd(?:\.exe)?\s+/c\b", re.IGNORECASE)
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
                        "type": "COMMAND_INJECTION",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Matched Command Injection pattern: {pat}",
                        "matched_pattern": pat
                    }

            # 2. Regex check for shell chaining / subshells
            for reg in self.regex_patterns:
                m = reg.search(target)
                if m:
                    return {
                        "rule_id": self.rule_id,
                        "type": "COMMAND_INJECTION",
                        "severity": self.severity,
                        "score": self.score,
                        "reason": f"Matched Command Injection regex pattern: {m.group(0)}",
                        "matched_pattern": m.group(0)
                    }

        return None
