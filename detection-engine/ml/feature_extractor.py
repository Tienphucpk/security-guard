"""
Feature Extraction Module for Machine Learning Anomaly Detection
Extracts a deterministic 10-feature vector from HTTP request metadata.
"""

import time
import urllib.parse
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

# Stable Schema Version
FEATURE_SCHEMA_VERSION = "1.0"

# Exact deterministic feature names and ordering
FEATURE_NAMES = [
    "method_code",
    "status_code",
    "response_time_ms",
    "url_length",
    "query_length",
    "special_char_count",
    "suspicious_token_count",
    "ua_length",
    "path_depth",
    "rolling_req_count_60s",
    "rolling_failed_login_300s"
]

METHOD_MAP = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "DELETE": 3,
    "PATCH": 4,
    "HEAD": 5,
    "OPTIONS": 6
}

SPECIAL_CHARS = set(["'", '"', '<', '>', ';', '(', ')', '{', '}', '[', ']', '%', '$', '&', '|', '`', '*', '+', '=', '#', '~', '^'])

SUSPICIOUS_TOKENS = (
    ".env", ".git", "wp-", "phpmyadmin", "select", "union", "--",
    "/*", "*/", "script", "alert", "onerror", "onload", "javascript",
    "sqlmap", "nikto", "nmap", "gobuster", "dirbuster", "acunetix",
    "eval(", "passwd", "cmd.exe", "/bin/", "../", "..\\", "%2e%2e",
    "win.ini", "whoami", "powershell"
)

INTERNAL_TELEMETRY_PREFIXES = (
    "/api/health",
    "/api/logs",
    "/api/alerts"
)


class FeatureExtractor:
    def __init__(self, track_history: bool = True):
        self.track_history = track_history
        # ip -> list of timestamps for general requests
        self.req_history: Dict[str, List[float]] = defaultdict(list)
        # ip -> list of timestamps for failed logins
        self.failed_login_history: Dict[str, List[float]] = defaultdict(list)

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

    def is_internal_telemetry(self, url: str) -> bool:
        if not url:
            return False
        clean_path = url.split("?")[0].lower().strip()
        return any(clean_path.startswith(prefix) for prefix in INTERNAL_TELEMETRY_PREFIXES)

    def extract_dict(self, log_entry: Dict[str, Any]) -> Dict[str, float]:
        """
        Extracts 10 numerical features as a dictionary.
        """
        if not isinstance(log_entry, dict):
            log_entry = {}

        # 1. Method Code
        raw_method = str(log_entry.get("method") or "GET").upper().strip()
        method_code = float(METHOD_MAP.get(raw_method, 7))

        # 2. Status Code
        raw_status = log_entry.get("statusCode") or log_entry.get("status_code") or 200
        try:
            status_code = float(int(raw_status))
            if status_code < 100 or status_code > 599:
                status_code = 200.0
        except (ValueError, TypeError):
            status_code = 200.0

        # 3. Response Time (ms)
        raw_resp_time = log_entry.get("responseTime") or log_entry.get("response_time_ms") or 0.0
        try:
            resp_time = float(raw_resp_time)
            # Clip between 0 and 60000ms (1 minute max)
            resp_time = max(0.0, min(resp_time, 60000.0))
        except (ValueError, TypeError):
            resp_time = 0.0

        # 4 & 5. URL and Query Lengths
        raw_url = str(log_entry.get("url") or "/")
        try:
            unquoted_url = urllib.parse.unquote(raw_url)
        except Exception:
            unquoted_url = raw_url

        url_length = float(len(unquoted_url))

        if "?" in unquoted_url:
            query_part = unquoted_url.split("?", 1)[1]
            query_length = float(len(query_part))
            path_part = unquoted_url.split("?", 1)[0]
        else:
            query_length = 0.0
            path_part = unquoted_url

        # 6. Special Characters Count
        special_count = float(sum(1 for char in unquoted_url if char in SPECIAL_CHARS))

        # 7. User-Agent
        raw_ua = str(log_entry.get("userAgent") or log_entry.get("user_agent") or "")
        ua_length = float(len(raw_ua))

        # 8. Suspicious Token Count
        combined_text = (unquoted_url + " " + raw_ua).lower()
        suspicious_token_count = float(sum(1 for token in SUSPICIOUS_TOKENS if token in combined_text))

        # 9. Path Depth
        clean_path = path_part.strip("/")
        if not clean_path:
            path_depth = 0.0
        else:
            path_depth = float(len(clean_path.split("/")))

        # 10 & 11. Rolling Statistics
        ip = str(log_entry.get("ip") or "127.0.0.1").strip()
        req_time = self._parse_timestamp(log_entry.get("timestamp"))

        if self.track_history:
            # Update general request history (window = 60s)
            recent_reqs = [t for t in self.req_history[ip] if (req_time - t) <= 60.0]
            recent_reqs.append(req_time)
            self.req_history[ip] = recent_reqs
            rolling_req_count = float(len(recent_reqs))

            # Update failed login history (window = 300s)
            is_login = "/login" in path_part.lower() and raw_method == "POST"
            is_failed = status_code == 401.0
            if is_login and is_failed:
                recent_failed = [t for t in self.failed_login_history[ip] if (req_time - t) <= 300.0]
                recent_failed.append(req_time)
                self.failed_login_history[ip] = recent_failed
                rolling_failed_login = float(len(recent_failed))
            else:
                recent_failed = [t for t in self.failed_login_history[ip] if (req_time - t) <= 300.0]
                self.failed_login_history[ip] = recent_failed
                rolling_failed_login = float(len(recent_failed))
        else:
            rolling_req_count = 1.0
            rolling_failed_login = 0.0

        return {
            "method_code": method_code,
            "status_code": status_code,
            "response_time_ms": resp_time,
            "url_length": url_length,
            "query_length": query_length,
            "special_char_count": special_count,
            "suspicious_token_count": suspicious_token_count,
            "ua_length": ua_length,
            "path_depth": path_depth,
            "rolling_req_count_60s": rolling_req_count,
            "rolling_failed_login_300s": rolling_failed_login
        }

    def extract_vector(self, log_entry: Dict[str, Any]) -> List[float]:
        """
        Extracts the 10 numerical features in exact deterministic order as a list of floats.
        """
        d = self.extract_dict(log_entry)
        return [d[k] for k in FEATURE_NAMES]

    def reset_state(self):
        """Clears rolling windows history"""
        self.req_history.clear()
        self.failed_login_history.clear()
