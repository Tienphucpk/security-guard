"""
SECURITY GUARD - Base Detection Rule Interface
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import urllib.parse


class BaseDetectionRule(ABC):
    """
    Lớp cơ sở cho các luật phát hiện an ninh (SQLi, XSS, Brute-force, Scanner, URL, Traffic).
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str = "medium",
        score: float = 50.0,
        enabled: bool = True,
        category: str = "general",
        description: str = ""
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity.upper()
        self.score = float(score)
        self.enabled = enabled
        self.category = category
        self.description = description

    @abstractmethod
    def evaluate(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Đánh giá 1 bản ghi log.
        Trả về dict mô tả detection nếu phát hiện, hoặc None nếu an toàn/rule disabled.
        Format trả về:
        {
            "rule_id": self.rule_id,
            "type": self.category.upper(),
            "severity": self.severity,
            "score": self.score,
            "reason": "Mô tả nguyên nhân phát hiện",
            "matched_pattern": "pattern tìm thấy nếu có"
        }
        """
        pass

    @staticmethod
    def normalize_str(val: Any) -> str:
        """
        Chuẩn hóa chuỗi an toàn: giải mã URL, chuyển về lowercase, strip khoảng trắng.
        """
        if val is None:
            return ""
        try:
            s = str(val)
            # Decode URL-encoded characters (e.g. %27 -> ', %20 -> space)
            decoded = urllib.parse.unquote(s)
            return decoded.lower().strip()
        except Exception:
            return str(val).lower().strip()
