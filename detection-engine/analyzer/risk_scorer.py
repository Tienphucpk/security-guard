"""
Risk Scorer Module
Tính toán tổng điểm rủi ro và xác định mức độ nghiêm trọng (Severity) dựa trên các rule vi phạm.
"""

from typing import List, Dict, Any, Tuple


class RiskScorer:
    """
    Tính toán thang điểm rủi ro từ 0 - 100:
    - LOW:      0 - 29
    - MEDIUM:   30 - 59
    - HIGH:     60 - 79
    - CRITICAL: 80 - 100
    """

    @staticmethod
    def calculate(detections: List[Dict[str, Any]]) -> Tuple[float, str]:
        """
        Tính điểm tổng hợp từ danh sách detections.
        Trả về: (risk_score, severity)
        """
        if not detections:
            return 0.0, "LOW"

        # Tính tổng điểm, giới hạn trần tối đa là 100.0
        total_score = sum(float(d.get("score", 0.0)) for d in detections)
        final_score = min(100.0, max(0.0, total_score))

        # Xác định severity theo thang điểm
        if final_score >= 80.0:
            severity = "CRITICAL"
        elif final_score >= 60.0:
            severity = "HIGH"
        elif final_score >= 30.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return round(final_score, 2), severity
