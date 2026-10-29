from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseAnalyzer(ABC):
    """
    Interface cơ sở cho các bộ phân tích hành vi bất thường (ML, Thống kê, Heuristic).
    Sẽ được triển khai chi tiết ở các giai đoạn tiếp theo.
    """

    @abstractmethod
    def analyze(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Nhận bản ghi log và trả về điểm rủi ro kèm cờ bất thường.
        """
        pass
