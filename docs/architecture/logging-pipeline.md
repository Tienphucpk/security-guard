# Luồng Xử Lý Ghi Vết Log (Logging Pipeline) - SECURITY GUARD Phase 2

Tài liệu chi tiết về cơ chế bắt giữ, chuẩn hóa, phân luồng lưu vết và xử lý sự cố trong Phase 2.

---

## 1. Sơ đồ Pipeline Tổng thể

```
HTTP Request
      │
      ▼
Express Application
      │
      ▼
Logging Middleware (src/middleware/logger.middleware.js)
      │
      ├─► [1] Chuẩn hóa IP (src/utils/ip.util.js)
      │       - ::ffff:127.0.0.1 -> 127.0.0.1
      │       - ::1 -> 127.0.0.1
      │       - Lấy client IP ngoài cùng từ X-Forwarded-For
      │
      ├─► [2] Thu thập Metadata
      │       - timestamp (ISO-8601)
      │       - ip (normalized)
      │       - method (GET/POST/...)
      │       - url (requested path & query)
      │       - statusCode (HTTP response code)
      │       - userAgent (browser/scanner client)
      │       - responseTime (thời gian xử lý ms)
      │
      ├─► [3] Console Output: [HTTP LOG] <JSON>
      │
      ├─► [4] JSON File Logger: ghi nối tiếp vào web-app/logs/requests.log
      │
      └─► [5] PostgreSQL Database Logger (src/services/database.js)
              - Parameterized query chèn vào bảng request_logs
              - Tác vụ bất đồng bộ non-blocking
```

---

## 2. Cấu trúc Bản ghi Log Chuẩn hóa (Schema)

```json
{
  "timestamp": "2026-10-07T08:15:37.754Z",
  "ip": "127.0.0.1",
  "method": "GET",
  "url": "/login",
  "statusCode": 200,
  "userAgent": "Mozilla/5.0 ...",
  "responseTime": 12
}
```

---

## 3. Cơ chế Kháng lỗi & Hoạt động Thích ứng (Resilience & Graceful Degradation)

| Kịch bản sự cố | Hành vi của hệ thống |
| :--- | :--- |
| **PostgreSQL hoạt động bình thường** | Log được ghi đồng thời ra console, file `requests.log` và bảng `request_logs`. API `/api/logs` lấy từ DB với index tốc độ cao. |
| **PostgreSQL offline / mất kết nối** | - Web App **không crash**.<br>- Request của người dùng vẫn phản hồi bình thường.<br>- Console in cảnh báo `[DB ERROR]`.<br>- File `requests.log` vẫn được ghi đầy đủ.<br>- API `/api/logs` và `/api/logs/stats` tự động chuyển sang đọc fallback từ file `requests.log` (`"source": "file_fallback"`).<br>- `/api/health` báo trạng thái `degraded` (`"database": "disconnected"`). |
| **Lỗi quyền ghi file log** | Console báo `[LOGGER ERROR]`, quá trình lưu trữ vào PostgreSQL và trả response HTTP vẫn tiếp tục diễn ra độc lập. |
