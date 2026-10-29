# Kiến trúc Hệ thống (System Architecture) - SECURITY GUARD

## 1. Mô hình Phân lớp Hệ thống

Kiến trúc tổng thể của đồ án **SECURITY GUARD** bao gồm 5 tầng thành phần chính:

```
[ Người dùng / Tester (Kali Linux) ]
               │
               ▼ HTTP Request
    ┌──────────────────────┐
    │   Web Application    │ (Node.js + Express)
    └──────────┬───────────┘
               │
               ▼ Middleware Interceptor
    ┌──────────────────────┐
    │    Logging System    │ (requests.log / Database)
    └──────────┬───────────┘
               │
               ▼ Forwarding / Batch Logs
    ┌──────────────────────┐
    │   Detection Engine   │ (Python + FastAPI + Scikit-Learn)
    └──────────┬───────────┘
               │
               ▼ Cảnh báo rủi ro (Risk Score & Alert Trigger)
    ┌──────────────────────┐
    │     Alert System     │ (Bảng security_alerts trong PostgreSQL)
    └──────────┬───────────┘
               │
               ▼ Truy vấn chỉ số & hiển thị
    ┌──────────────────────┐
    │      Dashboard       │ (React + Vite)
    └──────────────────────┘
```

---

## 2. Chi tiết các Phân hệ

### 2.1. Web Application (`web-app`)
- **Vai trò:** Hệ thống website mục tiêu phục vụ việc phát sinh các luồng lưu lượng truy cập (cả bình thường lẫn bất thường).
- **Tính năng chính:**
  - Cung cấp các đường dẫn mẫu: `/`, `/login`, `/register`, `/dashboard`, `/profile`, `/search`.
  - Logging Middleware chặn mọi HTTP request và ghi nhận: thời gian, IP nguồn, method, URL, HTTP status code, User-Agent, response time.

### 2.2. Logging System (`web-app/src/middleware/` & `database/`)
- Đảm bảo tính toàn vẹn và cấu trúc của dữ liệu log theo chuẩn JSON.
- Hỗ trợ lưu trữ file cục bộ (`requests.log`) và sẵn sàng lưu vào bảng `request_logs` trong cơ sở dữ liệu.

### 2.3. Detection Engine (`detection-engine`)
- **Vai trò:** Xử lý và phân tích log để phát hiện các dấu hiệu tấn công hoặc bất thường.
- **Tiến trình ở các giai đoạn:**
  - *Giai đoạn hiện tại (Foundation):* Khởi tạo REST API `/health`, `/analyze`, `/analyze/batch` trả về response stub chuẩn schema.
  - *Giai đoạn tiếp theo:* Tích hợp Rule-based engine (phát hiện Brute Force, SQLi, XSS, Scanner) và Machine Learning (Isolation Forest phát hiện dị biệt).

### 2.4. Alert & Database Layer (`database`)
- Quản lý các luật phát hiện (`detection_rules`).
- Ghi nhận các cảnh báo (`security_alerts`) với mức độ rủi ro (`risk_score`).

### 2.5. Dashboard (`dashboard`)
- Giám sát tình trạng vận hành của các dịch vụ trong hệ thống.
- Thống kê thời gian thực về lượng request, các request nghi vấn và các cảnh báo mới nhất.
