# HƯỚNG DẪN TÍCH HỢP WEBSITE MỚI VÀO SECURITY GUARD
## Phase 10: Multi-Website Monitoring & Gateway Integration Guide

---

## 1. Cơ chế Tích hợp Độc lập Công nghệ (Zero-SDK Approach)

Security Guard áp dụng mô hình **Technology-Independent Monitoring Gateway**. Bất kỳ website nào chạy trên bất kỳ ngôn ngữ hay framework nào (Node.js, Python, Java, PHP, Go, .NET, Ruby, tĩnh HTML/Nginx) đều có thể được giám sát và bảo vệ ngay lập tức mà không cần chỉnh sửa một dòng mã nguồn nào của ứng dụng gốc.

---

## 2. Quy trình Tích hợp Website Mới

### Bước 1: Khai báo Website trong Cơ sở Dữ liệu

Người quản trị (vai trò `ADMIN`) có thể đăng ký website mới thông qua Dashboard hoặc gọi trực tiếp API `POST /api/websites`:

```http
POST /api/websites HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Cookie: secguard_session=<admin_session_id>

{
  "websiteId": "site_hrm_java",
  "name": "Hệ thống Quản lý Nhân sự (Java Spring Boot)",
  "upstreamUrl": "http://127.0.0.1:8081",
  "monitoringMode": "MONITOR_ONLY",
  "description": "Ứng dụng quản lý hồ sơ nhân sự nội bộ"
}
```

**Ràng buộc kiểm tra (Validation):**
- `websiteId`: Chuỗi chữ và số, gạch nối hoặc gạch dưới (3 - 64 ký tự).
- `upstreamUrl`: Phải là URL HTTP/HTTPS hợp lệ, không thuộc danh sách đen SSRF.

---

### Bước 2: Định tuyến Lưu lượng Truy cập qua Gateway

Có 2 phương thức để gửi request của người dùng qua Gateway:

#### Phương thức 1: Sử dụng Tiền tố Đường dẫn (Path-Prefix) — Thuận tiện cho trình duyệt & Demo
Truy cập qua URL Gateway:
```
http://localhost:8080/site/<website_id>/<path>
```
*Ví dụ:*
- `http://localhost:8080/site/site_demo_node/products` -> Gateway tự động chuyển tiếp đến `http://127.0.0.1:4001/products`.
- `http://localhost:8080/site/site_demo_python/directory` -> Gateway chuyển tiếp đến `http://127.0.0.1:4002/directory`.

#### Phương thức 2: Sử dụng HTTP Header `X-Website-Id` — Dành cho Production Reverse Proxy / CDN
```bash
curl -X GET "http://localhost:8080/api/employees" \
  -H "X-Website-Id: site_hrm_java"
```

---

## 3. Tích hợp Trực tiếp thông qua Event Ingestion API (Tùy chọn Middleware)

Đối với các hệ sinh thái yêu cầu truyền thêm ngữ cảnh ứng dụng cấp cao (User Context, Session Context):
Ứng dụng có thể gửi trực tiếp log telemetry vào endpoint Ingestion:

```http
POST /api/ingest/events HTTP/1.1
Host: localhost:3000
Content-Type: application/json
X-Gateway-Secret: secguard_gateway_internal_secret_2026

{
  "event_id": "evt-custom-8888",
  "request_id": "req-custom-9999",
  "source_id": "site_demo_node",
  "timestamp": "2026-10-29T21:40:00.000Z",
  "method": "POST",
  "path": "/api/checkout",
  "source_ip": "192.168.1.15",
  "status_code": 200,
  "response_time_ms": 45.2,
  "user_agent": "Mozilla/5.0 ...",
  "blocked": false
}
```

---

## 4. Kiểm tra Sau Tích hợp (Post-Integration Verification)

1. Kiểm tra trạng thái Gateway:
   ```bash
   curl http://localhost:8080/health
   ```
2. Gửi request thử nghiệm sạch (Clean Request):
   ```bash
   curl http://localhost:8080/site/<website_id>/
   ```
   *Kỳ vọng:* Trả về nội dung website gốc kèm header `X-Security-Guard-Monitored: ACTIVE`.
3. Kiểm tra Dashboard: Sự kiện truy cập và lưu lượng hiển thị trong bảng **Enforcement Audit Trail** và **Request Logs**.
