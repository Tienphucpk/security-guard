# ĐÁNH GIÁ AN NINH VÀ PHÂN TÍCH RỦI RO HỆ THỐNG
## Phase 10: Security Review & Threat Modeling

---

## 1. Mô hình Đe dọa (Threat Modeling)

| Tác nhân đe dọa (Threat Actor) | Vectơ tấn công (Attack Vector) | Cơ chế phòng thủ trong Phase 10 | Trạng thái bảo vệ |
| :--- | :--- | :--- | :---: |
| **Kẻ tấn công Web bên ngoài** | SQL Injection, XSS, Path Traversal, Command Injection | Gateway đánh giá deterministic detectors và trả về 403 Forbidden ở chế độ `ENFORCE`. | **ĐÃ GIẢI QUYẾT** |
| **Kẻ tấn công khai thác Gateway** | SSRF (Server-Side Request Forgery) để quét mạng nội bộ | Danh sách `APPROVED_UPSTREAMS` nghiêm ngặt, chặn mọi hostname đám mây (`169.254.169.254`, `metadata.google.internal`), cấm proxy mở. | **ĐÃ GIẢI QUYẾT** |
| **Tấn công giả mạo Telemetry** | Gửi log sự kiện giả mạo vào `/api/ingest/events` | Xác thực `requireAgentAuth` với khóa mật mã `X-Gateway-Secret`, so sánh thời gian hằng số `timingSafeEqual`. | **ĐÃ GIẢI QUYẾT** |
| **Tấn công DoS Gateway** | Gửi payload kích thước khổng lồ làm tràn bộ nhớ | Giới hạn `MAX_PAYLOAD_SIZE = 1MB`. Nếu vượt quá, trả về `413 Payload Too Large`. | **ĐÃ GIẢI QUYẾT** |
| **Tấn công Side-Channel** | Timing attack phân tích thời gian so khớp token | Tất cả chuỗi xác thực được so sánh bằng `crypto.timingSafeEqual`. | **ĐÃ GIẢI QUYẾT** |
| **Rò rỉ Thông tin Nhạy cảm** | Lưu trữ mật khẩu, session cookies trong log | Module `redactUrlQuery` và `redactObject` tự động khử toàn bộ key nhạy cảm thành `[REDACTED]`. | **ĐÃ GIẢI QUYẾT** |
| **Leo thang đặc quyền** | Tài khoản Analyst thay đổi luật chặn hoặc đăng ký website | Phân quyền backend nghiêm ngặt (`requireRole(['ADMIN'])`). Analyst chỉ có quyền đọc `GET`. | **ĐÃ GIẢI QUYẾT** |

---

## 2. Ranh giới Phòng thủ SSRF (SSRF Boundary Architecture)

Monitoring Gateway được thiết kế với cơ chế kiểm soát địa chỉ đích chặt chẽ:
1. **Kiểm tra Scheme:** Chỉ chấp nhận `http:` hoặc `https:`. Mọi giao thức nguy hiểm như `file://`, `gopher://`, `dict://`, `ftp://` bị từ chối ngay ở cấp phân giải URL.
2. **Kiểm tra Host:**
   - Cấm hoàn toàn IP metadata của AWS/GCP/Azure: `169.254.169.254`.
   - Cấm tên miền nội bộ ảo: `metadata.google.internal`.
   - Cấm địa chỉ broadcast: `255.255.255.255`, `0.0.0.0`.
3. **Chỉ Chấp nhận Upstream Đã Duyệt:** Gateway từ chối chuyển tiếp nếu `website_id` không nằm trong bảng danh mục quản trị viên phê duyệt.

---

## 3. Khử Dữ liệu Nhạy cảm (Data Redaction Verification)

Kiểm thử tự động `Test 7` trong `phase10_multi_site.test.js` đã xác minh:
- Request gửi: `/api/login?user=alice&password=SuperSecretPassword123&token=tok_999`
- Dữ liệu ghi nhận trong `request_logs` và hiển thị trên Dashboard:
  `/api/login?user=alice&password=[REDACTED]&token=[REDACTED]`
- Hoàn toàn không lưu vết mật khẩu hay chuỗi xác thực nhạy cảm.

---

## 4. Kiểm soát Tác vụ và Tính Ổn định (Resilience)

- **Fail-Open Policy:** Trong trường hợp Detection Engine hoặc Decision API gặp sự cố, hệ thống chuyển sang trạng thái degraded an toàn và cho phép request đi qua Upstream, đảm bảo tính liên tục của dịch vụ cho các ứng dụng nghiệp vụ demo.
- **Bounded Timeout:** Thời gian phân tích quyết định bị chặn cứng ở mức tối đa 600ms – 1000ms, ngăn chặn nguy cơ Gateway bị treo do dịch vụ phân tích phản hồi chậm.
