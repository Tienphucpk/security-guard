# BÁO CÁO KẾT QUẢ KIỂM THỬ TOÀN DIỆN HỆ THỐNG
## Phase 10: Multi-Website Monitoring & Active Enforcement Test Report

---

## 1. Kết quả Tổng hợp Bộ Kiểm thử Hồi quy (Regression Suite)

- **Môi trường thực thi:** Windows Localhost, Node.js v24.15.0, Python 3.12, PostgreSQL 5432.
- **Lệnh chạy:** `scripts\test\test-all.bat`
- **Tỷ lệ vượt qua:** **176 / 176 tests PASS (100%)**

```
=======================================================
  Running SECURITY GUARD Automated Tests (Phase 1-10)
  Rule-Based & Machine Learning Anomaly Detection
  Multi-Website Monitoring & Active Policy Enforcement
=======================================================
[OK] PostgreSQL is ONLINE on port 5432

[1/2] Testing Web Application, Logging, and Database Layer...
ℹ tests 95
ℹ suites 1
ℹ pass 95
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ duration_ms ~12394ms

[2/2] Testing Detection Engine API...
----------------------------------------------------------------------
Ran 81 tests in 1.353s

OK

=======================================================
  All automated tests PASSED successfully! (176/176)
=======================================================
```

---

## 2. Chi tiết 20 Test Cases Mới của Phase 10 (`phase10_multi_site.test.js`)

| STT | Tên Test Case | Mục đích kiểm thử | Kết quả |
| :---: | :--- | :--- | :---: |
| 1 | `Agent Auth - Rejects missing credentials` | Kiểm tra request thiếu token trả về 401 Unauthorized | **PASS** |
| 2 | `Agent Auth - Rejects invalid credentials` | Kiểm tra request sai token trả về 401 Unauthorized | **PASS** |
| 3 | `Agent Auth - Accepts valid credentials` | Xác thực thành công Gateway bằng `X-Gateway-Secret` | **PASS** |
| 4 | `Event Ingestion - Rejects missing fields` | Từ chối payload thiếu `event_id` hoặc `source_id` (400) | **PASS** |
| 5 | `Event Ingestion - Rejects unregistered site` | Từ chối sự kiện từ website chưa đăng ký (404) | **PASS** |
| 6 | `Event Ingestion - Rejects duplicate submission` | Chống gửi trùng lặp `event_id` trong sliding window (409) | **PASS** |
| 7 | `Event Ingestion - Redacts sensitive parameters` | Khử mật khẩu và token trong URL query thành `[REDACTED]` | **PASS** |
| 8 | `SSRF Protection - Rejects cloud metadata hosts` | Chặn `169.254.169.254`, `metadata.google.internal` | **PASS** |
| 9 | `SSRF Protection - Accepts approved upstreams` | Chấp nhận URL hợp lệ thuộc cổng demo cho phép | **PASS** |
| 10 | `Policy Decision - MONITOR_ONLY never blocks` | Chế độ Monitor-Only trả về `ALLOW` kể cả khi có payload tấn công | **PASS** |
| 11 | `Policy Decision - ENFORCE blocks SQLi attacks` | Chế độ Enforce trả về `BLOCK` (403) khi phát hiện tấn công SQLi | **PASS** |
| 12 | `Policy Decision - Explicit IP block policy` | Áp dụng chính sách quản trị chặn IP cụ thể trong chế độ Enforce | **PASS** |
| 13 | `Policy Decision - Explicit ALLOW exception` | Ngoại lệ ALLOW ưu tiên cao hơn, bỏ qua luật chặn tấn công | **PASS** |
| 14 | `RBAC Management - Unauthenticated rejected` | Người dùng chưa đăng nhập không thể xem danh mục website (401) | **PASS** |
| 15 | `RBAC Management - ANALYST cannot register site` | Vai trò Analyst bị chặn khi cố tạo website mới (403) | **PASS** |
| 16 | `RBAC Management - ADMIN can register & toggle` | Vai trò Admin tạo website và chuyển đổi chế độ Enforce thành công | **PASS** |
| 17 | `Gateway End-to-End - Health check returns ONLINE` | Gateway lắng nghe cổng 8080 và phản hồi 200 ONLINE | **PASS** |
| 18 | `Gateway End-to-End - Proxies to Node Shop (:4001)` | Gateway chuyển tiếp thành công request đến Node Shop | **PASS** |
| 19 | `Gateway End-to-End - Rejects unknown website` | Gateway từ chối website không tồn tại với 404 Not Found | **PASS** |
| 20 | `Gateway Enforcement - Blocks attack with 403` | Gateway chủ động trả về 403 Forbidden khi gặp payload độc hại | **PASS** |

---

## 3. Kết quả Biên dịch Frontend Dashboard (Vite Production Build)

- **Lệnh thực hiện:** `npm run build` tại thư mục `dashboard`
- **Kết quả:** **Biên dịch thành công 100% trong 12.08s**, không có lỗi hay cảnh báo.
  ```
  vite v5.4.21 building for production...
  transforming...
  ✓ 34 modules transformed.
  rendering chunks...
  computing gzip size...
  dist/index.html                   0.41 kB │ gzip:  0.28 kB
  dist/assets/index-Vu--M6-u.css   10.17 kB │ gzip:  2.53 kB
  dist/assets/index-CNq69nkT.js   202.23 kB │ gzip: 59.40 kB
  ✓ built in 12.08s
  ```
