# SECURITY GUARD — Phase 9 Test & Verification Report

**Dự án:** SECURITY GUARD — Website Anomaly Monitoring and Detection System  
**Học phần:** Bảo mật và An toàn thông tin (BM&ATTT)  
**Ngày kiểm thử:** 29/10/2026  
**Tổng số test tự động:** **156 / 156 Tests PASS (100%)**  
**Thời gian thực thi toàn bộ:** ~12.5 giây  

---

## 1. Tổng kết Kết quả Kiểm thử Toàn diện

| Phân hệ Kiểm thử | Tập tin Test Suite | Số Test | PASS | FAIL | Trạng thái |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Web App (Phase 1–4 Baseline)** | `tests/server.test.js` | 24 | 24 | 0 | 🟢 **PASS** |
| **Web App (Phase 5 E2E & SSE)** | `tests/phase5_e2e.test.js` | 6 | 6 | 0 | 🟢 **PASS** |
| **Web App (Phase 6 ML Integration)** | `tests/phase6_ml.test.js` | 6 | 6 | 0 | 🟢 **PASS** |
| **Web App (Phase 7 Detection Rules)** | `tests/phase7_expansion.test.js` | 8 | 8 | 0 | 🟢 **PASS** |
| **Web App (Phase 8 Resilience)** | `tests/phase8_resilience.test.js` | 6 | 6 | 0 | 🟢 **PASS** |
| **Web App (Phase 9.1 Key/HMAC Auth)** | `tests/phase9_auth.test.js` | 8 | 8 | 0 | 🟢 **PASS** |
| **Web App (Phase 9 User & RBAC)** | `tests/phase9_user_auth.test.js` | **25** | **25** | 0 | 🟢 **PASS** |
| **Detection Engine (8 Rules)** | `tests/test_rules.py` | 33 | 33 | 0 | 🟢 **PASS** |
| **Detection Engine (Isolation Forest)** | `tests/test_ml_isolation_forest.py` | 24 | 24 | 0 | 🟢 **PASS** |
| **Detection Engine (Alert Correlation)**| `tests/test_alert_correlation.py` | 7 | 7 | 0 | 🟢 **PASS** |
| **Detection Engine (FastAPI Endpoints)**| `tests/test_api.py` | 17 | 17 | 0 | 🟢 **PASS** |
| **TỔNG CỘNG HỆ THỐNG** | **Toàn bộ 11 Test Suites** | **156** | **156** | **0** | 🟢 **100% PASS** |

---

## 2. Chi tiết 25 Test Cases mới của Phase 9 (`phase9_user_auth.test.js`)

### 2.1. Nhóm Xác thực (Authentication - 10 Tests)
1. **Auth 1 (Login Admin thành công):** Đăng nhập với `admin` / `Admin@123456`, nhận mã `200 OK`, trả về user info, session ID và thiết lập cookie `HttpOnly; SameSite=Lax`.
2. **Auth 2 (Login Analyst qua Email):** Đăng nhập bằng email `analyst@securityguard.local` / `Analyst@123456`, nhận `200 OK`.
3. **Auth 3 (Mật khẩu không chính xác):** Nhận lỗi an toàn `401 Unauthorized` (`Invalid username or password`).
4. **Auth 4 (Tài khoản không tồn tại):** Nhận thông báo lỗi đồng nhất `401 Unauthorized` (`Invalid username or password`) chống kỹ thuật dò quét tài khoản (Username Enumeration).
5. **Auth 5 (Thiếu tham số):** Gửi thiếu password nhận mã `400 Bad Request`.
6. **Auth 6 (Xác thực qua Cookie):** `GET /api/auth/me` gửi kèm HttpOnly cookie trả về đúng thông tin user hiện tại.
7. **Auth 7 (Xác thực qua Bearer Token):** `GET /api/auth/me` gửi kèm header `Authorization: Bearer <sessionId>` trả về đúng thông tin user.
8. **Auth 8 (Chưa xác thực):** `GET /api/auth/me` không có session trả về `401 Unauthorized`.
9. **Auth 9 (Rate Limiting):** Sau 5 lần đăng nhập sai liên tiếp, lần thứ 6 bị chặn ngay lập tức với mã `429 Too Many Requests`.
10. **Auth 10 (Đăng xuất an toàn):** `POST /api/auth/logout` xóa bản ghi session trong PostgreSQL và xóa cookie; các request sau đó dùng session cũ đều bị từ chối `401 Unauthorized`.

### 2.2. Nhóm Phân quyền RBAC (Authorization - 8 Tests)
11. **RBAC 1 (Chưa đăng nhập):** Gửi request tiếp nhận cảnh báo (`PATCH /acknowledge`) mà không có phiên bị từ chối `401 Unauthorized`.
12. **RBAC 2 (Analyst tiếp nhận cảnh báo):** Người dùng vai trò `ANALYST` gửi request tiếp nhận cảnh báo bị máy chủ từ chối với mã lỗi `403 Forbidden` (`Insufficient permissions: role 'ANALYST' cannot mutate alerts`).
13. **RBAC 3 (Analyst giải quyết cảnh báo):** Người dùng `ANALYST` giải quyết cảnh báo bị từ chối `403 Forbidden`.
14. **RBAC 4 (Admin tiếp nhận cảnh báo):** Người dùng `ADMIN` tiếp nhận cảnh báo thành công `200 OK`.
15. **RBAC 5 (Admin giải quyết cảnh báo):** Người dùng `ADMIN` giải quyết cảnh báo thành công `200 OK`.
16. **RBAC 6 (Analyst truy cập User Management):** `ANALYST` gọi `GET /api/users` bị chặn với `403 Forbidden`.
17. **RBAC 7 (Analyst tạo tài khoản):** `ANALYST` gọi `POST /api/users` bị chặn với `403 Forbidden`.
18. **RBAC 8 (Analyst tự nâng quyền):** `ANALYST` gửi request nâng quyền lên ADMIN bị chặn với `403 Forbidden`.

### 2.3. Nhóm Quản trị Tài khoản (User Management - 7 Tests)
19. **UserMgmt 1 (Lấy danh sách người dùng):** `ADMIN` gọi `GET /api/users` nhận danh sách đầy đủ, trường `password_hash` bị loại bỏ 100%.
20. **UserMgmt 2 (Tạo người dùng mới):** `ADMIN` tạo người dùng mới thành công với mã `201 Created`, mật khẩu được băm Bcrypt trong DB.
21. **UserMgmt 3 (Chống trùng lặp username):** Tạo tài khoản trùng tên bị từ chối `400 Bad Request`.
22. **UserMgmt 4 (Bật/Tắt trạng thái tài khoản):** `ADMIN` chuyển đổi trạng thái kích hoạt / khóa tài khoản thành công `200 OK`.
23. **UserMgmt 5 (Đổi vai trò người dùng):** `ADMIN` thăng quyền người dùng lên ADMIN và hạ quyền về ANALYST thành công `200 OK`.
24. **UserMgmt 6 (Quy tắc an toàn Khóa Admin):** Ngăn chặn hành vi vô hiệu hóa tài khoản ADMIN đang hoạt động cuối cùng với mã `400 Bad Request` (`Cannot deactivate the last active Admin account`).
25. **UserMgmt 7 (Quy tắc an toàn Hạ quyền Admin):** Ngăn chặn hành vi hạ quyền tài khoản ADMIN đang hoạt động cuối cùng với mã `400 Bad Request` (`Cannot demote the last active Admin account`).

---

## 3. Lệnh Tái hiện Kiểm thử

Để chạy kiểm thử toàn bộ hệ thống từ PowerShell/CMD:

```cmd
# Chạy toàn bộ 156 tests hồi quy của cả Web App và Detection Engine:
scripts\test\test-all.bat
```

Để chạy riêng bộ test xác thực & phân quyền Phase 9:

```cmd
cd web-app
node --test tests/phase9_user_auth.test.js
```
