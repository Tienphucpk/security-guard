# SECURITY GUARD — Phase 9: Authentication & Authorization Architecture Report

**Dự án:** SECURITY GUARD — Website Anomaly Monitoring and Detection System  
**Học phần:** Bảo mật và An toàn thông tin (BM&ATTT)  
**Giai đoạn:** Phase 9 — Authentication, Authorization & User Management  
**Ngày hoàn thiện:** 29/10/2026  
**Trạng thái kiểm thử:** 156/156 Tests PASS (100%)  

---

## 1. Kiến trúc Xác thực & Quản lý Phiên (Authentication & Session Architecture)

Hệ thống triển khai kiến trúc **Server-Side Session Store** kết hợp với **HttpOnly Cookie** và **Database PostgreSQL**, tuân thủ nghiêm ngặt các khuyến nghị phòng thủ của OWASP:

```text
┌───────────────────────┐                    ┌────────────────────────────┐
│ React/Vite Dashboard  │                    │    Express Web App (3000)  │
│      (Port 5173)      │                    │                            │
└───────────┬───────────┘                    └─────────────┬──────────────┘
            │                                              │
            │ 1. POST /api/auth/login                      │
            │    { username, password }                    │
            ├─────────────────────────────────────────────►│
            │                                              │ 2. Find user in PostgreSQL
            │                                              │    Verify bcrypt hash
            │                                              │    Generate random session (32 bytes)
            │                                              │    Save to 'user_sessions' table
            │ 3. Set-Cookie: secguard_session=<sessionId>; │
            │    HttpOnly; SameSite=Lax; Path=/            │
            │◄─────────────────────────────────────────────┤
            │                                              │
            │ 4. Subsequent requests with cookie           │
            │    (credentials: 'include')                  │
            ├─────────────────────────────────────────────►│ 5. Middleware 'requireAuth':
            │                                              │    Validate session in DB
            │                                              │    Attach req.user (Role & Status)
            │                                              │    Enforce RBAC ('requireRole')
```

### 1.1. Các đặc tính an ninh của Phiên làm việc (Session Security)

1. **HttpOnly Cookie (`secguard_session`):**
   - Không thể truy cập từ JavaScript (`document.cookie`), vô hiệu hóa triệt để rủi ro đánh cắp session ID qua tấn công XSS (Cross-Site Scripting).
2. **SameSite=Lax:**
   - Ngăn chặn trình duyệt tự động gửi cookie trong các truy vấn chéo nguồn (Cross-Origin POST requests) từ website độc hại, phòng thủ chống tấn công CSRF (Cross-Site Request Forgery).
3. **Session Fixation Prevention:**
   - Khi đăng nhập thành công, hệ thống luôn sinh mới một session ID ngẫu nhiên có độ dài 32 bytes (64 ký tự hex) thông qua `crypto.randomBytes(32).toString('hex')`.
4. **Server-Side Invalidation:**
   - Khi người dùng đăng xuất (`POST /api/auth/logout`), bản ghi session trong PostgreSQL bị xóa ngay lập tức (`DELETE FROM user_sessions WHERE session_id = ...`) và cookie được xóa về hạn quá khứ `1970-01-01`. Bất kỳ yêu cầu nào sau đó dùng session cũ đều bị từ chối `401 Unauthorized`.
5. **Giới hạn Thời gian Sống (TTL):**
   - Mỗi session có thời hạn tối đa 24 giờ (`expires_at = CURRENT_TIMESTAMP + interval '24 hours'`). Session hết hạn sẽ tự động bị từ chối.
6. **Bảo mật Mật khẩu:**
   - Mật khẩu được băm an toàn bằng thuật toán **Bcrypt** với 10 vòng muối (salt rounds). Tuyệt đối không lưu mật khẩu dạng bản rõ (plaintext).
   - API không bao giờ trả về trường `password_hash` cho client.

### 1.2. Cơ chế Phòng thủ Chống Tấn công Dò Mật khẩu (Rate Limiting)

- Hệ thống theo dõi số lần đăng nhập thất bại liên tiếp theo cặp `IP:identifier`.
- Sau **5 lần đăng nhập thất bại liên tiếp**, hệ thống tự động khóa tạm thời IP/tài khoản đó trong **5 phút**, trả về mã lỗi chuẩn `HTTP 429 Too Many Requests`.
- Thông báo lỗi khi đăng nhập sai hoặc tài khoản không tồn tại là **đồng nhất** (`Invalid username or password`), loại bỏ hoàn toàn khả năng dò quét tài khoản (Username Enumeration).

---

## 2. Ma trận Phân quyền theo Vai trò (Role-Based Access Control - RBAC)

Hệ thống định nghĩa 2 vai trò cốt lõi và kiểm soát chặt chẽ tại tầng Backend:

| Quyền hạn & Chức năng | Khách (Chưa đăng nhập) | ANALYST (Phân tích viên) | ADMIN (Quản trị viên) |
| :--- | :---: | :---: | :---: |
| **Xem Trang Đăng nhập** | Cho phép | Cho phép | Cho phép |
| **Đăng nhập / Đăng xuất** | Cho phép | Cho phép | Cho phép |
| **Xem Dashboard & Live SSE** | Bị chuyển về Login | **Cho phép** | **Cho phép** |
| **Xem Danh sách Request Logs** | 401 Unauthorized | **Cho phép** | **Cho phép** |
| **Xem Danh sách Cảnh báo & Chi tiết** | 401 Unauthorized | **Cho phép** | **Cho phép** |
| **Tiếp nhận Cảnh báo (`acknowledge`)** | 401 Unauthorized | **403 Forbidden** | **200 OK** |
| **Giải quyết Cảnh báo (`resolve`)** | 401 Unauthorized | **403 Forbidden** | **200 OK** |
| **Mở lại Cảnh báo (`status=new`)** | 401 Unauthorized | **403 Forbidden** | **200 OK** |
| **Xem Danh sách Tài khoản (`GET /api/users`)** | 401 Unauthorized | **403 Forbidden** | **200 OK** |
| **Tạo Tài khoản Mới (`POST /api/users`)** | 401 Unauthorized | **403 Forbidden** | **201 Created** |
| **Bật / Khóa Tài khoản (`PATCH /api/users/:id/status`)** | 401 Unauthorized | **403 Forbidden** | **200 OK** |
| **Thay đổi Vai trò (`PATCH /api/users/:id/role`)** | 401 Unauthorized | **403 Forbidden** | **200 OK** |

> **Nguyên tắc then chốt:** Mọi quyền hạn đều được thực thi tại Backend qua Middleware [`requireAuth`](file:///d:/BM%26ATTT/security-guard/web-app/src/middleware/auth.middleware.js) và [`requireRole`](file:///d:/BM%26ATTT/security-guard/web-app/src/middleware/auth.middleware.js). Frontend không chỉ ẩn nút bấm mà nếu client cố tình gọi API bằng công cụ như cURL hay Postman, máy chủ vẫn sẽ trả về `401 Unauthorized` hoặc `403 Forbidden`.

---

## 3. Danh sách API Xác thực & Phân quyền

### 3.1. Authentication APIs

- `POST /api/auth/login`
  - Body: `{ username, password }`
  - Headers: `Content-Type: application/json`
  - Trả về: `200 OK` (kèm `Set-Cookie: secguard_session=...; HttpOnly; SameSite=Lax`) hoặc `400 / 401 / 429`.
- `POST /api/auth/logout`
  - Headers: Cookie hoặc `Authorization: Bearer <sessionId>`
  - Trả về: `200 OK` (kèm xóa cookie và hủy session trong DB).
- `GET /api/auth/me`
  - Yêu cầu xác thực.
  - Trả về: `{ status: "success", user: { id, username, email, role, isActive } }`.

### 3.2. Alert Mutation APIs (Đã bảo vệ bằng RBAC)

- `PATCH /api/alerts/:id/acknowledge` -> Chỉ `ADMIN` (hoặc admin/operator API key) được phép. `ANALYST` bị từ chối `403 Forbidden`.
- `PATCH /api/alerts/:id/resolve` -> Chỉ `ADMIN` được phép. `ANALYST` bị từ chối `403 Forbidden`.
- `PATCH /api/alerts/:id/status` -> Chỉ `ADMIN` được phép. `ANALYST` bị từ chối `403 Forbidden`.

---

## 4. Cấu hình Môi trường (.env)

Hệ thống hỗ trợ các biến môi trường cấu hình tại `web-app/.env`:

```env
# Server Port & Host
WEB_PORT=3000
WEB_HOST=0.0.0.0

# PostgreSQL Connection
DB_HOST=localhost
DB_PORT=5432
DB_NAME=security_guard
DB_USER=postgres
DB_PASSWORD=<your_db_password>

# Initial Bootstrap Credentials (Optional overrides)
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@securityguard.local
ADMIN_PASSWORD=<custom_initial_password>
```
