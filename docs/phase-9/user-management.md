# SECURITY GUARD — Phase 9: User Management Architecture & Administration Guide

**Dự án:** SECURITY GUARD — Website Anomaly Monitoring and Detection System  
**Học phần:** Bảo mật và An toàn thông tin (BM&ATTT)  
**Tài liệu:** Hướng dẫn Quản trị Người dùng & Phân quyền RBAC  

---

## 1. Cấu trúc Cơ sở Dữ liệu (Database Schema)

Hệ thống quản trị tài khoản và phiên làm việc được lưu trữ tại PostgreSQL thông qua 2 bảng chính:

### 1.1. Bảng `users` (Quản lý Danh tính Tài khoản)

```sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'ANALYST',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

- `username`: Định danh tài khoản duy nhất (UNIQUE), tối thiểu 3 ký tự.
- `email`: Hộp thư điện tử duy nhất (UNIQUE), kiểm tra định dạng email hợp lệ.
- `password_hash`: Chuỗi băm Bcrypt an toàn (10 salt rounds).
- `role`: Vai trò người dùng, gồm `ADMIN` (Quản trị viên) hoặc `ANALYST` (Phân tích viên).
- `is_active`: Trạng thái kích hoạt (TRUE = hoạt động, FALSE = bị khóa).

### 1.2. Bảng `user_sessions` (Quản lý Phiên Đăng nhập Phía Máy chủ)

```sql
CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(128) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip VARCHAR(45),
    user_agent TEXT
);
```

- `session_id`: Chuỗi ngẫu nhiên 32 bytes (64 ký tự hex) bảo mật cao.
- `user_id`: Khóa ngoại liên kết tới bảng `users` (`ON DELETE CASCADE`).
- `expires_at`: Mốc thời gian hết hạn của phiên làm việc (24 giờ kể từ khi tạo).

---

## 2. Các API Quản trị Tài khoản (User Management APIs)

Tất cả các API dưới đây đều được bảo vệ nghiêm ngặt bởi Middleware:
`requireAuth` + `requireRole(['ADMIN'])`.  
Người dùng mang vai trò `ANALYST` hoặc chưa đăng nhập khi gửi request tới các endpoint này đều bị từ chối với mã lỗi `403 Forbidden` hoặc `401 Unauthorized`.

### 2.1. Danh sách người dùng
- **Endpoint:** `GET /api/users`
- **Quyền:** `ADMIN`
- **Mô tả:** Lấy danh sách toàn bộ tài khoản trong hệ thống.
- **Bảo mật:** Trường `password_hash` bị loại bỏ hoàn toàn khỏi kết quả trả về.

### 2.2. Tạo tài khoản mới
- **Endpoint:** `POST /api/users`
- **Quyền:** `ADMIN`
- **Body:**
  ```json
  {
    "username": "analyst_sec2",
    "email": "analyst2@securityguard.local",
    "password": "SecurePassword123!",
    "role": "ANALYST"
  }
  ```
- **Xác thực đầu vào:**
  - `username`: Tối thiểu 3 ký tự, chỉ chứa chữ cái, số, gạch dưới và gạch ngang.
  - `email`: Định dạng email chuẩn.
  - `password`: Tối thiểu 6 ký tự.
  - `role`: Chỉ chấp nhận `ADMIN` hoặc `ANALYST`.
  - Kiểm tra chống trùng lặp `username` hoặc `email` (trả về `400 Bad Request` nếu trùng).

### 2.3. Bật / Khóa tài khoản
- **Endpoint:** `PATCH /api/users/:id/status`
- **Quyền:** `ADMIN`
- **Body:** `{ "isActive": false }` hoặc `{ "isActive": true }`
- **Quy tắc an toàn (Safety Rule):**
  - Không cho phép khóa tài khoản `ADMIN` đang hoạt động cuối cùng trong hệ thống (`Cannot deactivate the last active Admin account`).
  - Khi một tài khoản bị vô hiệu hóa (`isActive: false`), tất cả phiên làm việc hiện tại của tài khoản đó trong bảng `user_sessions` đều bị hủy ngay lập tức (`DELETE FROM user_sessions WHERE user_id = ...`).

### 2.4. Thay đổi vai trò
- **Endpoint:** `PATCH /api/users/:id/role`
- **Quyền:** `ADMIN`
- **Body:** `{ "role": "ADMIN" }` hoặc `{ "role": "ANALYST" }`
- **Quy tắc an toàn (Safety Rule):**
  - Không cho phép hạ quyền tài khoản `ADMIN` đang hoạt động cuối cùng thành `ANALYST` (`Cannot demote the last active Admin account`).

---

## 3. Quy trình Khởi tạo Tài khoản Quản trị Ban đầu (Bootstrap Admin)

Để đảm bảo an toàn tuyệt đối và tránh để mở endpoint đăng ký tự do cho phép kẻ tấn công tự nâng quyền thành Admin:
- Hệ thống cung cấp script khởi tạo bảo mật **Bootstrap Admin** chuyên biệt tại [`web-app/src/scripts/bootstrap-admin.js`](file:///d:/BM%26ATTT/security-guard/web-app/src/scripts/bootstrap-admin.js).
- Script này chỉ chạy khi quản trị viên hệ thống chủ động thực thi từ giao diện dòng lệnh (CLI).

### 3.1. Lệnh thực thi Bootstrap

Mở Terminal và chạy lệnh sau từ thư mục `web-app`:

```powershell
npm run bootstrap:admin
```

Hoặc thiết lập mật khẩu tùy chọn an toàn qua biến môi trường:

```powershell
$env:ADMIN_USERNAME = "myadmin"
$env:ADMIN_PASSWORD = "SuperSecretPassword123!"
npm run bootstrap:admin
```

### 3.2. Tài khoản thử nghiệm mặc định sau khi Bootstrap:

| Vai trò | Tên đăng nhập | Email | Mật khẩu mẫu | Ghi chú |
| :--- | :--- | :--- | :--- | :--- |
| **👑 ADMIN** | `admin` | `admin@securityguard.local` | `Admin@123456` | Toàn quyền quản trị, xử lý cảnh báo, quản lý user |
| **🛡️ ANALYST** | `analyst` | `analyst@securityguard.local` | `Analyst@123456` | Chỉ xem Dashboard, log và cảnh báo (không thể sửa đổi) |

---

## 4. Giao diện Quản trị trên Dashboard (User Management Modal)

- Nút **👥 Quản lý Người dùng** chỉ hiển thị trên Header khi người dùng đăng nhập với vai trò **ADMIN**.
- Người dùng có thể:
  1. Thêm nhanh người dùng mới qua Form trực quan.
  2. Bấm nút **"Đổi Role"** để luân chuyển vai trò giữa ADMIN và ANALYST.
  3. Bấm nút **"Khóa"** hoặc **"Kích hoạt"** tài khoản tức thời.
  4. Hệ thống cảnh báo rõ ràng khi cố tình vi phạm các quy tắc an toàn.
