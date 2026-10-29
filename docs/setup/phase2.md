# Hướng Dẫn Thiết Lập & Vận Hành Phase 2 - SECURITY GUARD

Tài liệu hướng dẫn triển khai Phase 2: Tích hợp Web Application, Logging Pipeline và Cơ sở dữ liệu PostgreSQL.

---

## 1. Yêu cầu Hệ thống Phase 2
- **Node.js:** v20.x hoặc v24.x
- **Python:** 3.11+ hoặc 3.13+ (cho Detection Engine)
- **PostgreSQL:** Phiên bản 15 hoặc 16 (chạy cục bộ cổng 5432 hoặc qua Docker)
- **Hệ điều hành:** Windows 11 Native hoặc Ubuntu 24.04 LTS (môi trường Lab)

---

## 2. Cấu hình Môi trường (`.env`)

Sao chép `.env.example` thành `.env`:
```bash
copy .env.example .env
```

Các biến môi trường phục vụ kết nối CSDL:
```env
# Database Configuration (PostgreSQL)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=security_guard
DB_USER=security_guard
DB_PASSWORD=change_me
```

> [!NOTE]
> Web Application hỗ trợ cơ chế **Graceful Degradation**: nếu PostgreSQL chưa được bật, ứng dụng vẫn tự động chuyển sang chế độ file-only fallback (`requests.log`) và **hoàn toàn không bị crash**.

---

## 3. Khởi tạo Cơ sở Dữ liệu (Nếu có PostgreSQL)

Khi PostgreSQL đang hoạt động:
```bash
cd web-app
npm run db:init
```
Lệnh trên sẽ tự động:
1. Tạo bảng `users`, `request_logs`, `detection_rules`, `security_alerts`.
2. Tạo các index tối ưu: `timestamp`, `ip`, `status_code`, `method`, `url`.
3. Nạp dữ liệu mẫu ban đầu từ `database/seed/`.

---

## 4. Khởi chạy Hệ thống

Từ thư mục gốc `D:\BM&ATTT\security-guard`:
```cmd
:: Khởi chạy tất cả dịch vụ trong 3 console riêng biệt
scripts\start\start-all.bat
```

Các cổng hoạt động:
- **Web Application:** `http://localhost:3000`
- **Detection Engine:** `http://localhost:5000/docs`
- **Dashboard:** `http://localhost:5173`
- **PostgreSQL:** `localhost:5432`

---

## 5. Dừng Hệ thống
```cmd
scripts\stop\stop-all.bat
```
Lệnh sẽ giải phóng toàn bộ tiến trình trên các cổng 3000, 5000, 5173 và đóng cửa sổ tương ứng.
