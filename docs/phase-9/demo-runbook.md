# SECURITY GUARD — Academic Defense Live Demonstration Runbook (Phase 9)

**Dự án:** SECURITY GUARD — Website Anomaly Monitoring and Detection System  
**Tài liệu:** Kịch bản & Quy trình Thực nghiệm Trình diễn Báo cáo Đồ án BM&ATTT  
**Mục tiêu:** Cung cấp hướng dẫn từng bước chuẩn xác, rõ ràng cho nhóm tác giả khi báo cáo trực tiếp trước Hội đồng Thẩm định.

---

## 1. Chuẩn bị Trước Buổi Báo cáo (Pre-Flight Check)

1. **Kiểm tra môi trường:**
   - PostgreSQL đang chạy tại cổng `5432` (database `security_guard`).
   - Node.js (>= 18), Python (>= 3.10 với virtual environment `detection-engine\venv`).
2. **Kiểm tra cổng dịch vụ khả dụng:**
   - Web Application: `http://localhost:3000`
   - Detection Engine: `http://localhost:5000`
   - Dashboard: `http://localhost:5173`
3. **Mở sẵn các cửa sổ trên màn hình trình chiếu:**
   - **Màn hình chính (Trình duyệt):** Mở sẵn Tab Dashboard tại `http://localhost:5173`.
   - **Tab phụ (Trình duyệt):** Mở sẵn Swagger Docs của Detection Engine tại `http://localhost:5000/docs`.
   - **Cửa sổ Terminal (PowerShell/CMD):** Sẵn sàng để gửi cURL/Invoke-RestMethod mô phỏng request tấn công hoặc chạy test.

---

## 2. Quy trình Khởi động Hệ thống (Startup Sequence)

Mở PowerShell tại thư mục gốc `D:\BM&ATTT\security-guard` và chạy:

```bat
scripts\start\start-all.bat
```

Hoặc nếu muốn khởi động từng dịch vụ riêng biệt để dễ theo dõi log:

- **Terminal 1 (PostgreSQL):** Đảm bảo dịch vụ PostgreSQL đang chạy:
  ```powershell
  # Kiểm tra kết nối DB:
  psql -U postgres -d security_guard -c "SELECT COUNT(*) FROM request_logs;"
  ```
- **Terminal 2 (Detection Engine API - Python):**
  ```powershell
  cd D:\BM&ATTT\security-guard\detection-engine
  .\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 5000
  ```
- **Terminal 3 (Web Application - Node.js):**
  ```powershell
  cd D:\BM&ATTT\security-guard\web-app
  node src/server.js
  ```
- **Terminal 4 (Dashboard - Vite):**
  ```powershell
  cd D:\BM&ATTT\security-guard\dashboard
  npm run dev
  ```

---

## 3. Kịch bản Trình diễn 6 Bước Trước Hội đồng

### BƯỚC 1: Trình diễn Màn hình Đăng nhập & Xác thực Phiên làm việc (Authentication)
- **Thao tác:** Mở Dashboard tại `http://localhost:5173`.
- **Hiện tượng quan sát:**
  - Nếu chưa đăng nhập, hệ thống tự động hiển thị **Màn hình Đăng nhập (Login Screen)** với giao diện tối hiện đại, bảo vệ toàn bộ dữ liệu giám sát.
  - Hỗ trợ đăng nhập bằng username hoặc email.
  - Có các nút điền nhanh 1-Click: `👑 Admin (Toàn quyền)` hoặc `🛡️ Analyst (Phân tích viên)`.
- **Thuyết minh:**
  > *"Kính thưa quý thầy cô, trong Phase 9, hệ thống đã tích hợp toàn diện cơ chế xác thực phiên máy chủ (Server-side Session) lưu trữ trong PostgreSQL và cookie HttpOnly SameSite=Lax. Mọi giao diện và API đều yêu cầu xác thực trước khi truy cập."*
- **Thử nghiệm Đăng nhập:**
  - Nhấn nút **👑 Admin (admin / Admin@123456)** rồi nhấn **Đăng nhập vào Dashboard**.
  - Dashboard mở ra lập tức, hiển thị thông tin người dùng `👤 admin (👑 ADMIN)` trên Header.

---

### BƯỚC 2: Trình diễn Quản trị Người dùng & Phân quyền RBAC (Chỉ dành cho ADMIN)
- **Thao tác 1 (Mở Modal Quản trị):**
  - Nhấp vào nút **`👥 Quản lý Người dùng`** trên thanh Header.
  - Modal mở ra hiển thị danh sách tất cả các tài khoản trong cơ sở dữ liệu (`admin`, `analyst`, `alice`, `bob`).
  - Lưu ý: Cột mật khẩu được ẩn hoàn toàn, không lộ `password_hash`.
- **Thao tác 2 (Tạo tài khoản mới):**
  - Điền form: Tên đăng nhập `test_sec`, Email `test@sec.vn`, Mật khẩu `TestPass123!`, Vai trò `ANALYST`.
  - Nhấn nút **+ Tạo Tài Khoản**. Bản ghi mới xuất hiện ngay lập tức trong bảng.
- **Thao tác 3 (Khóa / Kích hoạt tài khoản):**
  - Bấm nút **"Khóa"** trên tài khoản vừa tạo. Trạng thái lập tức chuyển sang `○ Đã khóa`.
  - Thử đăng nhập bằng tài khoản bị khóa -> Máy chủ từ chối `401 Unauthorized` (`Account is disabled`).
- **Thao tác 4 (Kiểm chứng Quy tắc An toàn):**
  - Thử bấm **"Khóa"** hoặc **"Đổi Role"** trên tài khoản `admin` duy nhất -> Hệ thống từ chối ngay lập tức với cảnh báo: `Cannot deactivate/demote the last active Admin account`.

---

### BƯỚC 3: Trình diễn Khác biệt Phân quyền giữa ADMIN và ANALYST
- **Thao tác 1 (Đăng xuất Admin):** Nhấp nút **`🚪 Đăng xuất`**. Cookie bị xóa trên trình duyệt và session bị hủy trong PostgreSQL.
- **Thao tác 2 (Đăng nhập vai trò ANALYST):**
  - Điền tài khoản `analyst` / `Analyst@123456`.
  - Quan sát Header:
    - Hiển thị nhãn vai trò `🛡️ ANALYST`.
    - **Nút "👥 Quản lý Người dùng" bị ẩn hoàn toàn** khỏi giao diện.
- **Thao tác 3 (Kiểm tra thực thi quyền hạn ở Backend):**
  - Thử bấm nút **"Tiếp nhận"** hoặc **"Giải quyết"** trên một cảnh báo an ninh.
  - **Kết quả:** Máy chủ Express trả về ngay lập tức `403 Forbidden` kèm thông báo màu đỏ:  
    `[Lỗi 403] Insufficient permissions: role 'ANALYST' cannot mutate alerts. Required roles: admin, operator`.
  - Điều này chứng minh quyền hạn được bảo vệ chặt chẽ tại Backend, không chỉ ẩn nút ở giao diện!

---

### BƯỚC 4: Mô phỏng Lưu lượng Hợp lệ & Phát hiện Tấn công Thời gian thực
- **Thao tác 1 (Lưu lượng Hợp lệ):**
  ```powershell
  curl.exe -s "http://localhost:3000/"
  curl.exe -s "http://localhost:3000/search?q=tai+lieu+hoc+tap"
  ```
  *(Request 200 OK, không sinh cảnh báo).*
- **Thao tác 2 (Tấn công SQL Injection):**
  ```powershell
  curl.exe -s "http://localhost:3000/search?q=%27%20UNION%20SELECT%20username,password%20FROM%20users--"
  ```
  - Banner Toast màu đỏ xuất hiện tức thì: `🚨 Phát hiện cảnh báo mới: [SQL_INJECTION] từ IP 127.0.0.1 (Risk: 80)`.
  - Dòng cảnh báo xuất hiện ngay đầu danh sách qua Server-Sent Events mà **không cần F5 tải lại trang**.
- **Thao tác 3 (Path Traversal & Command Injection):**
  ```powershell
  curl.exe -s "http://localhost:3000/download?file=../../../../etc/passwd"
  curl.exe -s "http://localhost:3000/ping?ip=127.0.0.1;cat+/etc/shadow"
  ```

---

### BƯỚC 5: Trình diễn Phát hiện Bất thường bằng Học máy (Isolation Forest)
- **Thao tác:** Gửi request mang đặc trưng ngoại lai sâu (chiều dài bất thường, ký tự lặp nhưng không chứa từ khóa SQLi cổ điển):
  ```powershell
  curl.exe -s "http://localhost:3000/api/search?marker=ml_demo_anomaly&token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  ```
- **Thuyết minh:**
  > *"Mẫu request này hoàn toàn không kích hoạt bất kỳ Rule Regex tĩnh nào. Tuy nhiên, Feature Extractor trích xuất 11 vector số học đưa vào mô hình **Isolation Forest**. Mô hình nhận diện điểm bất thường, gán nhãn `ML_ANOMALY` với Badge màu tím đặc trưng trên giao diện."*

---

### BƯỚC 6: Trình diễn Toàn bộ Bộ Kiểm thử Tự động (156/156 Tests PASS)
- **Thao tác:**
  ```powershell
  cmd /c scripts\test\test-all.bat
  ```
- **Kết quả minh chứng trước Hội đồng:**
  - Web Application: **75/75 tests PASS (100%)**
  - Detection Engine: **81/81 tests PASS (100%)**
  - Grand Total: **156/156 automated tests PASS (100%)**
  - Thời gian thực thi: ~12 giây.

---

## 4. Xử lý Tình huống Sự cố Trong Buổi Báo cáo (Troubleshooting)

| Sự cố có thể gặp | Nguyên nhân | Cách xử lý nhanh |
| :--- | :--- | :--- |
| Màn hình báo "Không thể kết nối máy chủ" | Web App (cổng 3000) hoặc Detection Engine (cổng 5000) chưa bật | Chạy `scripts\start\start-all.bat` hoặc khởi động lại Web App |
| Đăng nhập báo 429 Too Many Requests | Đã thử nhập sai quá 5 lần | Chờ 5 phút hoặc restart lại tiến trình Web App để reset map |
| SSE báo "Polling (Fallback)" | Trình duyệt bị nghẽn kết nối hoặc Web App vừa khởi động lại | Nhấn nút F5 trên trình duyệt để khởi tạo lại luồng SSE |
| Quên mật khẩu Admin | Chưa chạy bootstrap | Chạy lệnh `npm run bootstrap:admin` tại thư mục `web-app` để reset về `admin` / `Admin@123456` |
