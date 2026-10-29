# KỊCH BẢN TRÌNH DIỄN & HƯỚNG DẪN BẢO VỆ ĐỒ ÁN (DEMO RUNBOOK)
## Phase 10: Multi-Website Monitoring & Active Enforcement Demonstration

Tài liệu này cung cấp hướng dẫn từng bước để trình diễn toàn bộ chức năng Phase 10 trước hội đồng đánh giá.

---

## 1. Khởi động Toàn bộ Hệ sinh thái Dịch vụ

Chạy file kịch bản tự động trên Windows:
```cmd
cd D:\BM&ATTT\security-guard
scripts\start\start-all.bat
```

Kịch bản sẽ tự động mở 6 cửa sổ console tương ứng với 6 dịch vụ:
1. `Window 1: Detection Engine` -> `http://localhost:5000/docs`
2. `Window 2: Web Application`  -> `http://localhost:3000`
3. `Window 3: Dashboard`        -> `http://localhost:5173`
4. `Window 4: Gateway (Proxy)`  -> `http://localhost:8080`
5. `Window 5: Demo Node Site`   -> `http://localhost:4001`
6. `Window 6: Demo Python Site` -> `http://localhost:4002`

---

## 2. Các Kịch bản Trình diễn Thực tế

### Kịch bản 1: Đăng nhập & Tham quan Bảng Điều khiển Đa Website
1. Mở trình duyệt tại: `http://localhost:5173`.
2. Đăng nhập với tài khoản quản trị:
   - **Tên đăng nhập:** `admin`
   - **Mật khẩu:** `Admin@123456`
3. Quan sát mục **🌐 Giám sát Đa Website & Active Enforcement (Phase 10)**:
   - Thấy 2 thẻ website đã được đăng ký:
     - `Node.js Demo Shop` (`site_demo_node` -> Port 4001).
     - `Python Demo Portal` (`site_demo_python` -> Port 4002).
   - Thấy trạng thái của Gateway: `Online (:8080)`.

---

### Kịch bản 2: Truy cập Lưu lượng Bình thường qua Gateway
Mở tab mới trên trình duyệt hoặc gửi cURL:
1. Truy cập Node.js Shop qua Gateway:
   ```
   http://localhost:8080/site/site_demo_node/products
   ```
   *Kết quả:* Trả về danh sách 5 sản phẩm từ server Node.js cổng 4001.
2. Truy cập Python Portal qua Gateway:
   ```
   http://localhost:8080/site/site_demo_python/directory
   ```
   *Kết quả:* Trả về danh bạ 4 nhân viên từ server Python cổng 4002.
3. Quay lại Dashboard: Quan sát số lượng request tăng lên trong bảng tổng quan.

---

### Kịch bản 3: Tấn công thử nghiệm ở chế độ `MONITOR_ONLY` (Chỉ cảnh báo)
Mặc định `site_demo_node` đang ở chế độ `MONITOR_ONLY`:
1. Gửi payload tấn công SQL Injection vào endpoint tìm kiếm:
   ```
   http://localhost:8080/site/site_demo_node/search?q=%27%20OR%201=1--
   ```
2. **Quan sát kết quả:**
   - Người dùng vẫn nhận được kết quả tìm kiếm bình thường (HTTP 200 OK — không bị gián đoạn).
   - Trên Dashboard, thông báo Toast xuất hiện tức thì qua Live SSE Stream: `🚨 Phát hiện cảnh báo mới: [SQL_INJECTION]`.
   - Cảnh báo mới được gán nhãn `site_demo_node` trong bảng Cảnh báo An ninh.

---

### Kịch bản 4: Kích hoạt `ENFORCE` & Chặn Tấn công Chủ động (Active Enforcement)
1. Trên giao diện Dashboard, tại thẻ `Node.js Demo Shop`, nhấn nút:  
   **🛡️ Kích hoạt ENFORCE**.  
   (Huy hiệu chuyển sang màu đỏ: `🛡️ ENFORCE (Chặn chủ động)`).
2. Gửi lại chính xác payload tấn công SQL Injection vừa nãy:
   ```
   http://localhost:8080/site/site_demo_node/search?q=%27%20OR%201=1--
   ```
3. **Quan sát kết quả:**
   - Trình duyệt/Client nhận ngay **HTTP 403 Forbidden**:
     ```json
     {
       "status": "blocked",
       "error": "Forbidden by Security Guard",
       "website_id": "site_demo_node",
       "reason": "Detected Attack [SQL_INJECTION]: Matched SQL injection pattern: '' or 1=1'",
       "mode": "ENFORCE"
     }
     ```
   - Request độc hại hoàn toàn bị chặn đứng ở Gateway và **không bao giờ chạm tới ứng dụng Node.js Upstream**!
   - Trong bảng **Lịch sử Thực thi (Enforcement Audit Trail)** trên Dashboard, dòng sự kiện `[BLOCKED]` màu đỏ xuất hiện theo thời gian thực.

---

### Kịch bản 5: Đặt Luật Quản trị Chặn IP & Phân quyền RBAC
1. Tại thẻ `Python Demo Portal`, nhấn nút **⚙️ Policies**.
2. Nhập biểu mẫu:
   - Loại chính sách: `IP_BLOCK`
   - IP cần chặn: `198.51.100.42`
   - Hành động: `BLOCK`
   - Lý do: `Chặn IP nghi ngờ dò quét brute force`
3. Nhấn **Áp dụng Chính sách**.
4. Chuyển `Python Demo Portal` sang chế độ `ENFORCE`.
5. Thử gửi request giả lập IP bị chặn:
   ```bash
   curl -H "X-Forwarded-For: 198.51.100.42" http://localhost:8080/site/site_demo_python/directory
   ```
   *Kết quả:* Nhận ngay HTTP 403 Forbidden kèm lý do `Chặn IP nghi ngờ dò quét brute force`.

---

## 3. Lệnh Demo Tự động 1-Click

Để kiểm chứng toàn bộ kịch bản trên chỉ trong 5 giây, chạy lệnh:
```cmd
cd D:\BM&ATTT\security-guard
node scripts\test\demo_phase10.js
```
Kịch bản tự động sẽ kiểm tra và in ra toàn bộ minh chứng thành công từ Step 1 đến Step 6!
