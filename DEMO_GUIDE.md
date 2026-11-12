# HƯỚNG DẪN THỰC NGHIỆM VÀ DEMO TOÀN DIỆN
## ĐỒ ÁN: SECURITY GUARD — HỆ THỐNG GIÁM SÁT, PHÁT HIỆN BẤT THƯỜNG & PHÒNG THỦ THÍCH ỨNG

---

## 📌 MỤC LỤC
1. [Thông Số Kiến Trúc & Cổng Dịch Vụ](#1-thông-số-kiến-trúc--cổng-dịch-vụ)
2. [Quy Trình Chuẩn Bị & Khởi Động Hệ Thống](#2-quy-trình-chuẩn-bị--khởi-động-hệ-thống)
3. [Kịch Bản 1: Giám Sát Đa Website & Kiểm Tra Kết Nối (Tab Giám Sát Website)](#3-kịch-bản-1-giám-sát-đa-website--kiểm-tra-kết-nối)
4. [Kịch Bản 2: Phát Hiện Tấn Công Thời Gian Thực (Tab Quản Lý Cảnh Báo)](#4-kịch-bản-2-phát-hiện-tấn-công-thời-gian-thực)
   - 4.1. SQL Injection (SQLi)
   - 4.2. Cross-Site Scripting (Reflected & Stored XSS)
   - 4.3. Command Injection
   - 4.4. Path Traversal / File Inclusion
   - 4.5. Brute Force Login
5. [Kịch Bản 3: Xem Bằng Chứng & Phân Tích Machine Learning (Evidence & ML)](#5-kịch-bản-3-xem-bằng-chứng--phân-tích-machine-learning)
6. [Kịch Bản 4: Quy Trình Xử Lý Sự Cố Chuẩn SOC (Alert Lifecycle Management)](#6-kịch-bản-4-quy-trình-xử-lý-sự-cố-chuẩn-soc)
7. [Kịch Bản 5: Phòng Thủ Chủ Động Thực Tế (ENFORCE Mode - Practical Prevention)](#7-kịch-bản-5-phòng-thủ-chủ-động-thực-tế)
8. [Kịch Bản 6: Thiết Lập Chính Sách Chặn Quản Trị (Custom Policy Engine)](#8-kịch-bản-6-thiết-lập-chính-sách-chặn-quản-trị)
9. [Kịch Bản 7: Phân Quyền Người Dùng & Quản Trị Hệ Thống (RBAC)](#9-kịch-bản-7-phân-quyền-người-dùng--quản-trị-hệ-thống)
10. [Kịch Bản 8: Đánh Giá Thực Nghiệm & Benchmark Phòng Thủ (Tab Phòng Thủ Thích Ứng)](#10-kịch-bản-8-đánh-giá-thực-nghiệm--benchmark)
11. [Dừng Hệ Thống & Khắc Phục Sự Cố Thường Gặp (Troubleshooting)](#11-dừng-hệ-thống--khắc-phục-sự-cố)

---

## 1. THÔNG SỐ KIẾN TRÚC & CỔNG DỊCH VỤ

| Thành phần | Địa chỉ truy cập | Ghi chú & Tài khoản |
|---|---|---|
| **Dashboard Quản Trị** | `http://localhost:5173` | • Admin: `admin` / `Admin@123456`<br>• Analyst: `analyst` / `Analyst@123456` |
| **Monitoring Gateway (WAF Proxy)** | `http://localhost:8080` | Trạm kiểm soát lưu lượng đứng trước các Website |
| **Detection & ML Engine** | `http://localhost:5000/docs` | FastAPI / Flask + Isolation Forest (Python) |
| **Web App Backend API** | `http://localhost:3000` | Node.js Express + PostgreSQL + SSE Stream |
| **OWASP Juice Shop** | `http://localhost:8080/site/owasp_juice_shop/` | Docker Container (:4101) |
| **DVWA (Damn Vulnerable Web App)**| `http://localhost:8080/site/dvwa/login.php` | Docker Container (:4102) — `admin` / `password` |
| **OWASP WebGoat** | `http://localhost:8080/site/owasp_webgoat/WebGoat` | Docker Container (:4103) |
| **OWASP WebWolf** | `http://localhost:8080/site/owasp_webwolf/WebWolf` | Docker Container (:9091) |

---

## 2. QUY TRÌNH CHUẨN BỊ & KHỞI ĐỘNG HỆ THỐNG

### Bước 1: Khởi động Docker Desktop
1. Mở phần mềm **Docker Desktop** trên Windows.
2. Kiểm tra các container mục tiêu (`dvwa`, `juice-shop`, `webgoat`) hiển thị màu xanh (**Running**).

### Bước 2: Khởi động 4 dịch vụ Security Guard
Mở PowerShell tại thư mục `D:\BM&ATTT\security-guard`:
```powershell
.\scripts\start\start-all.bat
```
*(Script sẽ tự động khởi động 4 cửa sổ console: Detection Engine :5000, Web App :3000, Dashboard :5173, Gateway :8080)*.

### Bước 3: Bố cục màn hình đề xuất khi thuyết trình
- **Nửa màn hình TRÁI**: Trình duyệt mở mục tiêu demo (ví dụ DVWA qua Gateway: `http://localhost:8080/site/dvwa/login.php`).
- **Nửa màn hình PHẢI**: Trình duyệt mở Dashboard Security Guard: `http://localhost:5173`.
- Bố cục chia đôi giúp người xem nhìn thấy phản ứng tức thì (Real-time) ngay khi bấm nút tấn công.

---

## 3. KỊCH BẢN 1: GIÁM SÁT ĐA WEBSITE & KIỂM TRA KẾT NỐI

> **Mục tiêu**: Chứng minh khả năng quản lý tập trung nhiều website độc lập công nghệ, giám sát chỉ số lưu lượng và chẩn đoán kết nối sức khỏe (Health Check).

1. Trên Dashboard, bấm chọn tab: **`🌐 Giám Sát Website (Docker Labs)`**.
2. **Quan sát 4 thẻ Website đại diện cho 4 lab Docker**:
   - `OWASP Juice Shop` (Node.js/Angular)
   - `DVWA` (PHP/Apache)
   - `OWASP WebGoat` (Java Spring Boot)
   - `OWASP WebWolf` (Java)
3. **Thao tác kiểm tra sức khỏe kết nối (Health Check)**:
   - Trên thẻ **DVWA**, bấm nút **"🩺 Kiểm tra kết nối"**.
   - Hệ thống gửi request chẩn đoán tới upstream: Hiển thị nhãn xanh **`● HEALTHY`** kèm thông báo chẩn đoán: *"Reverse Proxy upstream connection verified successfully"*.
4. **Mở website thông qua Gateway**:
   - Bấm nút **"🚀 Mở qua Gateway (:8080)"** để bắt đầu tương tác có giám sát.

---

## 4. KỊCH BẢN 2: PHÁT HIỆN TẤN CÔNG THỜI GIAN THỰC

> **Mục tiêu**: Chứng minh hệ thống bắt request thực tế qua Gateway, kết hợp 8 bộ luật chữ ký và Machine Learning để nhận diện chính xác các nhóm tấn công nguy hiểm, truyền thông báo tức thì qua Server-Sent Events (SSE).

Đảm bảo website DVWA đang ở chế độ **`MONITOR_ONLY`**. Đăng nhập DVWA (`admin` / `password`), vào **DVWA Security** $\rightarrow$ chọn mức **Low** $\rightarrow$ bấm **Submit**.

### 4.1. Tấn công SQL Injection (SQLi)
1. Trên menu DVWA, chọn mục **SQL Injection**.
2. Tại ô *User ID*, nhập payload Tautology:
   ```sql
   1' OR '1'='1
   ```
   Hoặc payload trích xuất dữ liệu:
   ```sql
   1' UNION SELECT null, user() #
   ```
3. Bấm **Submit**.
4. **Hiện tượng quan sát**:
   - **Bên DVWA**: Dữ liệu người dùng hiển thị ra màn hình (cuộc tấn công thành công trên web).
   - **Bên Dashboard**:
     - Toast thông báo đỏ nhảy lên góc trên: `🚨 Phát hiện cảnh báo mới: [SQL_INJECTION]`.
     - Tab **🚨 Quản Lý Cảnh Báo** xuất hiện dòng sự cố mới với mức độ **`CRITICAL`**, Risk Score: **`90 - 100`**.

### 4.2. Tấn công Cross-Site Scripting (XSS Reflected)
1. Trên menu DVWA, chọn mục **XSS (Reflected)**.
2. Tại ô nhập tên, dán payload:
   ```html
   <script>alert('Security-Guard-XSS')</script>
   ```
3. Bấm **Submit**.
4. **Hiện tượng quan sát**:
   - **Bên DVWA**: Hộp thoại popup JavaScript kích hoạt trên màn hình.
   - **Bên Dashboard**: Lập tức xuất hiện cảnh báo **`XSS`** với mức độ **`HIGH`** và Risk Score cao.

### 4.3. Tấn công Command Injection
1. Trên menu DVWA, chọn mục **Command Injection**.
2. Nhập payload thực thi lệnh hệ thống nối tiếp:
   ```bash
   127.0.0.1; whoami
   ```
   *(Hoặc trên Windows: `127.0.0.1 && dir`)*.
3. Bấm **Submit**.
4. **Hiện tượng quan sát**: Dashboard ghi nhận cảnh báo **`COMMAND_INJECTION`** (Rule ID: `RULE-CMD-001`, Severity: `HIGH`).

### 4.4. Tấn công Leo thang thư mục (Path Traversal / LFI)
1. Trên menu DVWA, chọn mục **File Inclusion**.
2. Thử truy cập leo cây thư mục hệ thống trên thanh địa chỉ:
   ```text
   http://localhost:8080/site/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd
   ```
3. **Hiện tượng quan sát**: Dashboard phát cảnh báo **`PATH_TRAVERSAL`** (Rule ID: `RULE-TRAV-001`).

### 4.5. Tấn công Dò quét mật khẩu (Brute Force)
1. Mở cửa sổ ẩn danh hoặc đăng xuất khỏi DVWA.
2. Gõ sai tài khoản/mật khẩu liên tục 4–5 lần trong thời gian ngắn.
3. **Hiện tượng quan sát**: Hệ thống nhận diện hành vi quét lặp và phát cảnh báo **`BRUTE_FORCE`** từ Client IP đó.

---

## 5. KỊCH BẢN 3: XEM BẰNG CHỨNG & PHÂN TÍCH MACHINE LEARNING

> **Mục tiêu**: Chứng minh tính minh bạch (Explainable Security) — giải thích được lý do vì sao một request bị coi là độc hại.

1. Tại bảng Quản lý cảnh báo, chọn dòng cảnh báo vừa xuất hiện $\rightarrow$ Bấm nút **"Chi tiết"**.
2. **Cửa sổ Modal phân tích đa chiều mở ra, gồm 4 khối dữ liệu**:
   - **Loại tấn công & Mức độ**: `SQL_INJECTION` | Severity `CRITICAL`.
   - **Mô tả phát hiện (Detection Reason)**: Hiển thị chuỗi vi phạm luật chữ ký:
     `Matched SQL injection signature in request: ' OR 1=1 or UNION SELECT`.
   - **Khối Phân tích Học máy (Isolation Forest Anomaly)**:
     - *Model Version*: `1.0.0 (Unsupervised Isolation Forest)`
     - *ML Anomaly Score*: Điểm ngoại lai (0–100) được tính dựa trên 11 đặc trưng (độ dài, ký tự đặc biệt, entropy...).
     - *Decision Raw Score*: Điểm quyết định của thuật toán cây phân lập.
   - **Khối Liên kết HTTP Request Log**:
     - *Log ID*: `#...`
     - *Client IP*: `127.0.0.1`
     - *HTTP Status*: `200`
     - *Độ trễ phản hồi*: Thường chỉ từ `2 - 8 ms`.

---

## 6. KỊCH BẢN 4: QUY TRÌNH XỬ LÝ SỰ CỐ CHUẨN SOC

> **Mục tiêu**: Trình diễn năng lực quản trị vòng đời cảnh báo (Alert Lifecycle) của một chuyên viên phân tích bảo mật (SOC Analyst).

1. Mở xem chi tiết một cảnh báo đang có trạng thái **`NEW`** (Cần xử lý).
2. **Tiếp nhận sự cố**:
   - Bấm nút **"✓ Tiếp nhận (Acknowledge)"**.
   - Trạng thái chuyển sang **`ACKNOWLEDGED`** (Thẻ thống kê trên Dashboard tự động nhảy số).
3. **Giải quyết sự cố**:
   - Sau khi rà soát bằng chứng, bấm nút **"✓ Đánh dấu đã giải quyết (Resolve)"**.
   - Trạng thái chuyển sang **`RESOLVED`** (Màu xanh lá cây).
4. **Mở lại khi có diễn biến mới**:
   - Bấm **"↺ Mở lại (Reopen)"** để đưa trạng thái quay lại phục vụ điều tra tiếp.
5. **Thử nghiệm Bộ lọc cảnh báo thông minh**:
   - Lọc theo Website: Chọn chỉ xem `dvwa` hoặc `owasp_juice_shop`.
   - Lọc theo Mức độ: Chọn `CRITICAL`, `HIGH`, `MEDIUM`.
   - Lọc theo Trạng thái: Chọn `NEW`, `ACKNOWLEDGED`, `RESOLVED`.
   - Kiểm tra các nút phân trang: `Trang 1 / Trang 2...`.

---

## 7. KỊCH BẢN 5: PHÒNG THỦ CHỦ ĐỘNG THỰC TẾ (ENFORCE MODE)

> **Mục tiêu**: **ĐIỂM NHẤN CỦA ĐỒ ÁN** — Chứng minh năng lực ngăn chặn thực tế (Practical Prevention) ngay tại Gateway. Kẻ tấn công bị chặn đứng bằng HTTP 403, mã độc không thể chạm tới máy chủ CSDL.

1. **Bật chế độ Chặn tự động**:
   - Trên Dashboard, chuyển sang tab **`🌐 Giám Sát Website (Docker Labs)`**.
   - Tìm thẻ **DVWA**, bấm vào nút đỏ: **`🛡️ ENFORCE`**.
   - Nhãn trạng thái đổi thành nhãn đỏ: **`🛡️ ENFORCE`** (Active Enforcement).
2. **Thực hiện lại đòn tấn công**:
   - Quay lại trang **SQL Injection** trên DVWA.
   - Nhập lại:
     ```sql
     1' OR '1'='1
     ```
   - Bấm **Submit**.
3. **Hiện tượng quan sát**:
   - **Bên DVWA**: **Bị chặn đứng 100%!** Màn hình không hiện danh sách người dùng nữa mà trả về phản hồi chặn từ WAF Gateway:
     ```json
     {
       "status": "blocked",
       "error": "Forbidden by Security Guard",
       "website_id": "dvwa",
       "reason": "Detected Attack [SQL_INJECTION]: Matched SQL injection signature in request...",
       "mode": "ENFORCE",
       "matched_rule": "SQL_INJECTION"
     }
     ```
   - **Bên Dashboard**:
     - Bảng **Live HTTP Requests** xuất hiện dòng request với mã trạng thái **`403`**.
     - Cuộn xuống phần **Lịch sử Giám sát & Thực thi (Enforcement Audit Logs)**: Ghi nhận một bản ghi audit mới với hành động **`BLOCKED`** màu đỏ.
     - Số lượng *"Bất thường / Bị chặn"* trên thẻ DVWA tự động tăng lên.
4. *(Tùy chọn)*: Bấm nút **`👁️ MONITOR_ONLY`** để đưa website trở lại chế độ giám sát quan sát bình thường.

---

## 8. KỊCH BẢN 6: THIẾT LẬP CHÍNH SÁCH CHẶN QUẢN TRỊ (POLICY ENGINE)

> **Mục tiêu**: Chứng minh khả năng tự định nghĩa chính sách bảo vệ riêng cho từng website (IP Blacklist, Path Restriction).

1. Trên tab **`🌐 Giám Sát Website`**, tại thẻ **DVWA**, bấm nút **"⚙️ Chính sách"**.
2. Cửa sổ Quản lý chính sách mở ra:
   - **Loại chính sách**: Chọn `IP_BLOCK` (Chặn IP) hoặc `PATH_RESTRICT` (Giới hạn đường dẫn nhạy cảm).
   - **Giá trị khớp**: Nhập ví dụ IP cần chặn `192.168.1.100` hoặc đường dẫn `/vulnerabilities/upload/`.
   - **Hành động**: `BLOCK`.
   - **Lý do**: *"Cấm truy cập chức năng upload file không an toàn"*.
   - Bấm **"Thêm Chính sách Mới"**.
3. Chính sách mới xuất hiện ngay lập tức trong bảng chính sách và có hiệu lực thực thi theo thứ tự ưu tiên (Priority 1: Custom Policies $\rightarrow$ Priority 2: Deterministic Rules $\rightarrow$ Priority 3: Isolation Forest ML).

---

## 9. KỊCH BẢN 7: PHÂN QUYỀN NGƯỜI DÙNG & QUẢN TRỊ HỆ THỐNG (RBAC)

> **Mục tiêu**: Chứng minh mô hình kiểm soát truy cập phân quyền chặt chẽ theo vai trò (Role-Based Access Control).

1. **Khám phá quyền Admin**:
   - Khi đang đăng nhập bằng tài khoản `admin` (Role: `ADMIN` màu tím trên góc phải).
   - Bấm nút: **"👥 Quản lý Người dùng"**.
   - Cửa sổ quản lý hiện danh sách tài khoản (`admin`, `analyst`...).
   - Có thể đổi vai trò (ADMIN $\leftrightarrow$ ANALYST $\leftrightarrow$ VIEWER), kích hoạt / vô hiệu hóa tài khoản, hoặc tạo tài khoản mới.
2. **Kiểm tra cơ chế phân quyền (Principle of Least Privilege)**:
   - Bấm **"🚪 Đăng xuất"**.
   - Bấm nút chọn mẫu nhanh: **🛡️ Analyst (Phân tích viên)** $\rightarrow$ Đăng nhập.
   - Nhìn vào góc phải: Role hiển thị là `ANALYST` (màu xanh dương).
   - **Quan sát sự khác biệt**:
     - Nút "👥 Quản lý Người dùng" **bị ẩn hoàn toàn**.
     - Nút chuyển đổi chế độ `ENFORCE` trên các thẻ Website **bị ẩn** (chỉ Admin mới có quyền bật/tắt chính sách chặn của hệ thống).
     - Analyst chỉ được xem, phân tích và thực hiện quy trình xử lý vòng đời cảnh báo (Acknowledge / Resolve).

---

## 10. KỊCH BẢN 8: ĐÁNH GIÁ THỰC NGHIỆM & BENCHMARK

> **Mục tiêu**: Trình diễn các số liệu nghiên cứu khoa học, đo lường định lượng chứng minh tính mới và khả năng cạnh tranh của đồ án.

1. Bấm chuyển sang tab: **`🛡️ Phòng Thủ Thích Ứng & Benchmark`**.
2. **Quan sát Bảng chỉ số thực nghiệm (Phase 8 Verified)**:
   - **Holdout Accuracy**: **`97.5%`**
   - **F1-Score**: **`0.974`** (Độ cân bằng hoàn hảo giữa Precision và Recall).
   - **Khả năng tổng quát hóa mẫu tấn công mới (Unseen Attack Generalization)**: **`93.8%`** (Recall đạt `92.5%`).
   - **Độ trễ trung vị đo lường đầu cuối (HTTP RTT p50)**: Chỉ **`3.75 ms`** (Gần như không gây ảnh hưởng đến trải nghiệm người dùng thực tế).
3. **Cấu hình Trọng số Thích ứng (Adaptive Risk Scoring Weights)**:
   - Cho phép điều chỉnh trọng số giữa Luật Chữ ký (`w_rule`) và Học máy (`w_ml`).
   - Lựa chọn chế độ vận hành Machine Learning: `shadow` (đối chiếu ngầm) hoặc `active` (tham gia quyết định trực tiếp).

---

## 11. DỪNG HỆ THỐNG & KHẮC PHỤC SỰ CỐ (TROUBLESHOOTING)

### Lệnh dừng hệ thống khi kết thúc buổi Demo:
Mở terminal và chạy lệnh:
```powershell
.\scripts\stop\stop-all.bat
```
*(Script sẽ đóng các tiến trình Node.js, Python, Vite và giữ nguyên các container Docker an toàn)*.

### Xử lý sự cố thường gặp:

| Hiện tượng | Nguyên nhân | Cách khắc phục |
|---|---|---|
| **Lỗi: "Không thể kết nối đến máy chủ xác thực"** khi đăng nhập Dashboard | Backend Node.js (:3000) chưa bật hoặc bị đóng | Chạy lại `.\scripts\start\start-all.bat` và đợi 5 giây |
| **Lỗi: "502 Bad Gateway"** khi mở link `/site/dvwa/` | Docker Desktop chưa được bật hoặc container DVWA bị stop | Mở Docker Desktop $\rightarrow$ Start lại container DVWA (:4102) |
| **Gửi tấn công nhưng Dashboard không nhảy số** | Bạn đang gõ trực tiếp cổng nội bộ `:4102` thay vì qua Gateway `:8080` | Đảm bảo đường dẫn luôn bắt đầu bằng: `http://localhost:8080/site/dvwa/...` |
| **Đăng nhập DVWA qua :8080 bị văng ra trang login** | Trình duyệt cũ chặn cookie | Bấm F5 hoặc xóa cookie trang `localhost:8080`. Hệ thống đã tự động gỡ bỏ `domain=127.0.0.1` để tương thích |

---
**SECURITY GUARD © 2026 — Đồ án môn Bảo mật và An toàn hệ thống thông tin (BM&ATTT)**
