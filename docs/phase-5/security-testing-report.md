# SECURITY GUARD – Phase 5 Implementation Report
## Security Testing, Anomaly Rule Verification & End-to-End Validation

> **Đồ án môn học:** Bảo mật và An toàn thông tin  
> **Giai đoạn:** Phase 5 — Security Testing & End-to-End Validation  
> **Thời gian thực hiện:** Tháng 10/2026  
> **Môi trường thử nghiệm:** Local Lab Windows 11 Native, Node.js v24.15.0, Python 3.12, PostgreSQL 18.6  

---

## 1. Mục tiêu và Phạm vi Kiểm thử (Scope)

Phase 5 tập trung vào kiểm thử bảo mật toàn diện (Security Testing) và xác thực luồng dữ liệu đầu-cuối (End-to-End Validation) trên hệ thống **SECURITY GUARD** sau khi hoàn thành 4 giai đoạn phát triển nền tảng:

1. **Phase 5.1 — Baseline Verification:** Kiểm tra tính sẵn sàng của 4 dịch vụ (Web App :3000, Detection Engine :5000, Dashboard :5173, PostgreSQL :5432) và thiết lập chỉ số baseline.
2. **Phase 5.2 — Detection Rule Testing:** Đối chiếu và kiểm thử 6 nhóm luật phát hiện bất thường với các ca kiểm thử Dương tính (Positive), Âm tính (Negative) và Biên (Boundary).
3. **Phase 5.3 — End-to-End Integration:** Xác thực chu trình khép kín:
   $$\text{HTTP Request} \longrightarrow \text{Web App Middleware} \longrightarrow \text{Detection Engine} \longrightarrow \text{PostgreSQL} \longrightarrow \text{Alert API} \longrightarrow \text{Dashboard}$$
   và vòng đời cảnh báo: `NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED` $\rightarrow$ `REOPEN`.
4. **Phase 5.4 — Server-Sent Events (SSE) Validation:** Kiểm thử kết nối stream thời gian thực, sự kiện `alert_created`, `alert_updated`, cơ chế dọn dẹp kết nối (disconnect cleanup) và chế độ dự phòng polling.
5. **Phase 5.5 — Đánh giá & Đo lường:** Tính toán ma trận lỗi (TP, FP, TN, FN), Precision, Recall, F1-Score và độ trễ phát hiện (Detection Latency).
6. **Phase 5.6 — Regression & Tài liệu bàn giao.**

---

## 2. Kết quả Phase 5.1 — Baseline Status

Trước khi thực hiện các bài test bảo mật, toàn bộ hệ thống được ghi nhận trạng thái ban đầu:

| Thành phần | Địa chỉ / Port | Trạng thái | Ghi chú |
|---|---|---|---|
| **Web Application** | `http://localhost:3000` | `ONLINE` | `database: connected`, Uptime: 28s |
| **Detection Engine** | `http://localhost:5000/health` | `ONLINE` | FastAPI `version: 1.0.0` |
| **Security Dashboard** | `http://localhost:5173` | `ONLINE` | React + Vite UI |
| **PostgreSQL Database** | `localhost:5432` | `ONLINE` | Database: `security_guard` |
| **Request Logs ban đầu** | Bảng `request_logs` | `4,463 records` | Ghi nhận lưu lượng trước test |
| **Security Alerts ban đầu**| Bảng `security_alerts` | `26 alerts` | Cảnh báo lưu vết từ Phase 3-4 |

---

## 3. Kết quả Phase 5.2 — Detection Rule Testing (6 Nhóm Luật)

Tất cả 6 nhóm luật được kiểm thử chuyên sâu trong file [`detection-engine/tests/test_phase5_rules.py`](file:///D:/BM&ATTT/security-guard/detection-engine/tests/test_phase5_rules.py).

### 3.1. Nhóm 1: Brute Force Detection (`RULE-BF-001`)
* **Đặc tả luật:** $\ge 5$ lần đăng nhập thất bại (`POST /login` trả về `401 Unauthorized`) từ cùng 1 IP trong cửa sổ 300 giây. Severity: `HIGH` (Điểm: 70.0).
* **Positive Test:** Gửi 5 request liên tiếp từ `192.168.100.1` $\rightarrow$ Kích hoạt `BRUTE_FORCE` chính xác ở lần thứ 5.
* **Boundary Test:**
  * Lần thứ 4 (Ngưỡng $- 1$): Trả về `None` (chưa vượt ngưỡng, không báo động giả).
  * Lần thứ 5 (Đúng ngưỡng): Báo động kích hoạt ngay lập tức.
* **Negative Test:**
  * 10 lần đăng nhập thành công (`HTTP 200`) $\rightarrow$ Không kích hoạt.
  * 6 lần request `GET /login` trả về 401 $\rightarrow$ Không kích hoạt (chỉ bắt phương thức `POST`).

### 3.2. Nhóm 2: Security Scanner Detection (`RULE-SCAN-001`)
* **Đặc tả luật:** Chữ ký User-Agent của các công cụ rà quét tự động (`sqlmap`, `nikto`, `nmap`, `dirbuster`, `gobuster`, `wpscan`, `masscan`). Severity: `HIGH` (Điểm: 60.0).
* **Positive Test:** Kiểm thử toàn bộ 7 chữ ký công cụ scan phổ biến $\rightarrow$ Tất cả 7/7 đều bị nhận diện chính xác.
* **Boundary Test:** Thử nghiệm không phân biệt hoa thường (`SQLMAP/1.6`, `GoBuster/3.1`) $\rightarrow$ Khớp mẫu thành công.
* **Negative Test:** 5 User-Agent trình duyệt chuẩn (Chrome Windows, Firefox macOS, Safari iOS, cURL, Postman) $\rightarrow$ Không bị cảnh báo sai.

### 3.3. Nhóm 3: Abnormal Traffic Rate (`RULE-TRAFFIC-001`)
* **Đặc tả luật:** Tần suất truy cập $> 100$ requests trong 60 giây từ 1 IP. Severity: `MEDIUM` (Điểm: 40.0).
* **Positive Test:** 101 requests trong cửa sổ trượt $\rightarrow$ Báo động `ABNORMAL_TRAFFIC`.
* **Boundary Test:**
  * Đúng 100 requests (chưa vượt ngưỡng $> 100$) $\rightarrow$ Không báo động.
  * Request thứ 101 $\rightarrow$ Kích hoạt cảnh báo.
* **Negative Test:** 150 requests vào các endpoint nội bộ (`/api/health`, `/api/logs`) $\rightarrow$ Không kích hoạt (loại trừ telemetry để tránh nhiễu hệ thống).

### 3.4. Nhóm 4: Suspicious URL Probing (`RULE-URL-001`)
* **Đặc tả luật:** Dò quét 9 tệp nhạy cảm (`/.env`, `/.git/head`, `/.git/config`, `/wp-login.php`, `/web.config`, `/config.php`, `/phpinfo.php`, `/.ds_store`, `/server-status`). Severity: `MEDIUM` (Điểm: 35.0).
* **Positive Test:** Cả 9/9 đường dẫn dò quét nhạy cảm đều kích hoạt cảnh báo `SUSPICIOUS_URL`.
* **Boundary Test:** Đường dẫn kèm tham số phức tạp `/.env?backup=true&format=raw` $\rightarrow$ Nhận diện chính xác `/.env`.
* **Negative Test:** Các URL hợp lệ (`/`, `/search?q=environment`, `/about-us`, `/docs/readme.txt`) $\rightarrow$ Không bị chặn nhầm.

### 3.5. Nhóm 5: SQL Injection (`RULE-SQLI-001`)
* **Đặc tả luật:** Ký tự và cú pháp khai thác SQLi (`' OR 1=1`, `UNION SELECT`, `INFORMATION_SCHEMA.`, `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY`). Severity: `CRITICAL` / `HIGH` (Điểm: 80.0).
* **Positive Test:** 6 mẫu payload kinh điển và biến thể đều được phát hiện chính xác.
* **Boundary Test:** Payload SQLi nằm trong body JSON của request `POST` $\rightarrow$ Trích xuất và phát hiện thành công.
* **Negative Test:** Truy vấn chứa từ ngữ thông thường trong tự nhiên ("european union report", "sleep therapy", "apples or oranges") $\rightarrow$ Không kích hoạt báo động giả.

### 3.6. Nhóm 6: Cross-Site Scripting (`RULE-XSS-001`)
* **Đặc tả luật:** Thẻ script và handler kích hoạt JS (`<script>`, `</script>`, `onload=`, `onerror=`, `javascript:`, `<iframe`, `<svg`, `document.cookie`). Severity: `HIGH` (Điểm: 75.0).
* **Positive Test:** 5 mẫu payload XSS (Stored & Reflected) $\rightarrow$ Đều bị phát hiện.
* **Boundary Test:** Kỹ thuật làm rối mã thẻ: chữ hoa thường xáo trộn `<ScRiPt src=evil.js>`, thẻ không đóng, khoảng trắng `<BODY ONLOAD=alert(1)>`, `<svg/onload=confirm(1)>` $\rightarrow$ Đều bị Regex bắt được.
* **Negative Test:** Từ khóa "script" hoặc ký tự toán học `<` ("learn javascript", "x < y and y > z") $\rightarrow$ Không bị cảnh báo giả.

---

## 4. Kết quả Phase 5.3 — End-to-End Integration & Alert Lifecycle

Được kiểm thử tự động trong [`web-app/tests/phase5_e2e.test.js`](file:///D:/BM&ATTT/security-guard/web-app/tests/phase5_e2e.test.js):

1. **Chu trình lưu vết & liên kết bảng (Foreign Key Consistency):**
   * Gửi request tấn công có mã nhận diện `phase5_marker_sqli_*` tới Web App.
   * Middleware ghi nhận log vào bảng `request_logs`.
   * DetectionClient đẩy bất đồng bộ tới Detection Engine và nhận phản hồi `detected: true`.
   * Cảnh báo được ghi vào bảng `security_alerts` với khóa ngoại `request_log_id` trỏ chính xác về bản ghi request log tương ứng.
   * Khi gọi API `GET /api/alerts/:id`, hệ thống tự động JOIN và trả về đầy đủ đối tượng `alert.requestLog` (`statusCode`, `url`, `userAgent`, `responseTime`).
2. **Vòng đời cảnh báo (Alert Lifecycle):**
   * Trạng thái khởi tạo: `new`.
   * Gọi `PATCH /api/alerts/:id/acknowledge` $\rightarrow$ Chuyển thành công sang `acknowledged`, cập nhật `updated_at`.
   * Gọi `PATCH /api/alerts/:id/resolve` $\rightarrow$ Chuyển thành công sang `resolved`, cập nhật `updated_at`.
   * Gọi `PATCH /api/alerts/:id/status` với body `{"status": "new"}` (Mở lại) $\rightarrow$ Quay trở lại `new`.
   * Toàn bộ trạng thái được kiểm chứng trực tiếp từ cơ sở dữ liệu PostgreSQL.
3. **Dọn dẹp dữ liệu kiểm thử (Safe Cleanup):**
   * Chỉ dọn dẹp các bản ghi mang tiền tố `phase5_marker_*`, tuyệt đối không làm ảnh hưởng đến dữ liệu thực của người dùng.

---

## 5. Kết quả Phase 5.4 — Server-Sent Events (SSE) Real-Time Stream

1. **Kết nối & Bắt tay (Handshake):**
   * `GET /api/alerts/stream` trả về header `Content-Type: text/event-stream` và `Cache-Control: no-cache`.
   * Client nhận ngay sự kiện `event: connected` kèm payload `{ status: "connected", timestamp: "..." }`.
2. **Sự kiện Thời gian thực khi có đợt tấn công (`event: alert_created`):**
   * Trong lúc client duy trì stream, một request tấn công được kích hoạt.
   * Server gửi ngay gói tin `event: alert_created` chứa toàn bộ thông tin cảnh báo (`id`, `alertType: "SQL_INJECTION"`, `riskScore: 80.0`, `sourceIp: "127.0.0.1"`).
3. **Sự kiện Thời gian thực khi cập nhật trạng thái (`event: alert_updated`):**
   * Khi chuyên viên bấm tiếp nhận (`acknowledge`), server broadcast ngay `event: alert_updated` với `status: "acknowledged"`.
4. **Quản lý kết nối & Dọn dẹp (Heartbeat & Disconnect Cleanup):**
   * Hệ thống duy trì ping định kỳ `: heartbeat\n\n` mỗi 20s.
   * Khi client ngắt kết nối (`socket.destroy()`), server lắng nghe sự kiện `close` và giải phóng đối tượng client khỏi `Set`, số lượng `activeClients` giảm về ban đầu mà không rò rỉ bộ nhớ.
5. **Cơ chế Polling Dự phòng (Polling Fallback):**
   * Nếu SSE gián đoạn, dashboard tự động chuyển sang polling các endpoint `/api/alerts` và `/api/alerts/stats` mỗi 3s một cách ổn định.

---

## 6. Kết quả Phase 5.5 — Ma trận Đánh giá & Độ trễ (Metrics & Latency)

Số liệu thực nghiệm thu được từ công cụ benchmark [`detection-engine/evaluate_metrics.py`](file:///D:/BM&ATTT/security-guard/detection-engine/evaluate_metrics.py):

| Nhóm phát hiện | Positive Tests | Negative Tests | True Positive (TP) | False Positive (FP) | True Negative (TN) | False Negative (FN) | Precision | Recall | F1-Score | Độ trễ TB (Latency) |
|---|---|---|---|---|---|---|---|---|---|---|
| **Brute Force (`RULE-BF-001`)** | 5 | 7 | 5 | 0 | 7 | 0 | **100.0%** | **100.0%** | **1.00** | **0.011 ms** |
| **Scanner Detection (`RULE-SCAN-001`)** | 7 | 5 | 7 | 0 | 5 | 0 | **100.0%** | **100.0%** | **1.00** | **0.002 ms** |
| **Abnormal Traffic (`RULE-TRAFFIC-001`)** | 3 | 5 | 3 | 0 | 5 | 0 | **100.0%** | **100.0%** | **1.00** | **0.195 ms** |
| **Suspicious URL (`RULE-URL-001`)** | 10 | 7 | 10 | 0 | 7 | 0 | **100.0%** | **100.0%** | **1.00** | **0.002 ms** |
| **SQL Injection (`RULE-SQLI-001`)** | 8 | 6 | 8 | 0 | 6 | 0 | **100.0%** | **100.0%** | **1.00** | **0.018 ms** |
| **Cross-Site Scripting (`RULE-XSS-001`)** | 8 | 6 | 8 | 0 | 6 | 0 | **100.0%** | **100.0%** | **1.00** | **0.003 ms** |
| **TỔNG HỢP TOÀN HỆ THỐNG** | **41** | **36** | **41** | **0** | **36** | **0** | **100.0%** | **100.0%** | **1.00** | **0.038 ms** |

### Nhận xét đánh giá:
- **Độ chính xác (Precision & Recall):** Đạt 100% trên bộ mẫu kiểm thử thiết kế theo đặc tả quy tắc. Không ghi nhận trường hợp báo động giả (FP = 0) đối với các truy vấn ngữ cảnh bình thường có chứa từ khóa nhạy cảm.
- **Thời gian xử lý (Detection Latency):** Cực kỳ nhanh, độ trễ trung bình của các luật dựa trên chuỗi và regex chỉ dao động từ **0.002 ms đến 0.018 ms**. Luật Abnormal Traffic có độ trễ 0.195 ms do phải duyệt mảng sliding window lịch sử request, hoàn toàn đáp ứng thời gian thực (dưới 1 ms).

---

## 7. Lỗi phát hiện trong quá trình kiểm thử và cách khắc phục

Trong quá trình thực hiện Phase 5, một lỗi logic tiềm ẩn đã được phát hiện và xử lý triệt để:

### Lỗi phát hiện:
* **Vị trí:** [`web-app/src/services/detectionClient.js`](file:///D:/BM&ATTT/security-guard/web-app/src/services/detectionClient.js), dòng 120–123.
* **Hiện tượng:** Khi gọi `db.insertSecurityAlert(alertData)`, hàm trả về `{ success: true, id: <ID> }`. Đoạn code cũ gán `savedAlert = inserted`, khiến biến `savedAlert` bị ghi đè thành `{ success: true, id: <ID> }`, làm mất toàn bộ các trường dữ liệu quan trọng (`alertType`, `targetUrl`, `sourceIp`, `riskScore`, `severity`). Khi phát sự kiện `alert_created` qua SSE xuống Dashboard, giao diện không nhận được đầy đủ dữ liệu cảnh báo.
* **Khắc phục:** Sửa thành:
  ```javascript
  const inserted = await db.insertSecurityAlert(alertData);
  if (inserted && inserted.id) {
    savedAlert.id = inserted.id; // Chỉ gán thêm ID được sinh ra, giữ nguyên toàn bộ payload
  }
  ```
  Sau khi sửa, sự kiện `alert_created` gửi đầy đủ 100% dữ liệu chi tiết của cảnh báo tới Dashboard.

---

## 8. Kết quả Regression Test toàn diện

Chạy lại toàn bộ test suite bằng lệnh:
```cmd
scripts\test\test-all.bat
```

* **Web Application Tests:** **30 / 30 tests PASS (100%)**
  * 24 tests nền tảng (Phase 1–4)
  * 6 tests E2E & SSE (Phase 5)
* **Detection Engine Tests:** **41 / 41 tests PASS (100%)**
  * 20 tests API & Detector cơ bản
  * 21 tests Positive, Negative, Boundary (Phase 5)
* **Tổng số bài test tự động:** **71 / 71 tests PASS (100%)**, thời gian thực thi: **2.7 giây**.

---

## 9. Hạn chế còn tồn tại & Hướng phát triển

1. **Sliding Window trên bộ nhớ RAM:** Lịch sử sliding window của Brute Force và Abnormal Traffic hiện lưu trong RAM của Python Detection Engine. Nếu dịch vụ restart, lịch sử trong window trượt hiện tại sẽ reset. (*Khuyến nghị: Chuyển sang Redis Cache ở phiên bản production*).
2. **Quy tắc tĩnh (Static Pattern Matching):** Mặc dù regex và chữ ký phát hiện rất tốt các cuộc tấn công chuẩn, các kỹ thuật làm rối mã nâng cao (advanced polymorphism / zero-day) có thể vượt qua rule tĩnh. Đây chính là tiền đề để mở rộng sang **Phase 6: Machine Learning Anomaly Detection (Isolation Forest)**.

---

## 10. Hướng dẫn tái hiện kiểm thử (Reproduction Guide)

1. **Chạy toàn bộ 71 bài test tự động:**
   ```cmd
   scripts\test\test-all.bat
   ```
2. **Chạy riêng bài test đo lường chỉ số Precision, Recall và Latency:**
   ```cmd
   cd detection-engine
   .\venv\Scripts\python.exe evaluate_metrics.py
   ```
3. **Chạy thử nghiệm mô phỏng tấn công thời gian thực lên Dashboard:**
   ```cmd
   node scripts\test\run_demo.js
   ```
