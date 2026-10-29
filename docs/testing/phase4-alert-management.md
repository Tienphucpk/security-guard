# SECURITY GUARD – Phase 4 Implementation Report
## Alert Management & Real-Time Monitoring

---

## 1. Architecture Overview (Kiến trúc hệ thống Phase 4)

Trong Phase 4, hệ thống **SECURITY GUARD** hoàn thiện vòng đời quản lý cảnh báo an ninh (Alert Management Lifecycle) và cơ chế giám sát thời gian thực (Real-time Monitoring) dựa trên Server-Sent Events (SSE):

```text
       HTTP Request
             │
             ▼
Express Web Application (:3000)
             │
             ├──► Logging Middleware ──► PostgreSQL (request_logs)
             ▼
     DetectionClient (HTTP POST /analyze, non-blocking)
             │
             ▼
Detection Engine FastAPI (:5000)
             │
             ├──► RuleEngine (6 detectors)
             ├──► RiskScorer (0 - 100 capped)
             ▼
      Detection Result
             │
             ▼
Web App Detection Handler
             │
             ├──► Persist: PostgreSQL (security_alerts) & alerts.log fallback
             │
             ▼
     AlertStreamService (SSE Stream)
             │
             ▼ (event: alert_created)
             │
Dashboard UI (:5173) ◄────────────────────────────────────────┐
   │                                                          │
   ├──► Real-Time Toast Notification Banner                   │
   ├──► Live SSE Connection Badge (with Polling Fallback)     │
   ├──► Alert Lifecycle Overview Cards                        │
   ├──► Management Table (Filter, Search, Sort, Pagination)   │
   └──► Security Analyst Action:                              │
             │                                                │
             ├──► PATCH /api/alerts/:id/acknowledge           │
             ├──► PATCH /api/alerts/:id/resolve               │
             └──► PATCH /api/alerts/:id/status                │
                         │                                    │
                         ▼                                    │
                   PostgreSQL (updated_at)                    │
                         │                                    │
                         └──► Broadcast: alert_updated ───────┘
```

---

## 2. Alert Lifecycle (Vòng đời cảnh báo an ninh)

Hệ thống định nghĩa trạng thái vòng đời chuẩn gồm 3 giai đoạn:

| Trạng thái | Mã định danh | Ý nghĩa | Hành động chuyển tiếp |
|---|---|---|---|
| **Mới phát hiện** | `NEW` | Cảnh báo vừa được rule engine phát hiện và tạo ra; đang chờ chuyên viên an ninh xem xét. | Chuyển sang `ACKNOWLEDGED` khi chuyên viên click **"Tiếp nhận"**. |
| **Đang tiếp nhận xử lý** | `ACKNOWLEDGED` | Chuyên viên đã tiếp nhận thông tin và đang tiến hành điều tra, phân tích hoặc cô lập. | Chuyển sang `RESOLVED` khi nguy cơ đã được xử lý xong; hoặc mở lại `NEW`. |
| **Đã giải quyết** | `RESOLVED` | Nguy cơ đã được khắc phục/ngăn chặn; cảnh báo được đóng và lưu vết lịch sử phục vụ kiểm toán. | Có thể bấm **"Mở lại"** (`NEW`) nếu phát hiện threat tái diễn. |

* **Lưu vết thời gian:**
  * `created_at`: Thời điểm cảnh báo được tạo ra.
  * `updated_at`: Thời điểm cập nhật trạng thái gần nhất (luôn được tự động cập nhật khi đổi trạng thái).

---

## 3. Server-Sent Events (SSE) Real-Time Stream

Hệ thống sử dụng **Server-Sent Events (`GET /api/alerts/stream`)** để đẩy dữ liệu thời gian thực từ Web App xuống Dashboard:

* **Header thiết lập:**
  * `Content-Type: text/event-stream`
  * `Cache-Control: no-cache, no-transform`
  * `Connection: keep-alive`
  * `X-Accel-Buffering: no`
* **Các sự kiện thời gian thực:**
  1. `connected`: Bắt tay kết nối thành công giữa Web App và client.
  2. `alert_created`: Phát ngay khi có request bất thường bị phát hiện (chứa đầy đủ thông tin alert).
  3. `alert_updated`: Phát ngay khi có thao tác thay đổi trạng thái alert (Acknowledge, Resolve, Reopen).
  4. `: heartbeat`: Bình luận duy trì kết nối (ping) gửi định kỳ mỗi 20 giây tránh bị timeout qua proxy/NAT.
* **Cơ chế phục hồi (Resilient Fallback Polling):**
  * Dashboard tự động theo dõi trạng thái `EventSource`. Nếu kết nối SSE bị ngắt hoặc trình duyệt không hỗ trợ, Dashboard tự động chuyển sang chế độ **Polling Fallback (3 giây/lần)** và hiển thị trạng thái `Polling (Fallback)` màu vàng cam. Khi kết nối lại được, hệ thống tự động quay về `Live SSE Stream` màu xanh lá.

---

## 4. REST APIs Phase 4

### 4.1. Real-time & Lifecycle APIs

* **`GET /api/alerts/stream`**
  * Thiết lập kết nối Server-Sent Events stream thời gian thực.
* **`PATCH /api/alerts/:id/acknowledge`**
  * Cập nhật trạng thái alert sang `acknowledged`.
  * Cập nhật cột `updated_at = CURRENT_TIMESTAMP`.
  * Broadcast sự kiện `alert_updated` qua SSE stream.
  * Trả về HTTP 200 kèm đối tượng alert đã cập nhật.
* **`PATCH /api/alerts/:id/resolve`**
  * Cập nhật trạng thái alert sang `resolved`.
  * Cập nhật cột `updated_at = CURRENT_TIMESTAMP`.
  * Broadcast sự kiện `alert_updated` qua SSE stream.
  * Trả về HTTP 200 kèm đối tượng alert đã cập nhật.
* **`PATCH /api/alerts/:id/status`**
  * Cập nhật trạng thái tự do (cho phép mở lại `new` hoặc chuyển đổi theo yêu cầu nghiệp vụ).
  * Kiểm tra hợp lệ: `status IN ('new', 'acknowledged', 'resolved')`.
  * Trả về HTTP 400 nếu status không hợp lệ, HTTP 404 nếu không tìm thấy alert.

### 4.2. Query & Details APIs (Được nâng cấp)

* **`GET /api/alerts`**
  * Hỗ trợ query params:
    * `page`: Trang cần lấy (mặc định 1).
    * `limit`: Số lượng mỗi trang (mặc định 50, trần tối đa 100).
    * `status`: Lọc theo trạng thái (`new`, `acknowledged`, `resolved`).
    * `severity`: Lọc theo mức độ nguy hiểm (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
    * `type`: Lọc theo loại tấn công (`SQL_INJECTION`, `XSS`, `SCANNER`, ...).
    * `ip`: Lọc theo client IP nguồn.
    * `sort`: Sắp xếp (`newest`, `oldest`, `risk_desc`, `risk_asc`).
  * Trả về: `{ status, source, page, limit, count, total, totalPages, alerts }`.
* **`GET /api/alerts/:id`**
  * Trả về chi tiết cảnh báo, bao gồm thông tin `requestLog` liên quan (liên kết khóa ngoại `request_log_id` sang bảng `request_logs`).
* **`GET /api/alerts/stats`**
  * Bổ sung các chỉ số vòng đời: `acknowledgedAlerts`, `resolvedAlerts`, `newAlerts`, `totalAlerts`.

---

## 5. Database Schema & Migration

### 5.1. File migration: `database/migrations/03_add_alert_updated_at.sql`

```sql
-- Phase 4: Alert Management Migration
ALTER TABLE security_alerts
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- Tạo index tối ưu hóa cho truy vấn lọc và sắp xếp
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_updated_at ON security_alerts(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON security_alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON security_alerts(alert_type);
```

Đã được thực thi và xác nhận trên cơ sở dữ liệu `security_guard` (PostgreSQL 18.6).

---

## 6. Giao diện Dashboard Phase 4

Giao diện Web Security Dashboard (`http://localhost:5173`) đã được nâng cấp toàn diện:

1. **Thanh chỉ báo Real-time:**
   * Hiển thị trạng thái `Live SSE Stream` (chấm xanh lá nhấp nháy) hoặc `Polling (Fallback)` (chấm vàng).
2. **Notification Toast Banner:**
   * Khi có cảnh báo mới phát sinh, banner thông báo nổi bật màu đỏ cam xuất hiện tức thì kèm nút **"Xem ngay"** để mở chi tiết cảnh báo. Tự động ẩn sau 6 giây.
3. **Thẻ thống kê vòng đời (Lifecycle Overview):**
   * Tổng Cảnh Báo.
   * Cần Xử Lý (NEW) – Màu xanh dương nhạt.
   * Đang Xử Lý (ACK) – Màu tím.
   * Đã Xử Lý (RESOLVED) – Màu xanh lá.
   * Mức Độ Cao / Khẩn (Critical & High) – Màu đỏ.
4. **Bảng điều khiển & Bộ lọc (Toolbar):**
   * Lọc theo Trạng thái (Tất cả / NEW / ACKNOWLEDGED / RESOLVED).
   * Lọc theo Mức độ (Tất cả / CRITICAL / HIGH / MEDIUM / LOW).
   * Sắp xếp (Mới nhất, Cũ nhất, Điểm rủi ro cao nhất, Điểm rủi ro thấp nhất).
   * Tìm kiếm theo Client IP.
   * Nút làm mới tức thì.
5. **Thao tác trực tiếp trên bảng cảnh báo:**
   * Nút **"Tiếp nhận"**: Chuyển trạng thái sang `acknowledged`.
   * Nút **"Giải quyết"**: Chuyển trạng thái sang `resolved`.
   * Nút **"Mở lại"**: Đưa cảnh báo đã xử lý quay về `new`.
   * Nút **"Chi tiết"**: Mở Modal xem thông tin chuyên sâu.
6. **Modal chi tiết cảnh báo (Alert Details Modal):**
   * Thông tin định danh, loại tấn công, severity, risk score.
   * Client IP, HTTP Method, Target URL.
   * Detection Reason & các rule vi phạm.
   * Thời gian phát hiện (`created_at`) & Thời gian cập nhật trạng thái (`updated_at`).
   * **Thông tin HTTP Request Log liên kết** (`statusCode`, `userAgent`, `responseTime`).
   * Các nút thao tác nghiệp vụ trực tiếp trong Modal.

---

## 7. Kết quả kiểm thử tự động (Automated Test Verification)

Toàn bộ test suite tự động được xác minh thông qua script `scripts\test\test-all.bat`:

### 7.1. Web Application & API Tests (24/24 PASS)
* **Test 1:** Web App starts and renders home page `✔ PASS`
* **Test 2:** GET /api/health reports service & database status `✔ PASS`
* **Test 3:** Request generates JSON file log in requests.log `✔ PASS`
* **Test 4:** Request log persistence to database `✔ PASS`
* **Test 5:** GET /api/logs returns valid structured JSON `✔ PASS`
* **Test 6:** Pagination works properly on GET /api/logs `✔ PASS`
* **Test 7:** Filter by IP on GET /api/logs `✔ PASS`
* **Test 8:** Filter by HTTP method on GET /api/logs `✔ PASS`
* **Test 9:** Filter by status code on GET /api/logs `✔ PASS`
* **Test 10:** GET /api/logs/stats returns computed statistics `✔ PASS`
* **Test 11:** Database offline does not crash Web App (Resilience) `✔ PASS`
* **Test 12:** IP normalization (IPv4, IPv6, proxies) `✔ PASS`
* **Test 13:** GET /api/alerts returns structured JSON data `✔ PASS`
* **Test 14:** GET /api/alerts enforces maximum limit <= 100 `✔ PASS`
* **Test 15:** GET /api/alerts/stats returns security alert statistics `✔ PASS`
* **Test 16:** GET /api/alerts/:id returns 404 for non-existent ID `✔ PASS`
* **Test 17:** Alert insertion handles DB gracefully without throwing `✔ PASS`
* **Test 18:** DetectionClient forwardLog is resilient and non-blocking `✔ PASS`
* **Test 19:** GET /api/alerts/stream returns SSE stream headers & connected event `✔ PASS`
* **Test 20:** GET /api/alerts/stats includes acknowledged & resolved counts `✔ PASS`
* **Test 21:** GET /api/alerts supports sorting and totalPages `✔ PASS`
* **Test 22:** Alert lifecycle: acknowledge and resolve transitions `✔ PASS`
* **Test 23:** PATCH /api/alerts/:id/status validates status parameter `✔ PASS`
* **Test 24:** PATCH /api/alerts/:id/acknowledge returns 404 for invalid alert `✔ PASS`

### 7.2. Detection Engine Unittest (20/20 PASS)
* Tất cả 20 test case kiểm thử 6 detectors (Brute Force, Scanner, Abnormal Traffic, Suspicious URL, SQL Injection, XSS) và Risk Scorer đều `PASS`.

**Tổng cộng:** **44 / 44 tests PASS (100%)**.
