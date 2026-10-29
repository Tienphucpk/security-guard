# SECURITY GUARD – Phase 3 Implementation Report
## Rule-Based Anomaly Detection + Risk Score + Security Alerts

---

## 1. Architecture Overview (Kiến trúc hệ thống)

Trong Phase 3, hệ thống SECURITY GUARD đã mở rộng từ luồng thu thập log đơn thuần thành hệ thống giám sát và phát hiện hành vi khả nghi theo thời gian thực (Real-time Rule-Based Detection Pipeline):

```text
HTTP Request
      │
      ▼
Express Web Application (:3000)
      │
      ├──► Request Logging Middleware
      │         │
      │         ├──► requests.log & PostgreSQL (request_logs)
      │         ▼
      └──► DetectionClient (Non-blocking, Timeout 1500ms)
                │
                ▼
      Detection Engine FastAPI (:5000)
                │
                ├──► RuleEngine
                │         ├── 1. Brute Force Detector
                │         ├── 2. Scanner Signature Detector
                │         ├── 3. Abnormal Traffic Rate Detector
                │         ├── 4. Suspicious URL Probe Detector
                │         ├── 5. SQL Injection Pattern Detector
                │         └── 6. XSS Pattern Detector
                │
                ├──► Risk Scorer (Thang điểm 0 - 100, Capped, Phân cấp mức độ)
                ▼
        Detection Result
                │
                ├──► security_alerts (PostgreSQL & alerts.log fallback)
                ▼
      Dashboard (:5173) & JSON APIs (/api/alerts, /api/alerts/stats)
```

---

## 2. Detection Rules Specification (Đặc tả các luật phát hiện)

| STT | Tên Rule | Category | Mã Rule | Severity | Điểm | Đặc trưng nhận diện & Ngưỡng |
|---|---|---|---|---|---|---|
| 1 | **Brute Force Detection** | `brute_force` | `RULE-BF-001` | HIGH | 70 | $\ge 5$ lần đăng nhập thất bại (HTTP 401 trên `/login`) từ cùng 1 IP trong cửa sổ trượt 300 giây (5 phút). |
| 2 | **Security Scanner Detection** | `scanner` | `RULE-SCAN-001` | HIGH | 60 | Khớp chữ ký User-Agent của các công cụ scan tự động: `sqlmap`, `nikto`, `nmap`, `dirbuster`, `gobuster`, `wpscan`, `masscan`. |
| 3 | **Abnormal Traffic Rate** | `abnormal_traffic` | `RULE-TRAFFIC-001` | MEDIUM | 40 | Tần suất request $> 100$ requests trong 60 giây từ một IP (loại trừ các request polling nội bộ). |
| 4 | **Suspicious URL Probing** | `suspicious_url` | `RULE-URL-001` | MEDIUM | 35 | Dò quét file nhạy cảm: `/.env`, `/.git/head`, `/.git/config`, `/wp-login.php`, `/web.config`, `/config.php`, `/phpinfo.php`, `/.ds_store`, `/server-status`. |
| 5 | **SQL Injection (SQLi)** | `sql_injection` | `RULE-SQLI-001` | HIGH | 80 | Ký tự và cú pháp khai thác SQLi: `' OR '1'='1`, `' OR 1=1`, `UNION SELECT`, `UNION ALL SELECT`, `INFORMATION_SCHEMA.`, `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY`. |
| 6 | **Cross-Site Scripting (XSS)** | `xss` | `RULE-XSS-001` | HIGH | 75 | Thẻ script và trigger thực thi JS: `<script>`, `</script>`, `onload=`, `onerror=`, `javascript:`, `<iframe>`, `<svg>`, `document.cookie`. |

---

## 3. Risk Scoring & Severity Scale (Thang điểm rủi ro)

* **Thang điểm:** $0 \rightarrow 100$.
* **Quy tắc cộng dồn:** Khi một request vi phạm nhiều rule đồng thời, điểm các rule được cộng dồn nhưng giới hạn trần tối đa là 100 điểm:
  $$\text{Final Score} = \min(100.0, \sum \text{Score}_i)$$
* **Phân cấp Severity:**
  * **CRITICAL:** $80 \le \text{Score} \le 100$
  * **HIGH:** $60 \le \text{Score} < 80$
  * **MEDIUM:** $30 \le \text{Score} < 60$
  * **LOW:** $0 \le \text{Score} < 30$

---

## 4. REST APIs

### 4.1. Detection Engine (`http://localhost:5000`)
* `GET /health`: Kiểm tra trạng thái hoạt động của Detection Engine.
* `GET /rules`: Danh sách 6 luật phát hiện và trạng thái bật/tắt (`enabled`).
* `POST /analyze`: Phân tích 1 bản ghi log, trả về `detected`, `risk_score`, `severity`, danh sách `detections`.
* `POST /analyze/batch`: Phân tích tập hợp nhiều log trong một batch request.

### 4.2. Web Application (`http://localhost:3000`)
* `GET /api/alerts`: Danh sách cảnh báo an ninh hỗ trợ phân trang (`page`, `limit <= 100`) và lọc (`type`, `severity`, `status`, `ip`, `from`, `to`).
* `GET /api/alerts/:id`: Chi tiết 1 cảnh báo an ninh theo ID.
* `GET /api/alerts/stats`: Thống kê tổng hợp cảnh báo (`totalAlerts`, `newAlerts`, `criticalSeverity`, `highSeverity`, `mediumSeverity`, `lowSeverity`, `topAlertTypes`, `topAlertIps`).

---

## 5. Database Schema & Storage Resilience

* Bảng **`security_alerts`**:
  * `id`: BIGSERIAL PRIMARY KEY
  * `rule_id`: REFERENCES `detection_rules(id)`
  * `request_log_id`: REFERENCES `request_logs(id)`
  * `alert_type`: VARCHAR(100)
  * `severity`: VARCHAR(20)
  * `risk_score`: NUMERIC(5, 2)
  * `source_ip`: VARCHAR(45)
  * `method`: VARCHAR(10)
  * `target_url`: TEXT
  * `description`: TEXT
  * `details`: JSONB
  * `status`: VARCHAR(50) (mặc định `'new'`)
  * `created_at`: TIMESTAMP WITH TIME ZONE
* **Cơ chế Chịu lỗi (Graceful Degradation):**
  * Khi PostgreSQL không khả dụng, hệ thống tự động ghi nhận cảnh báo vào `web-app/logs/alerts.log`.
  * Các API `/api/alerts` và `/api/alerts/stats` tự động đọc và tính toán từ file log mà không làm gián đoạn hệ thống.

---

## 6. Kết quả Kiểm thử (Test Results)

1. **Detection Engine Tests (`unittest`):**
   * 20/20 test cases **PASS**:
     * `test_brute_force_below_threshold`: 4 failed attempts $\rightarrow$ Not detected.
     * `test_brute_force_meets_threshold`: 5 failed attempts $\rightarrow$ Detected `BRUTE_FORCE` (Severity HIGH, Score 70).
     * `test_scanner_detection_sqlmap`: User-Agent sqlmap $\rightarrow$ Detected `SCANNER_DETECTION`.
     * `test_scanner_detection_nikto_and_nmap`: Khớp chữ ký scanners.
     * `test_abnormal_traffic_detection`: Tần suất vượt ngưỡng $\rightarrow$ Detected `ABNORMAL_TRAFFIC`.
     * `test_suspicious_url_patterns`: Khớp `/.env`, `/.git/head`, `/wp-login.php`.
     * `test_sql_injection_patterns`: Khớp `' OR '1'='1`, `UNION SELECT`, `INFORMATION_SCHEMA`.
     * `test_xss_patterns`: Khớp `<script>`, `onerror=`, `javascript:`.
     * `test_multi_rule_evaluation_and_capped_score`: Cộng dồn điểm và giới hạn trần 100 điểm.
     * `test_rule_disable_toggle`: Tắt/bật luật linh hoạt.
2. **Web Application Tests (`node --test`):**
   * 18/18 test cases **PASS**:
     * Kiểm tra khởi tạo server, health check, log file, phân trang, lọc theo IP/Method/StatusCode, tính toán stats.
     * Kiểm tra API `/api/alerts` phân trang, giới hạn $\le 100$.
     * Kiểm tra API `/api/alerts/stats`.
     * Kiểm tra xử lý chịu lỗi khi database offline và engine offline.
3. **Tổng cộng kiểm thử tự động:** **38/38 PASS**.

---

## 7. Known Limitations (Hạn chế đã biết ở Phase 3)

1. **Chưa áp dụng Machine Learning / Isolation Forest:** Toàn bộ giải thuật hiện tại là Rule-Based (dựa trên mẫu chuỗi và ngưỡng thống kê).
2. **Khả năng False Positive:** Các từ khóa kỹ thuật thông thường có thể trùng khớp với chữ ký tấn công nếu người dùng tìm kiếm tài liệu bảo mật.
3. **Ngưỡng cấu hình tĩnh:** Các ngưỡng (threshold 5 lần thử login, 100 requests/phút) là tham số cấu hình cố định trong JSON/DB, chưa có khả năng tự thích ứng (adaptive learning) theo thói quen người dùng.
4. **Chưa có cơ chế chủ động chặn (Blocking/WAF):** Hệ thống chỉ tập trung vào giám sát (Passive Detection & Alerting), chưa cấu hình chặn tường lửa (Firewall) hoặc cấm IP (IP banning).

---

## 8. Môi trường Thử nghiệm An toàn (Controlled Lab Testing)

Toàn bộ các quy tắc và kịch bản thử nghiệm chỉ được chạy trên môi trường cục bộ:
* `127.0.0.1` / `localhost`
* Web App Target: `http://localhost:3000`
* Detection Service: `http://localhost:5000`
* Dashboard: `http://localhost:5173`
Tuyệt đối không sử dụng công cụ kiểm thử trên các hệ thống bên ngoài.
