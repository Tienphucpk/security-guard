# SECURITY GUARD
> **Nghiên cứu và xây dựng hệ thống phát hiện hành vi bất thường trên Website**  
> Đồ án môn học: **Bảo mật và An toàn thông tin**  
> **Trạng thái:** Hoàn thành Phase 9 – Authentication, Authorization & User Management (156/156 Tests PASS)

---

## 1. Project Description (Mô tả Đồ án)
**SECURITY GUARD** là hệ thống giám sát và phát hiện sớm các hành vi truy cập bất thường, dấu hiệu quét lỗ hổng và tấn công mạng vào ứng dụng Web thông qua phân tích dữ liệu HTTP Request Logs.

Hệ thống được thiết kế theo kiến trúc Microservices hiện đại, tách biệt giữa ứng dụng mục tiêu (Web Application), tầng lưu vết (Logging System), cơ sở dữ liệu lưu trữ (PostgreSQL), động cơ phân tích (Detection Engine kết hợp Rule-Based và Machine Learning Isolation Forest), hệ thống cảnh báo & quản lý vòng đời (Alert Management) và bảng điều khiển trực quan thời gian thực (Real-time Dashboard).

### Các tính năng đã hoàn thiện:
- **Phase 1: Project Skeleton & Basic Web App:** Khởi tạo kiến trúc microservices và môi trường chạy đa nền tảng.
- **Phase 2: Logging Pipeline & PostgreSQL Integration:** Middleware bắt vết HTTP request logs, chuẩn hóa IP, lưu trữ kép (PostgreSQL `request_logs` & file dự phòng `requests.log`), cung cấp REST API truy vấn và thống kê lưu lượng.
- **Phase 3: Rule-Based Anomaly Detection + Risk Score + Security Alerts:**
  - 6 bộ quy tắc phát hiện: *Brute Force*, *Security Scanner*, *Abnormal Traffic Rate*, *Suspicious URL Probing*, *SQL Injection Pattern*, *Cross-Site Scripting (XSS)*.
  - Hệ thống chấm điểm rủi ro *Risk Scoring (0–100)* có giới hạn trần và phân cấp mức độ (*CRITICAL*, *HIGH*, *MEDIUM*, *LOW*).
  - Tự động sinh cảnh báo an ninh lưu vào bảng `security_alerts` và file dự phòng `alerts.log`.
- **Phase 4: Alert Management & Real-Time Monitoring:**
  - **Giám sát thời gian thực (Real-Time Monitoring):** Kết nối **Server-Sent Events (SSE)** tại `/api/alerts/stream` đẩy ngay tức thì các cảnh báo mới (`alert_created`) và cập nhật trạng thái (`alert_updated`) xuống Dashboard mà không cần reload trang. Có cơ chế tự động chuyển đổi sang *Polling Fallback* (3s) nếu SSE gián đoạn.
  - **Quản lý vòng đời cảnh báo (Alert Lifecycle Management):** Quy trình xử lý 3 giai đoạn: `NEW` ➔ `ACKNOWLEDGED` ➔ `RESOLVED` (kèm tính năng mở lại cảnh báo).
  - **Lưu vết thời gian cập nhật:** Cột `updated_at` trong bảng `security_alerts` tự động ghi nhận mỗi khi chuyên viên an ninh thay đổi trạng thái.
  - **Bảng điều khiển trực quan (Interactive Dashboard):** Thẻ thống kê vòng đời, thanh thông báo Toast khi có đợt tấn công mới, bộ lọc đa tiêu chí (Trạng thái, Mức độ, IP, Sắp xếp), phân trang và Modal xem chi tiết cảnh báo kèm thông tin HTTP log liên quan.
- **Phase 5: Security Testing & End-to-End Validation:**
  - **Kiểm thử 6 nhóm luật phát hiện bất thường:** Xây dựng ma trận test cases Positive, Negative, Boundary cho cả 6 luật bảo mật (Brute Force, Scanner, Abnormal Traffic, Suspicious URL, SQLi, XSS).
  - **Xác thực luồng tích hợp End-to-End:** Kiểm thử chu trình khép kín từ HTTP request, middleware log, detection engine, cơ sở dữ liệu PostgreSQL đến API cảnh báo và SSE stream.
  - **Kiểm thử chuyên sâu Server-Sent Events (SSE):** Xác thực sự kiện kết nối, broadcast `alert_created`, `alert_updated`, cơ chế dọn dẹp kết nối khi client disconnect và cơ chế dự phòng polling.
  - **Đo lường & Đánh giá hiệu năng:** Đạt Precision 100%, Recall 100% trên bộ test mẫu chuẩn, độ trễ phát hiện trung bình 0.038 ms/request. Báo cáo chi tiết tại `docs/phase-5/security-testing-report.md`.
- **Phase 6: Machine Learning-Based Anomaly Detection:**
  - **Feature Engineering:** Trích xuất vector 11 đặc trưng số học thuần túy từ metadata của HTTP request (phương thức, status code, độ trễ, độ dài URL, query, số ký tự đặc biệt, token nghi vấn, user-agent, độ sâu đường dẫn, tần suất truy cập trượt 60s, số lần đăng nhập thất bại trượt 300s). Loại trừ hoàn toàn IP thô, cookie, secrets và telemetry nội bộ.
  - **Mô hình Isolation Forest:** Triển khai module học máy không giám sát `IsolationForest(n_estimators=100, contamination=0.03, random_state=42)` với cơ chế lưu trữ mô hình (`models/isolation_forest_v1.joblib`), metadata (`model_metadata.json`), và thang điểm chuẩn hóa rủi ro 0–100.
  - **3 chế độ vận hành:** `disabled`, `shadow` (mặc định - giám sát đánh giá ngầm mà không gây nhiễu cảnh báo), `active` (tự động phát cảnh báo `ML_ANOMALY` khi phát hiện ngoại lai).
  - **Tương quan và chống trùng lặp cảnh báo (Alert Correlation & Deduplication):** Ưu tiên các luật đặc hiệu khi cùng bắt được một tấn công, tích hợp metadata ML vào `details`, khử lặp cảnh báo ML lặp lại từ cùng IP/URL trong cửa sổ 60 giây.
  - **Dashboard tích hợp ML:** Hiển thị trạng thái mô hình ML trên System Status, thống kê số lượng ngoại lai ML, badge màu tím đặc trưng `ML_ANOMALY` và chi tiết điểm số/phiên bản trong Modal cảnh báo.
  - **Hiệu năng & Kiểm thử:** Đạt 95.00% Accuracy, 100% Precision, 90.00% Recall, F1-Score 0.9474, độ trễ suy luận trung bình ~12.7 ms. Toàn bộ 93/93 bài test tự động đều vượt qua (100% PASS). Báo cáo tại `docs/phase-6/ml-anomaly-detection.md`.
- **Phase 7: Comprehensive Evaluation, Detection Expansion & System Hardening:**
  - **Mở rộng tập dữ liệu thực nghiệm:** Xây dựng tập holdout 80 mẫu HTTP có nhãn chuẩn xác (40 Benign + 40 Attack qua 8 nhóm tấn công) kèm metadata nguồn gốc.
  - **Mở rộng quy tắc phát hiện:** Triển khai thêm 2 luật phát hiện trọng yếu: *Path Traversal* (`RULE-TRAV-001`, score 75.0) và *Command Injection* (`RULE-CMDI-001`, score 85.0), nâng tổng số quy tắc chuyên biệt lên **8 detectors**.
  - **Hiệu chuẩn chống dương tính giả (FP Mitigation):** Làm giàu dữ liệu huấn luyện lành tính đa tham số và hiệu chuẩn ngưỡng quyết định `effective_threshold = -0.0256`, triệt tiêu hoàn toàn False Positives từ 32.5% về **0.0%**.
  - **Thực nghiệm so sánh 3 cấu hình (Benchmark):** Pipeline lai (*Hybrid*) đạt **97.50% Accuracy, 100.00% Precision, 95.00% Recall, F1-Score 0.9744** (phát hiện 38/40 đợt tấn công), khử trùng lặp 17 cảnh báo thừa (giảm 30.9% nhiễu).
  - **Đo lường hiệu năng & độ tin cậy:** Đánh giá trên 400 requests; Rule Engine p50 = 0.17 ms, toàn bộ pipeline p50 = 41.8 ms, thông lượng 22.8 req/s, bộ nhớ tiêu thụ chỉ ~3.1 MB.
  - **Hoàn thiện giao diện & Báo cáo:** Bổ sung badge nhận diện Path Traversal và Command Injection trên React Dashboard, tích hợp thanh tổng quan năng lực phát hiện lai, vượt qua **113/113 bài test tự động (100% PASS)**. Báo cáo chi tiết tại `docs/phase-7/evaluation-and-hardening-report.md`.
- **Phase 8: Production Readiness, Security Validation & Final Acceptance:**
  - **Kiểm định dữ liệu độc lập (Dataset Audit & Unseen Holdout v3):** Phát hiện 26/40 mẫu lành tính ở Phase 7 trùng khớp đường dẫn sinh dữ liệu huấn luyện; xây dựng tập holdout độc lập mới `holdout_dataset_unseen_v3.json` (100% không trùng lặp) đạt **93.75% Accuracy, 94.87% Precision, 92.50% Recall** trên dữ liệu chưa từng thấy.
  - **Kiểm toán bảo mật & Gia cố hệ thống (Security Hardening):** Giới hạn payload 1MB (chống DoS), bổ sung 4 headers bảo vệ chuẩn OWASP (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`), xử lý chuẩn lỗi cú pháp JSON (400 Bad Request), ẩn thông tin stack trace ở môi trường production, giới hạn batch 500 logs trên API Detection Engine.
  - **Tối ưu hóa độ trễ mạng Windows:** Chuẩn hóa địa chỉ nội bộ sang `127.0.0.1` loại bỏ hoàn toàn độ trễ DNS IPv6 timeout (2.1s), giảm độ trễ Web App round-trip trung vị từ 2045ms xuống chỉ còn **3.75 ms**.
  - **Kiểm thử khả năng phục hồi (Resilience & Recovery):** Xác thực 6 kịch bản sự cố hệ thống (DB offline fallback, Detection Engine offline fallback, thiếu model artifact, ngắt kết nối/kết nối lại SSE, payload quá tải, input dị dạng).
  - **Dashboard hoàn thiện nghiệm thu:** Phân biệt rõ số liệu Benchmark kiểm chuẩn và Alert thời gian thực, chú thích rõ Anomaly Score là khoảng cách ngoại lai thống kê, build Vite production thành công.
  - **Kiểm thử hồi quy toàn diện:** Toàn bộ **123 / 123 bài test tự động vượt qua (100% PASS)**. Báo cáo chi tiết tại thư mục `docs/phase-8/`.
- **Phase 9: Authentication, Authorization & User Management:**
  - **Kiến trúc Xác thực Phiên Máy chủ (Server-Side Sessions):** Quản lý phiên làm việc tập trung qua bảng `user_sessions` trong PostgreSQL với cookie `HttpOnly`, `SameSite=Lax` chống XSS và CSRF. Tự động sinh session ID ngẫu nhiên an toàn 32 bytes qua `crypto.randomBytes(32)` chống Session Fixation.
  - **Mật khẩu Băm Bcrypt An toàn:** Lưu trữ mật khẩu dưới dạng chuỗi băm `bcrypt` (10 salt rounds). Tuyệt đối không lưu plaintext và không trả về `password_hash` trong API.
  - **Phòng thủ Brute Force & Rate Limiting:** Tự động khóa tạm thời 5 phút (`429 Too Many Requests`) sau 5 lần đăng nhập thất bại liên tiếp; thông báo lỗi đồng nhất chống rà quét tài khoản (Username Enumeration).
  - **Phân quyền dựa trên Vai trò (RBAC):** Hỗ trợ 2 vai trò cốt lõi: `ADMIN` (toàn quyền quản trị, xử lý cảnh báo, quản lý người dùng) và `ANALYST` (chỉ xem Dashboard, log và cảnh báo; bị từ chối `403 Forbidden` khi thao tác sửa đổi).
  - **Quản trị Người dùng (User Management APIs):** Cung cấp các API dành riêng cho Admin: `GET /api/users` (danh sách), `POST /api/users` (tạo mới), `PATCH /api/users/:id/status` (bật/khóa), `PATCH /api/users/:id/role` (đổi vai trò).
  - **Quy tắc An toàn Nghiêm ngặt:** Ngăn chặn việc khóa hoặc hạ quyền tài khoản `ADMIN` đang hoạt động cuối cùng (`Cannot deactivate/demote the last active Admin account`).
  - **Quy trình Khởi tạo Bootstrap An toàn:** Hỗ trợ script `npm run bootstrap:admin` tạo hoặc cập nhật tài khoản quản trị ban đầu, không mở endpoint đăng ký công khai tự do.
  - **Tích hợp Dashboard React/Vite:** Màn hình đăng nhập (Login Page) tối hiện đại, kiểm tra phiên `/api/auth/me` khi mở trang, modal quản trị người dùng cho Admin, hiển thị vai trò trên Header và đăng xuất an toàn.
  - **Kiểm thử Toàn diện:** Bổ sung 25 test cases chuyên sâu, nâng tổng số test tự động lên **156 / 156 Tests PASS (100%)** (75 Web App + 81 Detection Engine). Biên dịch Vite production thành công 100%.

---

## 2. Architecture (Kiến trúc Hệ thống Phase 4)

```text
       HTTP Request
             │
             ▼ HTTP Traffic (Port 3000)
┌────────────────────────────────────────────────────────┐
│               Express Web Application                  │
│  - Target Web Routes (/search, /login, ...)            │
│  - Logging Middleware & normalizeIp()                  │
│  - Detection Client (Non-blocking HTTP forward)        │
│  - AlertStreamService (SSE Broadcaster)                │
└────────────┬─────────────────────────────┬─────────────┘
             │                             │
             ▼                             ▼
┌───────────────────────────┐ ┌───────────────────────────┐
│     Logging Storage       │ │  Detection Engine (FastAPI│
│ - PostgreSQL: request_logs│ │         Port 5000)        │
│ - Fallback: requests.log  │ │ - 6 Rule Detectors        │
└───────────────────────────┘ │ - Risk Scorer (0 - 100)   │
             ▲                └─────────────┬─────────────┘
             │ (foreign key link)           │
             │                              ▼ (Detection Result)
┌────────────┴──────────────────────────────┴────────────┐
│              Alert Storage & Lifecycle                 │
│ - PostgreSQL: security_alerts (with updated_at & idx)  │
│ - Fallback: alerts.log                                 │
└────────────────────────────┬───────────────────────────┘
                             │
                             ▼ (Server-Sent Events: /api/alerts/stream)
┌────────────────────────────────────────────────────────┐
│           Security Dashboard (Port 5173)               │
│ - Live SSE Stream Indicator (with Fallback Polling)    │
│ - Real-Time Alert Toast Notification                   │
│ - Alert Lifecycle Summary: NEW / ACK / RESOLVED        │
│ - Filter, Search, Sort & Pagination                    │
│ - Alert Actions: Acknowledge, Resolve, Reopen          │
│ - Detailed Investigation Modal (with HTTP Request Log) │
└────────────────────────────────────────────────────────┘
```

---

## 3. Technologies (Công nghệ Sử dụng)

- **Web Application Backend:** Node.js, Express.js, `pg` (node-postgres), JavaScript (ES6+), Server-Sent Events (SSE).
- **Detection Microservice:** Python 3, FastAPI, Uvicorn, Pandas, NumPy, Pydantic.
- **Dashboard Frontend:** React 18, Vite 5, Native EventSource API, Modern CSS.
- **Database Layer:** PostgreSQL 18/16 Native hoặc Containerized, Connection Pooling.
- **Testing & Quality Assurance:** Node Test Runner (`node:test`, `node:assert`), Python `unittest`, Pytest.
- **Lab & Security Testing:** Windows 11 Native, Kali Linux (Burp Suite, Nmap, Nikto, Sqlmap).

---

## 4. Database Schema (Bảng `request_logs` & `security_alerts`)

### Bảng `request_logs`
```sql
CREATE TABLE IF NOT EXISTS request_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ip VARCHAR(45) NOT NULL,
    method VARCHAR(10) NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    user_agent TEXT,
    response_time_ms NUMERIC(10, 2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### Bảng `security_alerts` (Đã cập nhật Phase 4)
```sql
CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGSERIAL PRIMARY KEY,
    rule_id VARCHAR(50),
    request_log_id BIGINT REFERENCES request_logs(id) ON DELETE SET NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    risk_score NUMERIC(5, 2) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    method VARCHAR(10) NOT NULL,
    target_url TEXT NOT NULL,
    description TEXT,
    details JSONB,
    status VARCHAR(50) DEFAULT 'new',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tối ưu hóa truy vấn lọc và sắp xếp
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_updated_at ON security_alerts(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON security_alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON security_alerts(alert_type);
```

---

## 5. REST APIs

### 5.1. System & Logs APIs
- `GET /api/health`: Trạng thái dịch vụ Web App và kết nối PostgreSQL.
- `GET /api/logs`: Danh sách logs phân trang (`page`, `limit`), lọc theo `ip`, `method`, `statusCode`, `from`, `to`.
- `GET /api/logs/stats`: Thống kê tổng quan lưu lượng HTTP.

### 5.2. Phase 4 Alert Management & Real-Time APIs
- `GET /api/alerts/stream`: Server-Sent Events stream thời gian thực (`alert_created`, `alert_updated`).
- `GET /api/alerts`: Danh sách cảnh báo có phân trang, hỗ trợ sắp xếp (`sort=newest|oldest|risk_desc|risk_asc`) và bộ lọc (`status`, `severity`, `type`, `ip`).
- `GET /api/alerts/:id`: Chi tiết 1 cảnh báo an ninh kèm bản ghi `requestLog` liên quan.
- `GET /api/alerts/stats`: Thống kê cảnh báo theo vòng đời (`totalAlerts`, `newAlerts`, `acknowledgedAlerts`, `resolvedAlerts`, `criticalSeverity`, `highSeverity`,...).
- `PATCH /api/alerts/:id/acknowledge`: Chuyển trạng thái cảnh báo sang `acknowledged` và cập nhật `updated_at`.
- `PATCH /api/alerts/:id/resolve`: Chuyển trạng thái cảnh báo sang `resolved` và cập nhật `updated_at`.
- `PATCH /api/alerts/:id/status`: Chuyển đổi trạng thái linh hoạt (`new`, `acknowledged`, `resolved`).

---

## 6. How to Start (Hướng dẫn Khởi chạy)

### Khởi chạy trên Windows 11 Native
```cmd
:: 1. Khởi chạy toàn bộ dịch vụ (Detection Engine, Web App, Dashboard)
scripts\start\start-all.bat

:: 2. Dừng toàn bộ dịch vụ
scripts\stop\stop-all.bat
```

### Các cổng dịch vụ:
| Dịch vụ | URL | Cổng |
| :--- | :--- | :--- |
| **Web Application** | `http://localhost:3000` | `3000` |
| **Detection Engine** | `http://localhost:5000/docs` | `5000` |
| **Security Dashboard** | `http://localhost:5173` | `5173` |
| **PostgreSQL Database** | `localhost:5432` | `5432` |

---

## 7. How to Test (Kiểm thử Tự động)

Chạy toàn bộ test suites tự động của cả 2 thành phần (Web App & Detection Engine):
```cmd
scripts\test\test-all.bat
```

**Kết quả kiểm thử tự động (Regression Suite):**
- **Web Application Tests:** **75 / 75 tests PASS** (Giao diện, middleware, database layer, resilience file mode, alert lifecycle PATCH APIs, SSE stream, stats, E2E flows, ML mode validation, Phase 7 rules expansion, Phase 8 security headers, payload limits, malformed JSON, SSE reconnect, Phase 9.1 API key/HMAC tests, Phase 9 Session authentication, rate limiting, RBAC, và User Management APIs).
- **Detection Engine Tests:** **81 / 81 tests PASS** (8 nhóm quy tắc phát hiện, API, Risk Scorer, feature extractor, Isolation Forest ML model, boundary tests, batch limits, extreme values, missing model graceful fallback).
- **Tổng cộng:** **156 / 156 tests PASS (100%)**, thời gian thực thi: ~12s.

Chạy thực nghiệm so sánh 3 cấu hình phát hiện (Rule-Only vs ML-Only vs Hybrid):
```cmd
cd detection-engine
# Chạy trên tập kiểm chuẩn Phase 7 (Holdout v2):
.\venv\Scripts\python.exe -m ml.benchmark_comparison --dataset v2

# Chạy trên tập dữ liệu độc lập chưa từng thấy Phase 8 & 9 (Holdout Unseen v3):
.\venv\Scripts\python.exe -m ml.benchmark_comparison --dataset v3
```

Chạy đo lường hiệu năng và độ trễ phân tán toàn diện (Rule / ML / Pipeline / End-to-End HTTP RTT):
```cmd
cd detection-engine
.\venv\Scripts\python.exe tests/test_e2e_performance.py
```

---

## 8. Lộ trình Đồ án (Project Roadmap)
- [x] **Phase 1:** Khởi tạo cấu trúc dự án & môi trường phát triển microservices.
- [x] **Phase 2:** Xây dựng Logging Pipeline & Tích hợp PostgreSQL.
- [x] **Phase 3:** Bộ phát hiện bất thường Rule-Based (6 detectors), Risk Score & Sinh Cảnh báo.
- [x] **Phase 4:** Quản lý vòng đời cảnh báo (Alert Lifecycle) & Giám sát thời gian thực (SSE + Dashboard).
- [x] **Phase 5:** Kiểm thử bảo mật toàn diện & Xác thực tích hợp End-to-End (E2E).
- [x] **Phase 6:** Tích hợp Học máy phát hiện bất thường (Isolation Forest Anomaly Detection).
- [x] **Phase 7:** Đánh giá so sánh Benchmark, Mở rộng 8 quy tắc phát hiện & Gia cố hệ thống.
- [x] **Phase 8:** Sẵn sàng vận hành (Production Readiness), Kiểm toán an ninh & Nghiệm thu.
- [x] **Phase 9:** Đóng toàn diện lỗ hổng an ninh (Security Closure RBAC/HMAC) & Sẵn sàng bảo vệ học thuật (Academic Defense Readiness).
- [x] **Phase 2:** Web Application + Logging Pipeline + PostgreSQL Database.
- [x] **Phase 3:** Rule-Based Anomaly Detection + Risk Score (0-100) + Security Alerts.
- [x] **Phase 4:** Alert Management Lifecycle (NEW / ACKNOWLEDGED / RESOLVED) + Real-Time Monitoring (SSE).
- [x] **Phase 5:** Security Testing, Rule Boundary Verification & End-to-End Validation.
- [x] **Phase 6:** Machine Learning-Based Anomaly Detection (Isolation Forest 11 đặc trưng, Shadow/Active Mode).
- [x] **Phase 7:** Comprehensive Evaluation, Detection Expansion (Path Traversal & Command Injection) & System Hardening (Hybrid Benchmark F1: 0.9744, FPR: 0.0%).
- [x] **Phase 8:** Production Readiness, Security Validation & Final Acceptance (Dataset Audit, Unseen Generalization v3 F1: 0.9367, Security Headers, DoS Limits, 123/123 Tests Pass).
