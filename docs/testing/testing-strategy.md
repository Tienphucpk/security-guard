# Chiến lược Kiểm thử (Testing Strategy) - SECURITY GUARD

Tài liệu này xác định các giai đoạn và phương pháp kiểm thử cho đồ án.

## 1. Nguyên tắc Kiểm thử An toàn
1. **Môi trường cách ly tuyệt đối:** Toàn bộ quá trình kiểm thử an toàn thông tin chỉ được diễn ra trong môi trường Lab ảo hóa Host-only (VMware).
2. **Không scan mục tiêu bên ngoài:** Nghiêm cấm sử dụng các công cụ rà quét hướng ra Internet công cộng hoặc các máy chủ không thuộc quyền quản lý.
3. **Phân tách các giai đoạn kiểm thử:**
   - **Giai đoạn 1 (Hiện tại):** Kiểm thử tính đúng đắn của phần mềm (Unit Testing, API contract, cơ chế logging).
   - **Giai đoạn 2 (Sau này):** Kiểm thử an toàn thông tin (Security Testing với công cụ Kali Linux).

---

## 2. Các tầng Kiểm thử Phần mềm (Giai đoạn 1)

### 2.1. Web Application Unit & Integration Tests
- Sử dụng Node.js test runner tích hợp:
  ```bash
  cd web-app
  npm test
  ```
- Tiêu chí đạt:
  - Tất cả route chính (`/`, `/login`, `/api/health`) trả về HTTP 200.
  - Logging Middleware ghi nhận đầy đủ bản ghi JSON vào file `requests.log`.

### 2.2. Detection Engine API Contract Tests
- Sử dụng Python `unittest`:
  ```bash
  cd detection-engine
  python -m unittest discover tests
  ```
- Tiêu chí đạt:
  - `/health` trả về `status: "ok"`.
  - `/analyze` tiếp nhận payload log và trả về `status: "not_implemented"`, `risk_score: 0.0`.
  - `/analyze/batch` xử lý danh sách log theo lô đúng định dạng.

---

## 3. Kế hoạch Kiểm thử Bảo mật (Giai đoạn 2 - Future Stages)

| Loại kiểm thử | Công cụ dự kiến (Kali Linux) | Mục tiêu kiểm tra |
| :--- | :--- | :--- |
| **Authentication Testing** | Burp Suite Intruder, Hydra | Kiểm thử tấn công dò mật khẩu (Brute-Force) để kiểm tra Rule BF-001 |
| **Web Vulnerability Scanning**| OWASP ZAP, Nikto | Kiểm tra nhận dạng dấu hiệu User-Agent và tần suất scan |
| **SQL Injection Probe** | Sqlmap (lab mode), Manual payloads | Kiểm tra phát hiện chuỗi ký tự đặc trưng trong URL query |
| **XSS Probe** | Burp Repeater | Kiểm tra phát hiện script tags và event handlers |
