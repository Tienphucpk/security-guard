# Nghiên cứu Phương pháp Phát hiện Bất thường trên Website

Tài liệu phục vụ cho các giai đoạn tiếp theo của đồ án môn học Bảo mật và An toàn thông tin.

## 1. Tổng quan bài toán
Phát hiện hành vi bất thường trên website (Web Anomaly Detection) nhằm nhận diện sớm các hoạt động độc hại hoặc rủi ro an ninh từ lưu lượng truy cập HTTP trước khi gây thiệt hại cho hệ thống.

## 2. Các hướng tiếp cận chính

### 2.1. Tiếp cận dựa trên Quy tắc (Rule-based Detection)
- **Cơ chế:** So khớp các mẫu đã biết (Signatures) thông qua biểu thức chính quy (Regex), danh sách User-Agent độc hại, hoặc ngưỡng tần suất (Thresholds).
- **Ưu điểm:**
  - Tốc độ xử lý nhanh, tốn ít tài nguyên tính toán.
  - Tỷ lệ dương tính giả (False Positive) thấp đối với các mẫu tấn công rõ ràng.
- **Hạn chế:**
  - Không thể phát hiện các biến thể tấn công mới hoặc hành vi tấn công tinh vi (Zero-day, Slow attack).

### 2.2. Tiếp cận dựa trên Học máy (Machine Learning / Anomaly Detection)
- **Mô hình tiềm năng:** **Isolation Forest (iForest)**
  - Thuật toán học không giám sát (Unsupervised Learning) đặc biệt hiệu quả trong việc phát hiện dị biệt (anomalies) trong dữ liệu đa chiều.
  - Cơ chế: Phân tách các điểm dị biệt sớm hơn so với các điểm dữ liệu bình thường qua cấu trúc cây ngẫu nhiên (Isolation Trees).
- **Các đặc trưng (Features) trích xuất từ HTTP Log:**
  1. `request_length`: Độ dài URL và query parameters.
  2. `request_frequency`: Số request phát sinh từ một IP trong cửa sổ thời gian `T`.
  3. `error_ratio`: Tỷ lệ mã lỗi 4xx/5xx so với tổng request.
  4. `method_distribution`: Tỷ lệ phương thức POST/GET bất thường.
  5. `response_time`: Độ trễ phản hồi bất thường (dấu hiệu Time-based SQLi hoặc DoS).

## 3. Lộ trình tích hợp vào Detection Engine
1. **Pha 1 (Hiện tại):** Chuẩn hóa luồng log và API nền tảng.
2. **Pha 2:** Xây dựng Rule Engine (Brute Force, Scanner, Basic SQLi/XSS).
3. **Pha 3:** Trích xuất đặc trưng và áp dụng Isolation Forest / Scikit-learn để chấm điểm rủi ro (Risk Scoring).
4. **Pha 4:** Đồng bộ cảnh báo thời gian thực lên Dashboard.
