# Detection Engine - SECURITY GUARD

Microservice chịu trách nhiệm phân tích dữ liệu HTTP logs thu thập từ Web Application nhằm phát hiện các hành vi bất thường và dấu hiệu tấn công.

## Mục tiêu giai đoạn hiện tại
- Cung cấp kiến trúc Microservice độc lập trên nền tảng **Python 3** và **FastAPI**.
- Cung cấp API endpoints chuẩn REST:
  - `GET /health`: Trả về trạng thái hoạt động của engine.
  - `POST /analyze`: Tiếp nhận bản ghi log đơn lẻ, trả về stub response rủi ro.
  - `POST /analyze/batch`: Tiếp nhận danh sách log theo lô.
- Thiết lập sẵn bộ khung module cho các giải thuật và quy tắc phát hiện:
  - `rules/`: Quy tắc phát hiện tấn công xác thực, injection, brute force.
  - `analyzer/`: Module phân tích hành vi và tiền xử lý dữ liệu.
  - `models/`: Nơi lưu trữ các mô hình Machine Learning (Isolation Forest, v.v.).
  - `data/`: Dữ liệu log mẫu phục vụ huấn luyện và kiểm thử.

## API Specification

### 1. Health Check
- **Endpoint:** `GET /health`
- **Response:**
```json
{
  "status": "ok",
  "service": "detection-engine",
  "version": "1.0.0"
}
```

### 2. Phân tích Log Request
- **Endpoint:** `POST /analyze`
- **Request Body:**
```json
{
  "timestamp": "2026-10-07T06:30:00.000Z",
  "ip": "192.168.235.10",
  "method": "GET",
  "url": "/login",
  "statusCode": 200,
  "userAgent": "Mozilla/5.0 ...",
  "responseTime": 25.0
}
```
- **Response mẫu:**
```json
{
  "status": "not_implemented",
  "risk_score": 0.0,
  "is_anomaly": false,
  "matched_rules": [],
  "details": {
    "received_url": "/login",
    "received_ip": "192.168.235.10"
  }
}
```

## Hướng dẫn cài đặt và chạy cục bộ
```bash
# Tạo môi trường ảo Python
python -m venv venv

# Kích hoạt môi trường ảo:
# Trên Windows:
venv\Scripts\activate
# Trên Linux:
source venv/bin/activate

# Cài đặt thư viện
pip install -r requirements.txt

# Khởi chạy service
uvicorn main:app --host 0.0.0.0 --port 5000 --reload

# Chạy kiểm thử
python -m unittest discover tests
```
