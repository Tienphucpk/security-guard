# Hướng Dẫn Kiểm Thử Phase 2 - SECURITY GUARD

Tài liệu kiểm thử xác thực các tính năng trong Phase 2: Web App, Logging Pipeline, Database Layer và API endpoints.

---

## 1. Kiểm thử Tự động qua Script
Từ thư mục gốc dự án:
```cmd
scripts\test\test-all.bat
```
Script sẽ thực thi 12 bài kiểm thử của Web App và 3 bài kiểm thử API của Detection Engine.

---

## 2. Danh mục 12 Bài Kiểm thử Tự động
1. **Test 1:** Web App khởi động và render HTML trang chủ (`GET /`).
2. **Test 2:** Endpoint `GET /api/health` trả về kết quả thành công kèm trạng thái DB (`connected` hoặc `disconnected`).
3. **Test 3:** Request tạo ra dòng log định dạng JSON trong `web-app/logs/requests.log`.
4. **Test 4:** Cơ chế lưu log vào CSDL PostgreSQL thực thi an toàn và trả kết quả mà không gây ngoại lệ.
5. **Test 5:** Endpoint `GET /api/logs` trả về cấu trúc JSON đúng chuẩn (`status`, `logs`, `count`, `total`).
6. **Test 6:** Phân trang (`GET /api/logs?page=1&limit=2`) giới hạn số bản ghi chính xác.
7. **Test 7:** Lọc theo IP (`GET /api/logs?ip=127.0.0.1`) lọc chính xác các bản ghi trùng IP.
8. **Test 8:** Lọc theo HTTP Method (`GET /api/logs?method=GET`) lọc chính xác method.
9. **Test 9:** Lọc theo HTTP Status Code (`GET /api/logs?statusCode=200`) lọc đúng mã trạng thái.
10. **Test 10:** Endpoint thống kê `GET /api/logs/stats` tính toán và trả về các chỉ số tổng hợp (`totalRequests`, `successfulRequests`, `uniqueIps`, `httpMethods`, ...).
11. **Test 11:** Kháng lỗi khi CSDL offline: Web App duy trì hoạt động, không crash khi DB không khả dụng.
12. **Test 12:** Chuẩn hóa IP: hàm `normalizeIp()` xử lý đúng các trường hợp `::ffff:127.0.0.1`, `::1`, `192.168.1.100`, và chuỗi forwarded IP.

---

## 3. Kiểm thử Thủ công qua cURL / PowerShell

Sau khi khởi chạy `scripts\start\start-all.bat`:

### 3.1. Kiểm tra trạng thái hệ thống:
```powershell
curl http://localhost:3000/api/health
```

### 3.2. Kiểm tra truy vấn danh sách log:
```powershell
# Mặc định (50 logs đầu)
curl http://localhost:3000/api/logs

# Phân trang
curl "http://localhost:3000/api/logs?page=1&limit=10"

# Lọc theo IP và Method
curl "http://localhost:3000/api/logs?ip=127.0.0.1&method=GET"

# Lọc theo Status Code
curl "http://localhost:3000/api/logs?statusCode=404"
```

### 3.3. Kiểm tra thống kê an ninh:
```powershell
curl http://localhost:3000/api/logs/stats
```
