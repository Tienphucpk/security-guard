# Kali Linux - Môi trường Kiểm thử An toàn Thông tin

> [!WARNING]
> Mọi hoạt động kiểm thử chỉ được thực hiện trong môi trường Lab cục bộ (VMware Host-only Network) do người dùng kiểm soát. Nghiêm cấm mọi hành vi tấn công hoặc quét các hệ thống bên ngoài.

---

## 1. Mục đích
Máy ảo Kali Linux đóng vai trò là môi trường của chuyên viên đánh giá bảo mật / người kiểm thử (Security Tester), phát sinh các yêu cầu HTTP để kiểm tra khả năng phát hiện của **SECURITY GUARD**.

### Luồng tương tác dự kiến:
```
Kali Linux
   ↓
Security Testing
   ↓
HTTP Requests
   ↓
Web Application (Ubuntu Server)
   ↓
Logging Middleware
   ↓
Detection Engine
```

---

## 2. Các công cụ dự kiến sử dụng

### 1. Burp Suite (Community / Professional)
- **Mục đích:** Proxy chặn bắt gói tin HTTP/HTTPS, kiểm tra request headers, can thiệp tham số (Repeater, Intruder) để mô phỏng các request bất thường.

### 2. Nmap
- **Mục đích:** Rà quét cổng và phát hiện dịch vụ (Service Fingerprinting) để tạo dấu vết rà quét mạng (Reconnaissance traffic).

### 3. OWASP ZAP (Zed Attack Proxy)
- **Mục đích:** Công cụ quét lỗ hổng ứng dụng web tự động để kiểm tra khả năng phát hiện các mẫu quét (Scanner Signatures / User-Agents).

### 4. Mozilla Firefox (Trình duyệt tích hợp trên Kali)
- **Mục đích:** Truy cập giao diện ứng dụng web, mô phỏng hành vi của người dùng thông thường và kiểm thử thủ công qua GUI.

---

## 3. Quy trình Kiểm thử trên Lab (Giai đoạn sau)
1. Khởi động máy ảo Kali Linux và Ubuntu Server trong cùng dải mạng Host-only.
2. Kiểm tra kết nối tới Web Application:
   ```bash
   curl -I http://192.168.235.20:3000/api/health
   ```
3. Tiến hành các kịch bản kiểm thử (đăng nhập sai nhiều lần, gửi tham số tìm kiếm bất thường, rà quét tự động).
4. Quan sát log sinh ra trong Web Application và kiểm tra phản hồi từ Detection Engine.
