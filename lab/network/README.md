# Mạng Kiểm thử Cô lập (Network Lab)

Tài liệu mô tả topo mạng ảo hóa cách ly cho đồ án **SECURITY GUARD**.

---

## 1. Sơ đồ Topo Mạng

```
Windows Host
    |
  VMware
    |
Host-only Network
    |
┌───┴───┐
Kali   Ubuntu
  |       |
  └──HTTP─┘
```

---

## 2. Mục tiêu của Mô hình Mạng
- **Cách ly tuyệt đối (Isolation):** Không để lưu lượng rà quét / kiểm thử phát sinh ra bên ngoài mạng Internet công cộng hoặc mạng LAN trường học / gia đình.
- **Mô phỏng chân thực:** Giả lập môi trường tấn công - phòng thủ thực tế giữa máy tấn công (Kali) và máy chủ dịch vụ (Ubuntu).
- **Đơn giản hóa:** Ở giai đoạn này không yêu cầu tự động hóa cấu hình mạng (SDN), chỉ cần cấu hình card mạng Host-only sẵn có trong VMware Workstation.

---

## 3. Bảng Phân bổ Mạng Dự kiến (Ví dụ mẫu)

```
Dải mạng: 192.168.235.0/24 (Host-only VMnet)
Gateway / Host Adapter: 192.168.235.1 (nếu bật trên Host)
Netmask: 255.255.255.0

+----------------------------------------------------+
| Kali Linux (Security Tester VM)                    |
| IP: 192.168.235.10 / 24                            |
+----------------------------------------------------+
                          |
                          | Gửi request kiểm thử HTTP (Port 3000)
                          v
+----------------------------------------------------+
| Ubuntu Server (SECURITY GUARD VM)                  |
| IP: 192.168.235.20 / 24                            |
| Services: Web App, Detection Engine, Dashboard, DB |
+----------------------------------------------------+
```

> [!NOTE]
> Địa chỉ IP trên là ví dụ minh họa và có thể tùy chỉnh theo cấu hình VMware thực tế của sinh viên. Ứng dụng đọc cổng và địa chỉ từ file biến môi trường `.env`.
