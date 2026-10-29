# Tài liệu Thiết lập Môi trường Thử nghiệm (Lab Environment)

Tài liệu này mô tả kiến trúc triển khai môi trường Lab phục vụ nghiên cứu và đánh giá hệ thống **SECURITY GUARD** trong khuôn khổ đồ án môn học Bảo mật & An toàn thông tin.

---

## 1. Tổng quan Kiến trúc Phần cứng & Ảo hóa

```
+--------------------------------------------------------------+
|                   Windows 11 Host Machine                     |
|                                                              |
|   +------------------------------------------------------+   |
|   |                VMware Workstation Pro                |   |
|   |                                                      |   |
|   |   +-------------------+      +-------------------+   |   |
|   |   |  Kali Linux VM    |      |  Ubuntu Server VM |   |   |
|   |   | (Security Testing)|      | (SECURITY GUARD)  |   |   |
|   |   +---------+---------+      +---------+---------+   |   |
|   |             |                          |             |   |
|   |             +------------+-------------+             |   |
|   |                          |                           |   |
|   |            VMware Host-only Network (VMnetX)         |   |
|   +------------------------------------------------------+   |
+--------------------------------------------------------------+
```

### Thành phần chi tiết:
- **Host Operating System:** Windows 11 64-bit
- **Hypervisor:** VMware Workstation Pro (hoặc VMware Player)
- **Security Testing VM:** Kali Linux (Phiên bản 2024.x trở lên)
- **Server VM:** Ubuntu Server 24.04 LTS (hoặc 22.04 LTS)
- **Network Mode:** VMware Host-only Network (Cách ly an toàn với mạng Internet công cộng)

---

## 2. Quy hoạch Địa chỉ Mạng (Ví dụ minh họa)

> [!IMPORTANT]
> Các địa chỉ IP dưới đây chỉ mang tính chất minh họa cho mô hình Lab cô lập. Hệ thống mã nguồn **hoàn toàn không hard-code** các địa chỉ IP này mà sử dụng cấu hình biến môi trường (`.env`).

| Thiết bị / Máy ảo | Vai trò | IP tham khảo | Cổng dịch vụ |
| :--- | :--- | :--- | :--- |
| **Kali Linux** | Máy tấn công kiểm thử (Attacker/Tester) | `192.168.235.10` | N/A |
| **Ubuntu Server** | Máy chủ triển khai hệ thống SECURITY GUARD | `192.168.235.20` | `3000`, `5000`, `5173`, `5432` |
| **Web Application** | Ứng dụng Web mục tiêu (Target Site) | `192.168.235.20` | `3000` (HTTP) |
| **Detection Engine** | Microservice phân tích log & ML | `192.168.235.20` | `5000` (REST API) |
| **Dashboard** | Giao diện giám sát an ninh mạng | `192.168.235.20` | `5173` (HTTP) |
| **Database** | Lưu trữ log, alert, rules (PostgreSQL) | `192.168.235.20` | `5432` (PostgreSQL) |

---

## 3. Các bước thiết lập trên VMware Workstation

### Bước 1: Tạo mạng Host-only Network
1. Mở VMware Workstation -> Chọn **Edit** -> **Virtual Network Editor**.
2. Chọn card mạng kiểu **Host-only** (ví dụ `VMnet2` hoặc `VMnet3`).
3. Tắt tùy chọn *Connect a host virtual adapter (DHCP có thể bật hoặc dùng IP tĩnh)*.
4. Đặt Subnet IP: `192.168.235.0`, Subnet mask: `255.255.255.0`.

### Bước 2: Cấu hình Card mạng cho Máy ảo
1. Trên máy ảo **Kali Linux**: Đổi Network Adapter sang `Custom: VMnetX (Host-only)`.
2. Trên máy ảo **Ubuntu Server**: Đổi Network Adapter sang cùng card `Custom: VMnetX (Host-only)`.

### Bước 3: Kiểm tra thông mạng
Từ Kali Linux, chạy lệnh ping kiểm tra kết nối tới Ubuntu Server:
```bash
ping -c 3 192.168.235.20
```
Nếu có phản hồi, truy cập thử nghiệm Web Application qua trình duyệt Firefox trên Kali:
```
http://192.168.235.20:3000
```
Mọi thao tác truy cập sẽ được Web Application tự động ghi log vào `logs/requests.log`.
