# Configuration Directory

Thư mục chứa các cấu hình mặc định phi bảo mật (non-sensitive default configurations) của hệ thống SECURITY GUARD.

- `default.json`: Các thiết lập mặc định (cổng, đường dẫn log, tên ứng dụng).
- Các giá trị nhạy cảm (mật khẩu, khóa bảo mật) được đọc thông qua biến môi trường (`.env`), không được lưu cứng trong thư mục này.
