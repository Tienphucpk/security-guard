# Web Application - SECURITY GUARD

Thành phần Web Application thử nghiệm đóng vai trò là ứng dụng mục tiêu (target website) trong mô hình kiểm thử an toàn thông tin.

## Mục tiêu
- Cung cấp các endpoint HTTP để tiếp nhận traffic từ người dùng thông thường và traffic kiểm thử bảo mật (từ Kali Linux / công cụ kiểm thử).
- Tích hợp **Logging Middleware** ghi nhận đầy đủ siêu dữ liệu (metadata) của mọi HTTP request vào log file chuẩn định dạng JSON.
- Đóng vai trò là nguồn dữ liệu đầu vào cho Detection Engine trong các pha tiếp theo.

## Cấu trúc thư mục
```
web-app/
├── src/
│   ├── routes/          # Định nghĩa endpoint (page, auth, api)
│   ├── controllers/     # Xử lý logic nghiệp vụ
│   ├── middleware/      # Logging middleware và bảo mật
│   ├── services/        # Client giao tiếp với Detection Engine
│   ├── utils/           # Tiện ích logger
│   └── server.js        # Điểm khởi chạy Express server
├── public/              # Giao diện HTML/CSS cơ bản
├── logs/                # Thư mục lưu requests.log
├── tests/               # Unit tests kiểm thử route và middleware
├── package.json
└── Dockerfile
```

## Các route được hỗ trợ
- `GET /` : Trang chủ giới thiệu
- `GET /login` : Form đăng nhập
- `POST /login` : Tiếp nhận yêu cầu đăng nhập
- `GET /register` : Form đăng ký tài khoản
- `POST /register` : Tiếp nhận đăng ký
- `GET /dashboard` : Trang quản trị người dùng
- `GET /profile` : Thông tin người dùng
- `GET /search` : Tìm kiếm (mô phỏng truy vấn dữ liệu)
- `GET /api/health` : Kiểm tra trạng thái hoạt động của Web App
- `GET /api/logs` : Xem danh sách các request log gần đây

## Định dạng Log HTTP Request
```json
{
  "timestamp": "2026-10-07T06:40:00.000Z",
  "ip": "192.168.235.10",
  "method": "GET",
  "url": "/login",
  "statusCode": 200,
  "userAgent": "Mozilla/5.0 ...",
  "responseTime": 12
}
```

## Chạy ứng dụng độc lập
```bash
# Cài đặt thư viện
npm install

# Khởi chạy chế độ phát triển
npm run dev

# Khởi chạy chế độ production
npm start

# Chạy kiểm thử tự động
npm test
```
