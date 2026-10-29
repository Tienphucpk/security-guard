# Dashboard - SECURITY GUARD

Giao diện Web Frontend giám sát trạng thái hệ thống và thống kê an ninh mạng trong khuôn khổ đồ án **SECURITY GUARD**.

## Mục tiêu
- Trực quan hóa trạng thái các service trong hệ thống:
  - **Web Application**
  - **Detection Engine**
  - **Database**
- Hiển thị các chỉ số thống kê cơ bản:
  - `Total Requests`: Tổng số request ghi nhận.
  - `Suspicious Requests`: Số lượng request phát hiện bất thường.
  - `Alerts`: Tổng số cảnh báo an ninh được kích hoạt.
- Hiển thị danh sách cảnh báo gần đây (`Recent Alerts`).

## Công nghệ sử dụng
- React 18
- Vite
- CSS thuần tối giản, responsive, tối ưu cho đồ án kỹ thuật.

## Hướng dẫn chạy cục bộ
```bash
# Cài đặt dependencies
npm install

# Khởi chạy chế độ phát triển
npm run dev

# Build bản production
npm run build

# Xem trước bản build
npm run preview
```
Mặc định Dashboard chạy tại: `http://localhost:5173`
