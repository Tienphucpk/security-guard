# Helper Scripts - SECURITY GUARD

Thư mục chứa các script tự động hóa cho cả môi trường **Windows** (`.bat`) và **Linux / Ubuntu** (`.sh`).

## Danh mục Scripts

### 1. `scripts/setup/`
- `setup.bat` (Windows): Tự động cài đặt dependencies cho `web-app`, tạo virtualenv Python và cài đặt packages cho `detection-engine`, cài đặt packages cho `dashboard`.
- `setup.sh` (Linux / Ubuntu): Script cài đặt tương đương cho môi trường Linux.

### 2. `scripts/start/`
- `start-all.bat` (Windows): Khởi chạy đồng thời 3 terminal riêng biệt để chạy Web App (cổng 3000), Detection Engine (cổng 5000) và Dashboard (cổng 5173).
- `start-all.sh` (Linux): Khởi chạy các service dưới dạng background jobs và lưu Process ID (PID).

### 3. `scripts/stop/`
- `stop-all.bat` (Windows): Đóng các tiến trình node, uvicorn và docker containers.
- `stop-all.sh` (Linux): Tắt các tiến trình background dựa trên PID đã lưu.

### 4. `scripts/test/`
- `test-all.bat` (Windows): Thực thi toàn bộ unit tests của Web Application và Detection Engine.
- `test-all.sh` (Linux): Chạy tests tương đương trên Linux.

## Ví dụ sử dụng trên Windows
```cmd
:: Cài đặt lần đầu
scripts\setup\setup.bat

:: Chạy kiểm thử tự động
scripts\test\test-all.bat

:: Khởi chạy tất cả service
scripts\start\start-all.bat

:: Dừng hệ thống
scripts\stop\stop-all.bat
```
