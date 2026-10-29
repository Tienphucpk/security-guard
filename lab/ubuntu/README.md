# Ubuntu Server - Máy chủ Triển khai SECURITY GUARD

Tài liệu hướng dẫn cấu hình máy chủ Ubuntu Server trong môi trường ảo hóa VMware để vận hành toàn bộ hệ sinh thái **SECURITY GUARD**.

---

## 1. Vai trò của Ubuntu Server
Ubuntu Server 24.04 LTS (hoặc 22.04 LTS) đóng vai trò là Server VM lưu trữ và chạy:
- **Docker & Docker Compose**
- **SECURITY GUARD Services**:
  - `web-app`: Web Application mục tiêu (Node.js + Express)
  - `detection-engine`: Microservice phân tích log & ML (Python + FastAPI)
  - `dashboard`: Giao diện giám sát an ninh (React + Vite / Nginx)
  - `database`: Cơ sở dữ liệu PostgreSQL

---

## 2. Yêu cầu Hệ thống Máy ảo Ubuntu
- **OS:** Ubuntu Server 24.04 LTS x86_64
- **RAM:** Tối thiểu 2GB (Khuyến nghị 4GB)
- **CPU:** 2 vCPU
- **Disk:** 20GB
- **Network Adapter:** Host-only Network (giao tiếp cô lập với Kali Linux)

---

## 3. Cài đặt Docker & Môi trường trên Ubuntu

```bash
# Cập nhật hệ thống
sudo apt update && sudo apt upgrade -y

# Cài đặt Docker Engine & Docker Compose Plugin
sudo apt install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Phân quyền chạy docker không cần sudo cho user
sudo usermod -aG docker $USER
```

---

## 4. Khởi chạy SECURITY GUARD trên Ubuntu
```bash
# Di chuyển vào thư mục project
cd /path/to/security-guard

# Sao chép cấu hình môi trường
cp .env.example .env

# Khởi động toàn bộ các container dịch vụ
docker compose up -d

# Kiểm tra trạng thái các container
docker compose ps

# Theo dõi logs hệ thống
docker compose logs -f
```
