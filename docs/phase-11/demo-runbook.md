# Phase 11 — Live Demonstration Runbook

## 1. System Components & Port Map

Ensure the following background services are online:

| Component | Port | Technology | Process / Command |
| :--- | :--- | :--- | :--- |
| **PostgreSQL Database** | 5432 | PostgreSQL 16 | Service: `security_guard` DB |
| **Web Application** | 3000 | Node.js Express | `node src/server.js` |
| **Python Detection Engine** | 5000 | FastAPI / Uvicorn | `python -m uvicorn main:app --port 5000` |
| **React Dashboard** | 5173 | Vite + React | `npm run dev` |
| **Monitoring Gateway** | 8080 | Node.js Reverse Proxy | `node gateway/server.js` |
| **Demo Node Shop** | 4001 | Express | `node server.js` |
| **Demo Python Portal** | 4002 | Python HTTP | `python server.py` |

---

## 2. Step-by-Step Demonstration Script

### Scenario 1: External Website Registration & Secret Generation
1. Open the Dashboard in your browser: `http://localhost:5173`.
2. Log in with Administrator credentials:
   - **Username**: `admin`
   - **Password**: `Admin@123456`
3. Scroll down to the **🌐 Giám sát Website & Active Enforcement (Phase 11)** section.
4. Click **➕ Đăng ký Website Ngoài**.
5. Fill in the modal form:
   - **Website ID**: `site_external_blog`
   - **Tên Hiển thị**: `External Corporate Blog`
   - **Tên miền**: `blog.example.com`
   - **Phương thức**: `APPLICATION_AGENT`
   - **Mô tả**: `Blog doanh nghiệp chạy bên ngoài mạng nội bộ`
6. Click **Đăng ký & Cấp Secret Key**.
7. **Inspect Output**:
   - The modal displays the one-time **Agent Secret Key** (e.g. `secguard_ag_7f9a...`) with a **Sao chép** (Copy) button.
   - Integration instructions and code snippets are provided directly.
8. Click **Tôi đã lưu trữ khóa an toàn — Đóng**.
9. The new website card appears on the dashboard with a purple **🧩 Application Agent** badge and status `○ UNKNOWN`.

---

### Scenario 2: Telemetry Ingestion & Real-Time Status Transition
Simulate an agent forwarding an event using the generated Secret Key:

```powershell
curl -X POST "http://localhost:3000/api/ingest/events" `
  -H "Content-Type: application/json" `
  -H "X-Website-Id: site_external_blog" `
  -H "X-Agent-Secret: <YOUR_SECRET_KEY>" `
  -d '{"event_id":"evt-demo-1","source_id":"site_external_blog","method":"GET","path":"/articles","status_code":200,"response_time_ms":12}'
```

**Verify Dashboard Reaction:**
- Notice the status badge on `site_external_blog` immediately flips to **● HEALTHY**.
- The diagnostic message updates in real time via SSE: *"Active agent telemetry received"*.

---

### Scenario 3: Passive Log Ingestion (Nginx / Apache)
Simulate streaming an Apache or Nginx access log:

```powershell
curl -X POST "http://localhost:3000/api/ingest/logs" `
  -H "X-Website-Id: site_external_blog" `
  -H "X-Agent-Secret: <YOUR_SECRET_KEY>" `
  -H "Content-Type: text/plain" `
  -d "198.51.100.25 - - [10/Oct/2026:15:30:00 +0700] ""GET /products?token=secret123 HTTP/1.1"" 200 4096"
```

**Verify Dashboard Reaction:**
- The system ingests the log entry, redacts the token (`/products?token=[REDACTED]`), and forwards it to the Detection Engine.
- The Dashboard displays a toast notification confirming passive log ingestion.

---

### Scenario 4: SSRF Boundary Verification (Reverse Proxy Mode)
Try registering a website with an illegal upstream targeting loopback or AWS metadata:

```powershell
curl -X POST "http://localhost:3000/api/websites/external" `
  -H "Content-Type: application/json" `
  -H "Cookie: <ADMIN_SESSION_COOKIE>" `
  -d '{"websiteId":"site_ssrf_test","name":"SSRF Test","integrationMethod":"REVERSE_PROXY","upstreamUrl":"http://169.254.169.254/latest/meta-data/"}'
```

**Verify Output:**
- The API promptly rejects the request with HTTP 400:
  `"SSRF Validation Failed: Forbidden destination: AWS/GCP/Azure Cloud Metadata IP (169.254.169.254)"`.

---

### Scenario 5: Secret Key Rotation
1. On the `site_external_blog` card, click **🔄 Secret**.
2. Confirm the prompt.
3. The modal displays the new Secret Key, and old keys are immediately invalidated.

---

### Scenario 6: Active Enforcement (Reverse Proxy Mode)
1. On `site_demo_node`, click **🛡️ Kích hoạt ENFORCE** (or **🛡️ ENFORCE**).
2. The card turns red with badge `🛡️ ENFORCE (Chặn chủ động)`.
3. Send an attack payload through the Gateway:
   ```bash
   curl -i "http://localhost:8080/site/site_demo_node/products?category=' OR 1=1--"
   ```
4. **Observe Output**:
   - Gateway immediately blocks the attack with **HTTP 403 Forbidden**.
   - An enforcement audit record is posted to the Dashboard table in real time.
