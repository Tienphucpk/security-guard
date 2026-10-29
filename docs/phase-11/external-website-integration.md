# External Website Registration & Integration Manual

## 1. Overview
The Security Guard External Website Management subsystem allows authenticated Administrators to onboard, configure, verify, and secure third-party and external websites.

## 2. Administrator Workflow

### Step 1: Register External Website
Navigate to the Dashboard (**Port 5173**) -> **Giám sát Website & Active Enforcement** -> Click **➕ Đăng ký Website Ngoài**.

#### Registration Parameters:
- **Website ID**: Unique alphanumeric slug (e.g., `site_prod_blog`).
- **Name**: Human-readable label (e.g., `Corporate Production Blog`).
- **Domain**: Registered domain or hostname (e.g., `blog.example.com`).
- **Integration Method**: Select one of:
  - `REVERSE_PROXY`
  - `APPLICATION_AGENT`
  - `LOG_INGESTION`
- **Upstream URL**: Target server base URL (required for `REVERSE_PROXY`).
- **Description**: Operational context.

> **Safety Default**: Every newly registered website defaults to `MONITOR_ONLY` mode. Enforcement (`ENFORCE`) must be explicitly triggered by an Admin.

---

### Step 2: One-Time Secret Key Generation
Upon successful registration, the API returns the cryptographically generated `plaintextSecret` (format: `secguard_ag_<hex>`).

```
⚠️ IMPORTANT SECURITY NOTICE:
The Secret Key is displayed ONLY ONCE in the confirmation modal.
Copy and store it in your application's environment configuration immediately.
Security Guard stores only the SHA-256 hash and AES-256-GCM envelope key in PostgreSQL.
```

---

### Step 3: Connection Verification & Diagnostics
Click **🔍 Verify** on any website card:
- For **REVERSE_PROXY**: Performs SSRF validation followed by an HTTP probe with a 3000ms timeout.
- For **APPLICATION_AGENT** and **LOG_INGESTION**: Inspects real-time telemetry timestamps (`HEALTHY` if events received within 15 mins, `DEGRADED` if stale, `UNKNOWN` if awaiting initial stream).

---

### Step 4: Secret Key Rotation
If an Agent secret is compromised or routine rotation is required:
1. Open the website card and click **🔄 Secret**.
2. Confirm the prompt to immediately invalidate the old key.
3. Copy the newly generated secret key and update your application environment.

---

## 3. API Reference

### Register External Website
- **Endpoint**: `POST /api/websites/external`
- **Authentication**: Session Cookie (Role: `ADMIN`)
- **Request Body**:
  ```json
  {
    "websiteId": "site_prod_store",
    "name": "E-Commerce Production",
    "domain": "store.example.com",
    "integrationMethod": "APPLICATION_AGENT",
    "description": "Production store telemetry"
  }
  ```
- **Response** (`201 Created`):
  ```json
  {
    "status": "success",
    "message": "External website registered successfully",
    "website": {
      "websiteId": "site_prod_store",
      "monitoringMode": "MONITOR_ONLY",
      "isExternal": true
    },
    "plaintextSecret": "secguard_ag_7f9a12b3c4d5e6f7...",
    "instructions": { ... }
  }
  ```

### Rotate Secret Key
- **Endpoint**: `POST /api/websites/:id/rotate-secret`
- **Authentication**: Session Cookie (Role: `ADMIN`)
- **Response** (`200 OK`):
  ```json
  {
    "status": "success",
    "websiteId": "site_prod_store",
    "plaintextSecret": "secguard_ag_new_secret_..."
  }
  ```

### Verify Website Health
- **Endpoint**: `POST /api/websites/:id/verify`
- **Authentication**: Session Cookie (Role: `ADMIN` or `ANALYST`)
- **Response** (`200 OK`):
  ```json
  {
    "status": "success",
    "websiteId": "site_prod_store",
    "healthStatus": "HEALTHY",
    "diagnostic": "Active telemetry stream. Last event received 1m ago.",
    "lastHealthCheck": "2026-10-29T15:20:00.000Z"
  }
  ```
