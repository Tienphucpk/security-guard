# Real-World Integration Lab Validation

## 1. Objective & Topology

This document details the real-world validation of **SECURITY GUARD** actively protecting an independent, standalone external web application (`integration-lab/`) deployed on a separate port without any internal codebase dependencies.

### Architecture Topology
```
[External User / Attacker]
           |
           v (Port 8080)
+-------------------------------------------------------------+
| SECURITY GUARD Monitoring Gateway                           |
| - Route: /site/site_integration_lab/*                        |
| - Pre-inspection Normalization (recursive decode)           |
| - Adaptive Decision Check (Web App :3000 / Engine :5000)   |
+-------------------------------------------------------------+
           |
          / \
    [Allowed]     [Blocked (ENFORCE & Risk >= 70)]
        /               \
       v                 v
+------------------+  +-------------------------------+
| Target Web App   |  | Gateway 403 Forbidden Response|
| Integration Lab  |  | "X-Security-Guard-Enforced"   |
| (Port 4005)      |  +-------------------------------+
+------------------+
```

---

## 2. Target Application Architecture (`integration-lab/`)

The validation web application is a standalone Enterprise Research Portal (`integration-lab/server.js`) providing:
1. **Health Verification Endpoint**: `GET /health`
2. **Search Articles**: `GET /api/articles?q=search_term`
3. **Public Comments / Feedback Form**: `POST /api/comments`
4. **Author Profiles**: `GET /api/profile?id=1`

The application runs independently and has **zero Security Guard code** embedded within it, demonstrating that SECURITY GUARD functions as a true **technology-independent WAF / Reverse Proxy**.

---

## 3. End-to-End Validation Protocol & Verified Results

The validation protocol executes 9 automated verification steps (`web-app/tests/integration_lab.test.js`):

| Step | Action | Method / URL | Expected Result | Actual Result | Status |
|:---:|---|---|---|---|:---:|
| **1** | External Registration | `POST /api/websites/external` | Status 201 Created; mode: `MONITOR_ONLY` | 201 Created, secret generated | **PASS** |
| **2** | Health Check Verification | `POST /api/websites/:id/verify` | Upstream probe returns 200, status `HEALTHY` | `HEALTHY` confirmed | **PASS** |
| **3** | Benign Proxy Routing | `GET /site/:id/api/articles?q=security` | Forwarded through Gateway (200 OK) | 200 OK, upstream payload returned | **PASS** |
| **4** | Passive Attack Audit | `GET /site/:id/api/articles?q=%2527%20OR%201%3D1--` | Permitted to upstream; alert logged | 200 OK, telemetry alert raised | **PASS** |
| **5** | Switch to ENFORCE Mode | `PATCH /api/websites/:id` | Status 200; mode updated to `ENFORCE` | `ENFORCE` confirmed | **PASS** |
| **6** | Benign Traffic in ENFORCE | `GET /site/:id/api/articles?q=zero+trust` | Permitted through Gateway (200 OK) | 200 OK, zero false drops | **PASS** |
| **7** | Active Block: SQLi | `GET /site/:id/api/articles?q=%27%20OR%201%3D1--` | Gateway intercept (403 Forbidden) | **403 Forbidden**, drop verified | **PASS** |
| **8** | Active Block: XSS | `GET /site/:id/api/articles?q=%3Cscript%3Ealert(1)%3C/script%3E` | Gateway intercept (403 Forbidden) | **403 Forbidden**, drop verified | **PASS** |
| **9** | Audit Evidence Verification | `GET /api/monitoring/evidence?websiteId=:id` | Evidence records with risk scores $\ge 70$ | Evidence records retrieved | **PASS** |

---

## 4. Academic Demonstration Runbook

To run the standalone lab site manually during live evaluation:
```powershell
# 1. Start Integration Lab target application on port 4005
cd D:\BM&ATTT\security-guard\integration-lab
node server.js

# 2. Test direct access (bypassing security guard)
curl http://127.0.0.1:4005/health

# 3. Test through Gateway in ENFORCE mode
# Benign request:
curl -i http://127.0.0.1:8080/site/site_integration_lab/api/articles?q=security

# SQL Injection Attack (Blocked 403):
curl -i "http://127.0.0.1:8080/site/site_integration_lab/api/articles?q=%27%20OR%201%3D1--"

# XSS Attack (Blocked 403):
curl -i "http://127.0.0.1:8080/site/site_integration_lab/api/articles?q=%3Cscript%3Ealert(1)%3C/script%3E"
```
