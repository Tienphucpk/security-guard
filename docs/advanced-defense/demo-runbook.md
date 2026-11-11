# Defense Demonstration Runbook: Security Guard

This runbook guides instructors, evaluators, and presenters through a live, end-to-end demonstration of the 4 core capabilities of **SECURITY GUARD**:
1. **Hybrid Detection** (Rule + Isolation Forest)
2. **Adaptive Defense & Evidence Aggregation** (Synergy Bonus & Cap)
3. **Practical In-Line Prevention** (SQLi & XSS Gateway Drop)
4. **Experimental Benchmark Validation** (Empirical Comparison)

---

## 1. Environment Startup

Open a PowerShell terminal and verify running background services:
```powershell
cd D:\BM&ATTT\security-guard

# 1. Verify PostgreSQL Database
# Port 5432: security_guard

# 2. Verify / Start Python Detection Engine (Port 5000)
cd detection-engine
.\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 5000

# 3. Verify / Start Web Application (Port 3000)
cd ..\web-app
node src/server.js

# 4. Verify / Start Monitoring Gateway (Port 8080)
cd ..\gateway
node server.js

# 5. Start Integration Lab Portal (Port 4005)
cd ..\integration-lab
node server.js

# 6. Start Dashboard (Port 5173)
cd ..\dashboard
npm run dev
```

---

## 2. Interactive Demonstration Scenarios

### Scenario 1: Accessing the Protected Standalone Portal (Benign Traffic)
Open browser or terminal to probe the Integration Lab through the Gateway:
```powershell
curl -i http://127.0.0.1:8080/site/site_demo_node/api/products
```
**Expected Observation:**
- HTTP `200 OK`
- Header: `X-Security-Guard-Monitored: ACTIVE`
- Dashboard: Request logged cleanly, Risk Score $< 15$, Decision: `ALLOW`.

---

### Scenario 2: Passive Monitoring vs. Active Enforcement (SQL Injection)

#### Step 2A: Passive Monitoring (`MONITOR_ONLY`)
```powershell
# Set website mode to MONITOR_ONLY via Dashboard UI or API
# Execute SQL Injection attack through Gateway:
curl -i "http://127.0.0.1:8080/site/site_demo_node/search?q=' OR 1=1--"
```
**Expected Observation:**
- Upstream returns HTTP `200 OK` (Traffic permitted in monitor mode).
- Dashboard: New Security Alert `SQL_INJECTION` raised in real-time via SSE.
- Evidence Panel: Risk score $\ge 80.0$, Decision: `MONITOR`.

#### Step 2B: Active Enforcement (`ENFORCE`)
Switch mode to `ENFORCE` in Dashboard Website Management panel.
```powershell
# Re-send identical SQL Injection attack:
curl -i "http://127.0.0.1:8080/site/site_demo_node/search?q=' OR 1=1--"
```
**Expected Observation:**
- **HTTP 403 Forbidden** returned immediately by Gateway.
- Header: `X-Security-Guard-Enforced: BLOCK`.
- JSON body confirms: `"status": "blocked"`, `"matched_rule": "SQL_INJECTION"`.
- Upstream Node.js application was completely shielded and received zero traffic.

---

### Scenario 3: Multi-Encoding Normalization Evasion Bypass Test
Attackers try to evade regex signatures using double URL encoding:
```powershell
# Double-encoded payload: %2527%20OR%201%3D1-- (%2527 unmasks to %27, then to ')
curl -i "http://127.0.0.1:8080/site/site_demo_node/search?q=%2527%20OR%201%3D1--"
```
**Expected Observation:**
- Normalizer de-obfuscates the payload before inspection.
- Gateway intercepts and returns **HTTP 403 Forbidden**.
- Evidence Panel displays unmasked payload and detection rationale.

---

### Scenario 4: Cross-Site Scripting (XSS) In-Line Interception
```powershell
curl -i "http://127.0.0.1:8080/site/site_demo_node/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
```
**Expected Observation:**
- Gateway intercepts and returns **HTTP 403 Forbidden**.
- Reason: `Detected Attack [XSS_ATTACK]`.

---

### Scenario 5: Viewing Empirical Benchmark Results
1. Navigate to Dashboard: `http://localhost:5173`.
2. Click **"📊 Xem Kết Quả Benchmark Thực Nghiệm"**.
3. Inspect:
   - **So Sánh 3 Phương Pháp**: Accuracy (93.67% vs 91.67% vs 82.00%), F1-Score (89.50% vs 85.71% vs 63.51%).
   - **Ma Trận Nhầm Lẫn**: Direct TP, FP, TN, FN numbers.
   - **Nghiên Cứu Triệt Tiêu (Ablation Study)**: Proof of contribution of normalizer and ML synergy.
