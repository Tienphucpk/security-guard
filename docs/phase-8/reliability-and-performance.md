# SECURITY GUARD — Phase 8 Reliability and Performance Report

## 1. Benchmarking Methodology & Test Environment

- **Host Operating System**: Windows 11 Enterprise (AMD64)
- **Runtime Versions**: Node.js v22.14.0, Python 3.13.13 (CPython), FastAPI 0.115, Uvicorn 0.34
- **Database Engine**: PostgreSQL 18.1 (Native Service on port 5432)
- **Evaluation Dataset**: `holdout_dataset_unseen_v3.json` (80 independent, out-of-sample samples)
- **Warm-up Requests**: 10 requests executed before metric collection
- **Measured Iterations**: 2 cycles (160 requests total)
- **Profiling Tool**: Standard `time.perf_counter()` and Python standard library `tracemalloc`

---

## 2. Empirical Latency Profiles

Measurements collected via `detection-engine/tests/test_e2e_performance.py`:

| Layer / Measurement | Mean Latency | Median ($p_{50}$) | 95th %ile ($p_{95}$) | 99th %ile ($p_{99}$) | Min | Max |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Rule Engine (8 Rules)** | 0.494 ms | **0.398 ms** | 0.929 ms | 1.523 ms | 0.163 ms | 3.173 ms |
| **ML Inference (Isolation Forest)** | 80.153 ms | **73.098 ms** | 110.344 ms | 128.029 ms | 39.818 ms | 134.865 ms |
| **Combined Detection Pipeline** | 80.647 ms | **73.518 ms** | 110.922 ms | 129.162 ms | 39.981 ms | 135.599 ms |
| **End-to-End HTTP RTT (Web App)** | 9.571 ms | **3.755 ms** | 28.129 ms | 29.702 ms | 2.539 ms | 59.108 ms |

### Key Observations:
1. **Rule Engine Efficiency**: The 8 deterministic detection rules execute in **sub-millisecond time ($p_{50} = 0.398$ ms)**.
2. **Asynchronous Architecture Benefits**: The Web App returns responses to end-users in **3.755 ms ($p_{50}$)** because detection forwarding occurs asynchronously via non-blocking HTTP dispatch without impeding page delivery.
3. **Engine Throughput**: Achieved **11.05 req/sec** under synchronous sequential execution on local developer hardware.
4. **Reliability Metrics**:
   - Total HTTP Requests Completed: **160 / 160**
   - HTTP Error Rate: **0.0%**
   - Timeout Rate: **0.0%**
5. **Memory Footprint**:
   - Baseline process memory: **1.1 MB**
   - Peak traced memory during batch inference: **3.12 MB**

---

## 3. Failure-Recovery & Degradation Scenarios

The system was evaluated against 6 major operational failure scenarios:

| Failure Scenario | Evaluated Behavior | Outcome |
|---|---|:---:|
| **1. Database Unreachable (Port 5432 down)** | Web App logs warning and immediately falls back to reading/writing `requests.log` and `alerts.log`. Web server continues serving pages without crashing. | **PASS** (Graceful Degradation) |
| **2. Detection Engine Offline (Port 5000 down)** | `detectionClient` catches connection failure or timeout within 1500ms; suppresses noisy exceptions; writes alerts to disk; web requests complete normally. | **PASS** (Zero Client Impact) |
| **3. ML Model Artifact Missing or Corrupted** | `IsolationForestAnomalyDetector` falls back to `is_available = False`, skips ML scoring, returns `is_anomaly = False`, and allows Rule Engine to process requests unhindered. | **PASS** (Rule Precedence Intact) |
| **4. Oversized Payload (> 1 MB)** | Express body-parser rejects request with `413 Payload Too Large`. Memory exhaustion is prevented. | **PASS** (DoS Protected) |
| **5. Malformed Client JSON Syntax** | Express body-parser catches `SyntaxError` and returns `400 Bad Request` with structured JSON message. Server does not crash. | **PASS** (Clean Error Handling) |
| **6. SSE Subscriber Disconnect & Reconnect** | `alertStream` cleans up dead sockets from active client Set on `close` event, allowing clients to reconnect seamlessly without resource leakage. | **PASS** (Leak-free SSE) |

---

## 4. Reproducibility Instructions

To reproduce these measurements on Windows:
```powershell
# 1. Start Detection Engine on port 5000
Set-Location 'D:\BM&ATTT\security-guard\detection-engine'
.\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 5000

# 2. In a separate terminal, start Web App on port 3000
Set-Location 'D:\BM&ATTT\security-guard\web-app'
node src/server.js

# 3. Run End-to-End Performance Benchmark
Set-Location 'D:\BM&ATTT\security-guard\detection-engine'
.\venv\Scripts\python.exe tests/test_e2e_performance.py
```
Output data is automatically exported to `detection-engine/data/performance_report_phase8.json`.
