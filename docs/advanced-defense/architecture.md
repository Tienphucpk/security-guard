# SECURITY GUARD — System Architecture & Component Interaction Specification

## 1. System Overview

**SECURITY GUARD** is an advanced hybrid web application anomaly monitoring, detection, and active enforcement system developed for the Information Security & Assurance (BM&ATTT) capstone defense.

It unifies:
1. **Multi-Website Monitoring Gateway** (Port 8080): Technology-independent reverse proxy inspecting HTTP traffic in-flight.
2. **Web Application & Policy Controller** (Port 3000): Central management API, PostgreSQL audit logs, RBAC authentication, and SSE broadcast.
3. **Detection Engine** (Port 5000): Python FastAPI service with 8 deterministic rule-based detectors and an Isolation Forest unsupervised anomaly model.
4. **Adaptive Risk Scorer & Evidence Aggregator**: In-memory synthesis engine calculating calibrated risk scores and enforcing allow/block decisions.
5. **Real-Time SOC Dashboard** (Port 5173): React / Vite single-page application with live metrics, alerts, evidence inspection, and benchmark analysis.
6. **PostgreSQL Relational Store** (Port 5432): Durable multi-tenant database `security_guard`.

---

## 2. End-to-End Architecture Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                    CLIENT / ATTACKER / BROWSER                                     |
+----------------------------------------------------------------------------------------------------+
                   |                                                              |
                   | In-flight HTTP Traffic (:8080)                               | Management Web UI (:5173)
                   v                                                              v
+--------------------------------------+                       +-------------------------------------+
|        MONITORING GATEWAY            |                       |        REACT SOC DASHBOARD          |
|            (Port 8080)               |                       |            (Port 5173)              |
| - Reverse Proxy Router               |                       | - Live Alert Feed (SSE)             |
| - Recursive Normalizer               |                       | - Adaptive Evidence Audit Panel     |
| - In-line 403 Dropper                |                       | - Experimental Benchmark Modal      |
+--------------------------------------+                       +-------------------------------------+
           |                     ^                                                |
           | Evaluate Decision   | Policy Decision (ALLOW/BLOCK)                  | REST / Session Cookie
           v                     |                                                v
+----------------------------------------------------------------------------------------------------+
|                                   WEB APP & POLICY CONTROLLER                                      |
|                                           (Port 3000)                                              |
| - Route: POST /api/monitoring/decision                                                             |
| - Route: POST /api/ingest/events                                                                   |
| - Recursive URL, HTML & SQL Comment Normalizer                                                     |
| - Administrative Policy Evaluator (Priority 1)                                                     |
| - Adaptive Evidence Aggregator & Calibrated Risk Scorer (Priority 2)                                |
| - SSE Real-time Broadcast Bus                                                                      |
+----------------------------------------------------------------------------------------------------+
           |                                                              |
           | Analyze Request (:5000)                                      | Read / Write Persistence
           v                                                              v
+--------------------------------------+                       +-------------------------------------+
|       PYTHON DETECTION ENGINE        |                       |        POSTGRESQL DATABASE          |
|            (Port 5000)               |                       |            (Port 5432)              |
| - 8 Deterministic Rule Detectors     |                       | - request_logs                      |
|   (SQLi, XSS, Trav, CmdI, Brute,...) |                       | - security_alerts                   |
| - Isolation Forest ML Model          |                       | - detection_evidence                |
| - Feature Geometry Extractor         |                       | - registered_websites               |
+--------------------------------------+                       | - enforcement_audit_logs            |
                                                               +-------------------------------------+
```

---

## 3. Data Flow & Decision Lifecycle

```
[Gateway :8080] Receives Request -> Reads Host / Path Prefix -> Resolves Target Website
       |
       +---> [Web App :3000] POST /api/monitoring/decision
                 |
                 +---> 1. Normalization: Recursive unquote, entity decode, comment removal
                 +---> 2. Check Administrative Policies (ALLOW / BLOCK overrides)
                 +---> 3. Dispatch to [Detection Engine :5000] POST /analyze
                 |         |---> Rule Detectors (Pattern Regex)
                 |         +---> Isolation Forest (Geometry Anomaly Score)
                 +---> 4. Adaptive Scorer computes Risk R(x) = min(100, RuleScore + ML_Bonus)
                 +---> 5. Persist Immutable Evidence into `detection_evidence`
                 +---> 6. Return Decision (action: ALLOW | BLOCK, statusCode: 200 | 403)
       |
       v
[Gateway :8080] Acts on Decision:
   - If BLOCK (and mode == 'ENFORCE'): Drops request immediately with 403 Forbidden
   - If ALLOW (or mode == 'MONITOR_ONLY'): Forwards to Upstream Application (:4001, :4002, :4005)
```

---

## 4. Multi-Tenant Website & Mode Model

Each monitored website possesses an explicit operational state:
- **`MONITOR_ONLY` (Passive Defense)**:
  - All attacks are detected, risk-scored, and recorded in `security_alerts` and `detection_evidence`.
  - Upstream traffic is never dropped (`action: 'ALLOW'`), allowing security analysts to observe adversary actions in stealth.
- **`ENFORCE` (Active Defense)**:
  - Verified attacks ($R \ge 70.0$) and administrative block policies trigger immediate TCP/HTTP termination with `403 Forbidden` and `X-Security-Guard-Enforced: BLOCK`.
  - Benign traffic passes unimpeded with zero false drops.
