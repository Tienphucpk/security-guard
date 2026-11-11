# Baseline Audit & Architectural Verification

## 1. Overview
This document records the empirical verification of the SECURITY GUARD repository prior to implementing the **Advanced Hybrid Web Attack Detection, Adaptive Defense & Experimental Validation** upgrade. All assertions in this audit are grounded in direct code inspection and live automated test execution on November 4, 2026.

- **Baseline Test Execution**: `.\scripts\test\test-all.bat`
- **Total Automated Tests**: **202 / 202 PASSED (100.0%)**
  - Web Application & Integration Tests: 121 / 121 PASS
  - Python Detection Engine & Model Tests: 81 / 81 PASS
- **Dashboard Production Build**: `npm run build` completed successfully (34 modules transformed, 0 errors).

---

## 2. Comprehensive Baseline Audit Matrix

| Feature | Existing Implementation | Actual Verification | Test Evidence | Missing Capability | Proposed Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Eight Rule-Based Detectors** | Implemented in `detection-engine/rules/` (`sqli.py`, `xss.py`, `path_traversal.py`, `command_injection.py`, `brute_force.py`, `scanner.py`, `abnormal_traffic.py`, `probe.py`) | Evaluated via `/analyze` and `/analyze/batch` in `detection-engine/main.py`. | 35 unit tests in `test_rules.py` passing | Detection evaluates rules sequentially without explicit adaptive risk fusion with ML features. | Retain all 8 detectors intact; feed rule outputs into an Adaptive Evidence Aggregator. |
| **2. Isolation Forest Anomaly Detection** | `isolation_forest.py` with 11 numerical features extracted by `feature_extractor.py`, serialized in `isolation_forest_v1.joblib` | Model loads successfully, inference via `model.decision_function(X)`. Calibrated threshold ~ `-0.0260`. | 23 unit tests in `test_isolation_forest.py` + 4 tests in `phase6_ml.test.js` | Anomaly score is raw decision score, not normalized into a probabilistic risk index; no dynamic weighting. | Normalize Isolation Forest decision score into calibrated confidence $[0, 100]$ without false probability equivalence. |
| **3. Three ML Modes** | Configured via `ML_MODE` (`disabled`, `shadow`, `active`) in `detection-engine/config.py` and `main.py` | Verified via `/health` returning `ml_mode: shadow` and shadow logging in `logs/ml_shadow.log`. | `phase6_ml.test.js` tests shadow mode vs active mode | Mode switches globally or statically; lacks per-request adaptive risk escalation. | Maintain full backward compatibility with `disabled`, `shadow`, `active`; introduce an `adaptive` mode. |
| **4. Policy Precedence & Decision Engine** | `web-app/src/services/policyEngine.js` evaluates: (1) Active site check $\to$ (2) Specific website policies (ALLOW/BLOCK) $\to$ (3) Detection Engine analysis | Verified in `policyEngine.js:evaluateDecision()` with explicit priority override. | Tests 10-13 in `phase10_multi_site.test.js` passing | Decisions are binary (ALLOW/BLOCK) based on static rule hit or custom policy; no multi-evidence confidence score. | Upgrade `policyEngine.js` to support Adaptive Risk Scoring combining Rule severity + ML anomaly + behavioral history. |
| **5. Request Flow Gateway $\to$ Detection** | `gateway/server.js` (Port 8080) intercepts requests, calls `POST /api/monitoring/decision` on Web App (3000), forwards to upstream or drops with 403 | Reverse-proxy tested across Node Shop (4001) and Python Portal (4002). | Tests 18-20 in `phase10_multi_site.test.js` | Gateway relies on Web App decision response; no deep multi-encoding normalization (double URL, hex, HTML entity). | Enhance request normalization in Gateway & Detection Engine to decode multi-layered encodings for SQLi and XSS. |
| **6. Website Registry & Integration Methods** | `web-app/src/services/websiteRegistry.js` supporting `REVERSE_PROXY`, `APPLICATION_AGENT`, `LOG_INGESTION` in `monitored_websites` table | Additive migration `06_external_website_integration.sql` verified in PostgreSQL. | 26 tests in `phase11_external_integration.test.js` passing | No independent external integration lab outside `demo-sites/` directory for defense grading. | Establish an independent Express integration lab (`integration-lab/`) to validate end-to-end integration. |
| **7. MONITOR_ONLY vs. ENFORCE Safety** | Controlled by `monitoring_mode` column in `monitored_websites`. `MONITOR_ONLY` never blocks; `ENFORCE` drops with 403 | Inspected in `policyEngine.js` lines 180-220 and `gateway/server.js`. | Test 10 (`MONITOR_ONLY` allows) and Test 11 (`ENFORCE` blocks) passing | Need experimental validation showing False Blocking Rate vs True Blocking Rate in both modes. | Implement benchmark script measuring blocking success rate and false blocking rate. |
| **8. SSE, Alert Lifecycle & RBAC** | `alertStream.js` (SSE stream), `database.js` (`acknowledgeAlert`, `resolveAlert`), `auth.middleware.js` (ADMIN vs ANALYST) | Verified via `GET /api/alerts/stream`, `POST /api/auth/login`, session cookies. | 21 tests in `phase9_user_auth.test.js`, 8 tests in `phase9_auth.test.js` | Dashboard lacks real-time visualization of hybrid evidence and benchmark metrics. | Add Detection Evidence Panel, Prevention Overview, and Benchmark Dashboard to React UI. |
| **9. Database Failure Resilience** | `database.js` handles pool disconnects; `logger.middleware.js` falls back to `logs/requests.log` | Database health check and graceful file-only fallback verified. | Tests 11 & 18 in `server.test.js` passing | Evidence aggregation should persist cleanly even when database is degraded. | Retain graceful file logging and fail-open resilience in all new components. |
| **10. Experimental Validation & Benchmark** | Existing `holdout_dataset_v3.json` evaluated in Phase 8 | Evaluated on static holdout dataset. | Historical reports in `docs/phase-8/` | Lacks formal 3-way benchmark (Rule vs ML vs Hybrid) on standardized Train/Validation/Test split with Ablation Study. | Build `datasets/benchmark/` (train, val, test) and automated runner `scripts/benchmark/run-benchmark.py`. |

---

## 3. Verified Repository Artifacts
- **Web App**: Node.js v24.15.0, Express v4.21.2, pg v8.23.1, bcryptjs v3.0.3, cookie-parser v1.4.7
- **Detection Engine**: Python 3.12, FastAPI 0.115.0, Uvicorn 0.31.0, Scikit-Learn 1.5.2, Joblib 1.4.2
- **Dashboard**: React 18, Vite 5.4.21, production bundle 214.95 kB (gzip: 62.07 kB)
- **Database**: PostgreSQL 16 on port 5432 (`security_guard`) with migrations 02 to 06 applied
- **Gateway**: Node.js reverse-proxy on port 8080 with SSRF protection (`ssrfValidator.js`)
