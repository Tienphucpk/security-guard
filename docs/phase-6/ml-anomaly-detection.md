# Phase 6 Implementation Report: Machine Learning-Based Anomaly Detection

## 1. Overview & Objectives

In Phase 6, **SECURITY GUARD** integrates an unsupervised Machine Learning pipeline based on **Isolation Forest (`sklearn.ensemble.IsolationForest`)** alongside the existing six rule-based detectors from Phases 1–5.

The primary goal of Phase 6 is to provide adaptive, statistical anomaly detection capable of uncovering zero-day anomalies, abnormal query payloads, and subtle behavioral outliers without disrupting or replacing the high-confidence deterministic rules.

```text
HTTP Request
     ↓
Express Web App (Port 3000)
     ↓
Logging Middleware
     ↓
PostgreSQL / request_logs
     ↓
Detection Engine (Port 5000)
  ├── 1. Rule-Based Detectors (SQLi, XSS, Brute Force, Scanner, etc.)
  └── 2. ML Isolation Forest Detector (11 Numeric Features)
     ↓
Alert Correlation & Deduplication (60s window, rule precedence)
     ↓
PostgreSQL / security_alerts (alert_type: 'ML_ANOMALY' or Correlated Rule)
     ↓
Server-Sent Events (SSE /api/alerts/stream)
     ↓
React Dashboard (Port 5173 - ML Status, Badging, and Metrics)
```

---

## 2. Feature Engineering & Schema

The ML module extracts a fixed, deterministic vector of **11 numerical features** from HTTP request logs. Raw IP addresses, session cookies, and sensitive tokens are strictly excluded to prevent overfitting and data leakage.

| # | Feature Name | Type | Description |
|---|--------------|------|-------------|
| 1 | `method_code` | float | Stable numeric encoding (`GET`: 0, `POST`: 1, `PUT`: 2, `DELETE`: 3, `PATCH`: 4, `HEAD`: 5, `OPTIONS`: 6) |
| 2 | `status_code` | float | HTTP response status code (e.g. 200.0, 400.0, 401.0, 404.0) |
| 3 | `response_time_ms` | float | Request duration clipped to [0, 60000] ms |
| 4 | `url_length` | float | Total character length of unquoted URL |
| 5 | `query_length` | float | Length of URL query parameters |
| 6 | `special_char_count` | float | Occurrences of special symbols (`'`, `"`, `<`, `>`, `%`, `(`, `)`, `;`, etc.) |
| 7 | `suspicious_token_count`| float | Occurrences of sensitive probes / attack tokens (`.env`, `.git`, `union`, `sqlmap`, etc.) |
| 8 | `ua_length` | float | Length of User-Agent header string |
| 9 | `path_depth` | float | Directory hierarchy depth of URL path |
| 10 | `rolling_req_count_60s` | float | Request rate for client IP in a 60-second sliding window |
| 11 | `rolling_failed_login_300s`| float | Failed authentication attempts for client IP in a 300-second window |

### Internal Telemetry Exclusion
Internal monitoring endpoints (`/api/health`, `/api/logs`, `/api/alerts`) are automatically bypassed by the feature extractor and model inference to ensure monitoring polling never triggers false positives.

---

## 3. Machine Learning Model Architecture

- **Algorithm**: `IsolationForest(n_estimators=100, contamination=0.03, random_state=42)`
- **Artifact Location**: `detection-engine/models/isolation_forest_v1.joblib`
- **Metadata Location**: `detection-engine/models/model_metadata.json`
- **Score Calibration**:
  - `decision_function` values $< 0$ denote statistical anomalies.
  - Anomaly score is mapped to a human-interpretable $0.0 - 100.0$ scale:
    - Normal requests: $0.0 - 50.0$
    - Anomalies / Outliers: $60.0 - 100.0$
- **Resilient Fallback**: If the model artifact is missing or corrupted, the engine safely degrades with `model_available: false` and `anomaly_score: 0.0` without crashing or interrupting the rule-based detection pipeline.

---

## 4. Operating Modes

Configurable via the environment variable `DETECTION_ML_MODE`:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `disabled` | ML inference is bypassed completely. | Minimal resource usage. |
| `shadow` *(Default)* | ML model evaluates all requests, records scores and features into metadata/telemetry, but does NOT create user-facing alerts. | Safe model evaluation & baseline profiling in production. |
| `active` | ML model evaluates requests and generates `ML_ANOMALY` security alerts when score $\ge 60.0$. | Production threat defense. |

---

## 5. Alert Correlation & Deduplication

1. **Correlation Precedence**: When both a specific rule detector (e.g. `SQL_INJECTION`) and the ML detector fire on the same request, the rule-based detector takes precedence as the primary `alertType`. The ML result is attached inside `alert.details.ml_result`.
2. **Deduplication Window**: In `active` mode, duplicate `ML_ANOMALY` alerts for the same `sourceIp:targetUrl` within a 60-second window (`ML_DEDUP_WINDOW_MS=60000`) are automatically suppressed to eliminate alert fatigue.

---

## 6. Evaluation & Benchmark Results

Evaluated against labeled holdout datasets consisting of benign baseline web application traffic and attack vectors (SQL Injection, XSS, Scanner UAs, Sensitive file probes, and Brute Force):

```text
============================================================
      ISOLATION FOREST MODEL EVALUATION REPORT
============================================================
Total Evaluated Samples : 20
True Positives (TP)     : 9
True Negatives (TN)     : 10
False Positives (FP)    : 0
False Negatives (FN)    : 1
------------------------------------------------------------
Accuracy                : 95.00%
Precision               : 100.00%
Recall                  : 90.00%
F1 Score                : 0.9474
------------------------------------------------------------
Avg Inference Latency   : 12.691 ms
p95 Inference Latency   : 16.258 ms
============================================================
```

---

## 7. Automated Test Suite Summary

Total automated tests: **93/93 PASS (100%)**

1. **Detection Engine (Python - 59 tests)**:
   - `test_rules.py`: 12 rule tests
   - `test_phase5_rules.py`: 24 positive, negative, and boundary tests
   - `test_api.py`: 9 API, health, and ML mode tests
   - `test_feature_extractor.py`: 8 feature engineering & rolling window tests
   - `test_isolation_forest.py`: 7 model serialization, calibration, and fallback tests

2. **Web Application (Node.js - 34 tests)**:
   - `app.test.js`: 12 Web App and logging tests
   - `alerts.test.js`: 12 Alert lifecycle and pagination tests
   - `phase5_e2e.test.js`: 6 End-to-End and real-time SSE stream tests
   - `phase6_ml.test.js`: 4 ML shadow mode, active mode, deduplication, and correlation tests
