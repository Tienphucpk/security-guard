# Adaptive Hybrid Defense: Evidence Aggregation, Risk Scoring & Policy Decision

## 1. Overview & Architecture

The **Adaptive Hybrid Defense** subsystem upgrades SECURITY GUARD from a static signature matcher into an evidence-driven, multi-layered threat assessment and active enforcement engine.

```
                           +----------------------------------------+
                           |           Incoming Request             |
                           +----------------------------------------+
                                               |
                                               v
                           +----------------------------------------+
                           | 1. Normalization & De-obfuscation Layer |
                           |  - Recursive URL Decoding (%2527 -> ') |
                           |  - HTML Entity Decode (&lt; -> <)      |
                           |  - SQL Comment Removal (UN/**/ION)     |
                           |  - Sensitive Header & Token Redaction  |
                           +----------------------------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |    2. Administrative Policy Check      |
                           |       (Explicit ALLOW / BLOCK)         |
                           +----------------------------------------+
                                          /          \
                         [Explicit Match]             [No Policy Override]
                                        /              \
                                       v                v
                  +-------------------------+     +-------------------------------+
                  | Policy Direct Override  |     |  3. Parallel Threat Analysis  |
                  | ALLOW -> Action: ALLOW  |     |  - Deterministic Rules (8)    |
                  | BLOCK -> Action: BLOCK  |     |  - Isolation Forest (ML)      |
                  +-------------------------+     +-------------------------------+
                                                                |
                                                                v
                                                  +-------------------------------+
                                                  | 4. Adaptive Risk Synthesizer  |
                                                  |  - Evidence Fusion & Bonus    |
                                                  |  - ML Anomaly Bounded Cap     |
                                                  |  - Threat Correlation         |
                                                  +-------------------------------+
                                                                |
                                                                v
                                                  +-------------------------------+
                                                  | 5. Mode-Aware Enforcement     |
                                                  |  - ENFORCE: 403 on Risk >= 70 |
                                                  |  - MONITOR_ONLY: Audit & 200  |
                                                  |  - Audit Evidence Persisted   |
                                                  +-------------------------------+
```

---

## 2. Evidence Fusion & Mathematical Formulation

### 2.1 Limitations of Standalone ML in Production WAFs
Machine learning anomaly detectors (such as Isolation Forest) evaluate the *geometric density* of requests within feature space ($\mathcal{X} \subset \mathbb{R}^d$):

$$s(\mathbf{x}, n) = 2^{-\frac{E(h(\mathbf{x}))}{c(n)}}$$

Where:
- $h(\mathbf{x})$ is the path length of observation $\mathbf{x}$ across trees.
- $c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$ is the average path length of unsuccessful searches in Binary Search Trees.

A statistical outlier indicates that a request geometry (e.g. unusually long path, high query parameter count, or unusual character entropy) deviates from the training baseline distribution. **However, geometric deviation does not equate to malicious intent.** For instance:
- A benign user submitting a detailed markdown article or large JSON payload will exhibit high entropy and path length.
- If an unsupervised anomaly detector had autonomous authority to drop packets, it would cause unacceptable **False Positive Denial of Service** on legitimate traffic.

### 2.2 Synergistic Evidence Fusion Formula
To address this challenge, SECURITY GUARD implements a mathematically bounded **Synergistic Evidence Fusion Model**:

$$\mathcal{R}(\mathbf{x}) = \min\left(100.0, \; \mathcal{S}_{\text{rule}}(\mathbf{x}) + \mathcal{B}_{\text{synergy}}(\mathbf{x})\right)$$

Where:

1. **Rule Base Score** $\mathcal{S}_{\text{rule}}(\mathbf{x})$:
   $$\mathcal{S}_{\text{rule}}(\mathbf{x}) = \max_{r \in \mathcal{H}_{\text{rules}}} \text{SeverityScore}(r)$$
   - `CRITICAL` (e.g., SQLi UNION / Stacked Queries, Command Injection): $90.0$
   - `HIGH` (e.g., Reflected XSS, Path Traversal `../..`): $75.0$
   - `MEDIUM` (e.g., Abnormal Scanner, Brute Force threshold): $50.0$
   - `LOW` (e.g., Suspicious URL pattern): $25.0$
   - `NONE`: $0.0$

2. **Synergistic Corroboration Bonus** $\mathcal{B}_{\text{synergy}}(\mathbf{x})$:
   When both a deterministic signature and an Isolation Forest anomaly fire concurrently, the statistical anomaly corroborates the signature match:
   $$\mathcal{B}_{\text{synergy}}(\mathbf{x}) = \begin{cases} 
   \omega_{\text{ml}} \cdot \mathcal{C}_{\text{ml}}(\mathbf{x}) & \text{if } |\mathcal{H}_{\text{rules}}| > 0 \land \mathcal{C}_{\text{ml}}(\mathbf{x}) \ge 50.0 \\ 
   0 & \text{otherwise} 
   \end{cases}$$
   *(Default synergy weight $\omega_{\text{ml}} = 0.15$)*

3. **Standalone ML Anomaly Bounding (Anti-False-Positive Guard)**:
   When no deterministic rule hits, but the Isolation Forest flags an anomaly ($\mathcal{C}_{\text{ml}} > 0$):
   $$\mathcal{R}_{\text{ml\_only}}(\mathbf{x}) = \min\left(48.0, \; 0.48 \cdot \mathcal{C}_{\text{ml}}(\mathbf{x})\right)$$
   Because $48.0 < \mathcal{T}_{\text{block}} = 70.0$, **an isolated ML anomaly can never trigger an active block by itself**. It will trigger `MONITOR` telemetry and audit logging, alerting analysts without disrupting benign users.

4. **Benign Baseline**:
   When neither rules nor ML flag the request:
   $$\mathcal{R}_{\text{benign}}(\mathbf{x}) = \max\left(0.0, \; 0.10 \cdot \mathcal{C}_{\text{ml}}(\mathbf{x})\right) < 15.0$$

---

## 3. Decision Matrix & Mode Enforcement

The final enforcement action depends on the calculated risk score $\mathcal{R}$ and the website's administrative monitoring mode:

| Risk Score Range $\mathcal{R}$ | Rule Matches Present? | `MONITOR_ONLY` Action | `ENFORCE` Action | HTTP Status | Rationale |
|---|---|---|---|---|---|
| **$70.0 \le \mathcal{R} \le 100.0$** | Yes (CRITICAL / HIGH) | `ALLOW` (Audit: `ALLOWED_MONITOR`) | `BLOCK` (Audit: `BLOCKED`) | `403 Forbidden` (Enforce) / `200 OK` (Monitor) | Confirmed high-severity attack signature. Active drop in enforce mode. |
| **$35.0 \le \mathcal{R} < 70.0$** | Medium / Isolated ML | `ALLOW` (Audit: `ALLOWED_MONITOR`) | `ALLOW` (Audit: `MONITOR`) | `200 OK` | Suspicious behavioral anomaly or low-risk pattern. Telemetry logged. |
| **$0.0 \le \mathcal{R} < 35.0$** | No | `ALLOW` | `ALLOW` | `200 OK` | Normal request conforming to expected distribution. |

---

## 4. Multi-Layer Normalization & De-obfuscation

Attackers frequently leverage encoding bypasses to evade signature scanners. The normalizer operates prior to inspection:

1. **Recursive URL Decoding**: Unmasks nested percent-encoding (e.g. `%2527` $\to$ `%27` $\to$ `'`).
2. **HTML Entity Normalization**: Translates entities like `&lt;script&gt;` into `<script>`.
3. **SQL Comment Token Stripping**: Normalizes split keywords (e.g. `UN/**/ION` $\to$ `UNION`, `SEL/**/ECT` $\to$ `SELECT`).
4. **Header and Secret Redaction**: Replaces `Authorization: Bearer ...`, `Cookie: connect.sid=...`, and sensitive parameters with `[REDACTED]` before evidence storage to maintain zero secret leakage.

---

## 5. Audit Trail & Evidence Schema

Every evaluated request generates an immutable evidence entry in PostgreSQL table `detection_evidence`:

```sql
SELECT id, request_id, website_id, rule_matches, rule_severity, 
       ml_anomaly_score, risk_score, decision, decision_reason, processing_time_ms
FROM detection_evidence 
ORDER BY timestamp DESC LIMIT 5;
```

This ensures complete auditability, explainability, and forensic readiness for incident responders and academic evaluation.
