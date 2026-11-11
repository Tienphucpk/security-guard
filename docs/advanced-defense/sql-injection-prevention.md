# Practical Prevention: SQL Injection (SQLi) Defense In-Depth

## 1. Vulnerability Analysis & Attack Mechanics

SQL Injection (SQLi) occurs when untrusted user input is concatenated directly into SQL command strings, allowing an attacker to manipulate the database parser's Abstract Syntax Tree (AST).

### 1.1 Attack Classes Evaluated
1. **Classic / Tautology-Based**: `' OR '1'='1`, `' OR 1=1--`
2. **UNION-Based Extraction**: `' UNION SELECT id, username, password FROM users--`
3. **Time-Based Blind**: `' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--`
4. **Stacked Queries**: `'; DROP TABLE audit_logs;--`
5. **Evasion & Obfuscation**:
   - Double URL Encoding: `%2527%2520OR%25201%253D1--`
   - Inline SQL Comment Splitting: `UN/**/ION/**/SEL/**/ECT`
   - Whitespace Substitution: `SELECT/**/username/**/FROM/**/users`

---

## 2. In-Line Gateway & WAF Defense (SECURITY GUARD Implementation)

In SECURITY GUARD, in-line defense is executed at the **Technology-Independent Gateway** (Port 8080) and **Policy Engine**:

```
[Attacker Payload]
       |
       v
+--------------------------------------------------------------+
| Gateway Normalization (Recursive Unquote + Comment Strip)    |
| Example: %2527 -> %27 -> '                                   |
| Example: UN/**/ION -> UNION                                  |
+--------------------------------------------------------------+
       |
       v
+--------------------------------------------------------------+
| Hybrid Risk Evaluation                                       |
| - Deterministic Detector: RULE-SQLI-001 (Patterns match)     |
| - Isolation Forest ML: Anomaly score calculated              |
| - Adaptive Risk Score: R >= 90.0 (CRITICAL)                  |
+--------------------------------------------------------------+
       |
      / \
[ENFORCE Mode]       [MONITOR_ONLY Mode]
     /                     \
    v                       v
403 Forbidden          Forward to Upstream
Payload Dropped        Log Alert & Evidence
Database Untouched     Database Vulnerable
```

### 2.1 Gateway Response in ENFORCE Mode
When `monitoring_mode = 'ENFORCE'`, the Gateway intercepts the request before it reaches the application layer or database:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-Security-Guard-Enforced: BLOCK
X-Request-Id: gw-1730730000000-a1b2c3d4

{
  "status": "blocked",
  "error": "Forbidden by Security Guard",
  "website_id": "site_demo_node",
  "client_ip": "198.51.100.77",
  "target_path": "/api/products?search=%27%20OR%201%3D1--",
  "reason": "Detected Attack [SQL_INJECTION]: SQL injection signatures detected in requested URL, query parameter, or payload",
  "mode": "ENFORCE",
  "matched_rule": "SQL_INJECTION",
  "timestamp": "2026-11-04T14:15:00.000Z"
}
```

---

## 3. Application-Layer Remediation vs. Gateway Filtering

A core criterion of academic rigor in BM&ATTT is distinguishing **perimeter filtering** from **definitive root-cause remediation**:

| Dimension | Gateway / WAF Perimeter Defense (SECURITY GUARD) | Application-Layer Root Cause Defense (Prepared Statements) |
|---|---|---|
| **Mechanism** | Regex inspection, payload normalization, statistical anomaly scoring. | Separates SQL command code from data binding at the database protocol level. |
| **Enforcement Point** | Reverse Proxy / Ingress Gateway (Port 8080). | Database Client Driver / ORM (Node.js pg, Python asyncpg, Hibernate). |
| **Zero-Day Resistance** | Partial; unknown zero-day syntax variations may bypass heuristic filters. | **Complete**; input is strictly treated as scalar literal data, never executed as code. |
| **Legacy Compatibility** | **High**; protects heterogeneous legacy sites without code changes. | Requires refactoring source code and database query invocations. |
| **Overhead** | ~0.5ms - 2.5ms gateway proxy and inspection latency. | Negligible; prepared statement caching often improves DB throughput. |

### 3.1 Recommended Application-Layer Implementation

#### Vulnerable Code (Anti-Pattern):
```javascript
// DANGEROUS: String concatenation creates executable AST nodes
const query = `SELECT * FROM products WHERE name LIKE '%${req.query.search}%'`;
const result = await db.query(query);
```

#### Secure Code (Parameterized Queries):
```javascript
// SECURE: Parameter binding treats input as pure data literal
const query = 'SELECT * FROM products WHERE name ILIKE $1';
const result = await db.query(query, [`%${req.query.search}%`]);
```

In Python / psycopg2:
```python
# SECURE: Database engine handles escaping and parsing independently
cursor.execute("SELECT * FROM products WHERE name ILIKE %s", (f"%{search_term}%",))
```

---

## 4. Verification Matrix

| Test Scenario | Payload | Mode | Result | Verified Metric |
|---|---|---|---|---|
| Plain SQLi | `?id=1' OR '1'='1` | ENFORCE | 403 Forbidden | Blocked at Gateway |
| Double URL Encoded | `?search=%2527%20OR%201%3D1--` | ENFORCE | 403 Forbidden | De-obfuscated & Blocked |
| Inline Comment Obfuscation | `?q=UN/**/ION/**/SELECT` | ENFORCE | 403 Forbidden | Normalized & Blocked |
| Benign Search | `?search=laptop` | ENFORCE | 200 OK | Allowed, Risk < 15 |
| Passive Audit | `?id=1' OR 1=1` | MONITOR_ONLY | 200 OK | Forwarded, Alert Raised |
