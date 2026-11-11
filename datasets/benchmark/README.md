# Benchmark Datasets: Security Guard Academic Evaluation

## 1. Dataset Provenance & Split Architecture
Standardized evaluation dataset partitions for empirical validation and ablation study:

- `train.jsonl`: 1,400 records (1,200 Benign, 200 Multi-vector Attacks)
- `validation.jsonl`: 300 records (200 Benign, 100 Multi-vector Attacks)
- `test.jsonl`: 300 records (200 Benign, 100 Multi-vector Attacks) - **Held-out for uncorrupted testing**

## 2. Attack Vector Coverage
Evaluated attack distributions across 5 distinct categories:
1. **SQL Injection (SQLi)**: Tautologies, UNION-selects, stacked queries, time-based sleep, comment splitting, and double-URL encoding.
2. **Cross-Site Scripting (XSS)**: Script tags, SVG/IMG onerror event handlers, pseudo-protocols, HTML entities, and iframe injection.
3. **Path Traversal**: Parent directory references (`../`, `..\\`), double-encoded dots (`%252e%252e%252f`), absolute system files.
4. **Command Injection**: Shell metacharacters (`;`, `|`, `&&`, backticks, powershell, /bin/sh).
5. **Credential Stuffing & Brute Force**: Repeated authentication failures, rate limit bursts, dictionary attacks.

## 3. Record Schema
Each line in `*.jsonl` adheres to this schema:
```json
{
  "id": 101,
  "timestamp": "2026-11-04T12:30:15.000Z",
  "ip": "198.51.100.42",
  "method": "GET",
  "url": "/search?q=' OR 1=1--",
  "statusCode": 200,
  "userAgent": "Mozilla/5.0 ...",
  "responseTime": 18.5,
  "category": "ATTACK",
  "label": 1,
  "attack_vector": "sql_injection"
}
```
