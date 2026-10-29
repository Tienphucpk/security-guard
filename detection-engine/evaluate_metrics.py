"""
Phase 5.5 - Security Detection Metrics & Latency Benchmark Script
Calculates True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN),
Precision, Recall, F1-Score, and Detection Latency (ms) across the 6 Rule Categories.
"""

import time
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from analyzer.rule_engine import RuleEngine
from analyzer.detectors.brute_force import BruteForceDetector
from analyzer.detectors.scanner import ScannerDetector
from analyzer.detectors.abnormal_traffic import AbnormalTrafficDetector
from analyzer.detectors.suspicious_url import SuspiciousUrlDetector
from analyzer.detectors.sql_injection import SqlInjectionDetector
from analyzer.detectors.xss import XssDetector


def benchmark_group(name, detector, positive_cases, negative_cases):
    tp, fp, tn, fn = 0, 0, 0, 0
    latencies = []

    # 1. Evaluate Positive Cases (Expected: detected is True)
    for case in positive_cases:
        t0 = time.perf_counter()
        if isinstance(case, list):
            res = None
            for sub_case in case:
                res = detector.evaluate(sub_case)
        else:
            res = detector.evaluate(case)
        lat = (time.perf_counter() - t0) * 1000.0  # ms
        latencies.append(lat)

        if res is not None:
            tp += 1
        else:
            fn += 1

    # 2. Evaluate Negative Cases (Expected: detected is False / None)
    for case in negative_cases:
        t0 = time.perf_counter()
        if isinstance(case, list):
            res = None
            for sub_case in case:
                res = detector.evaluate(sub_case)
        else:
            res = detector.evaluate(case)
        lat = (time.perf_counter() - t0) * 1000.0  # ms
        latencies.append(lat)

        if res is None:
            tn += 1
        else:
            fp += 1

    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "group": name,
        "positive_tests": len(positive_cases),
        "negative_tests": len(negative_cases),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "avg_latency_ms": round(avg_latency, 3),
        "min_latency_ms": round(min(latencies), 3) if latencies else 0.0,
        "max_latency_ms": round(max(latencies), 3) if latencies else 0.0
    }


def main():
    engine = RuleEngine()
    engine.reset_state()

    results = []

    # 1. Brute Force
    bf_detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
    bf_pos = [
        [{"ip": f"10.0.1.{i}", "method": "POST", "url": "/login", "statusCode": 401} for _ in range(5)]
        for i in range(5)
    ]
    bf_neg = [
        # Exactly 4 attempts (boundary)
        [{"ip": f"10.0.2.{i}", "method": "POST", "url": "/login", "statusCode": 401} for _ in range(4)]
        for i in range(3)
    ] + [
        # Successful logins 200
        [{"ip": f"10.0.3.{i}", "method": "POST", "url": "/login", "statusCode": 200} for _ in range(6)]
        for i in range(2)
    ] + [
        # GET logins
        [{"ip": f"10.0.4.{i}", "method": "GET", "url": "/login", "statusCode": 401} for _ in range(6)]
        for i in range(2)
    ]
    results.append(benchmark_group("Brute Force (RULE-BF-001)", bf_detector, bf_pos, bf_neg))

    # 2. Scanner Detection
    scanner_detector = ScannerDetector()
    scanner_pos = [
        {"userAgent": "sqlmap/1.7#stable", "url": "/search"},
        {"userAgent": "Nikto/2.1.6", "url": "/"},
        {"userAgent": "Nmap Scripting Engine", "url": "/"},
        {"userAgent": "DirBuster-1.0-RC1", "url": "/"},
        {"userAgent": "gobuster/3.5", "url": "/"},
        {"userAgent": "WPScan v3.8.22", "url": "/"},
        {"userAgent": "masscan/1.3.2", "url": "/"}
    ]
    scanner_neg = [
        {"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36", "url": "/"},
        {"userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0", "url": "/"},
        {"userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) Mobile/15E148 Safari/604.1", "url": "/"},
        {"userAgent": "curl/7.88.1", "url": "/"},
        {"userAgent": "PostmanRuntime/7.36.1", "url": "/"}
    ]
    results.append(benchmark_group("Scanner Detection (RULE-SCAN-001)", scanner_detector, scanner_pos, scanner_neg))

    # 3. Abnormal Traffic
    traffic_detector = AbnormalTrafficDetector({"threshold": 100, "window_seconds": 60})
    traffic_pos = [
        [{"ip": f"10.1.1.{k}", "url": "/search", "timestamp": time.time() + (i * 0.1)} for i in range(101)]
        for k in range(3)
    ]
    traffic_neg = [
        # Boundary 100 requests (not > 100)
        [{"ip": f"10.1.2.{k}", "url": "/search", "timestamp": time.time() + (i * 0.1)} for i in range(100)]
        for k in range(3)
    ] + [
        # Excluded health paths (150 requests)
        [{"ip": f"10.1.3.{k}", "url": "/api/health", "timestamp": time.time() + (i * 0.1)} for i in range(150)]
        for k in range(2)
    ]
    results.append(benchmark_group("Abnormal Traffic (RULE-TRAFFIC-001)", traffic_detector, traffic_pos, traffic_neg))

    # 4. Suspicious URL Probing
    url_detector = SuspiciousUrlDetector()
    url_pos = [
        {"url": "/.env"},
        {"url": "/.git/head"},
        {"url": "/.git/config"},
        {"url": "/wp-login.php"},
        {"url": "/web.config"},
        {"url": "/config.php"},
        {"url": "/phpinfo.php"},
        {"url": "/.ds_store"},
        {"url": "/server-status"},
        {"url": "/.env?backup=true"}
    ]
    url_neg = [
        {"url": "/"},
        {"url": "/search?q=environment"},
        {"url": "/about-us"},
        {"url": "/api/health"},
        {"url": "/login"},
        {"url": "/docs/readme.txt"},
        {"url": "/products/list"}
    ]
    results.append(benchmark_group("Suspicious URL (RULE-URL-001)", url_detector, url_pos, url_neg))

    # 5. SQL Injection
    sqli_detector = SqlInjectionDetector()
    sqli_pos = [
        {"url": "/search?q=' OR '1'='1"},
        {"url": "/search?q=' OR 1=1--"},
        {"url": "/products?cat=1' UNION SELECT username, password FROM users--"},
        {"url": "/search?q=admin' AND SLEEP(5)--"},
        {"url": "/search?q=1; WAITFOR DELAY '0:0:5'--"},
        {"url": "/api/query?table=information_schema.columns"},
        {"url": "/search?q=%27%20OR%201%3D1"},
        {"url": "/api/users", "method": "POST", "body": "{\"filter\": \"' OR 1=1--\"}"}
    ]
    sqli_neg = [
        {"url": "/search?q=european union economic report"},
        {"url": "/search?q=sleep disorders and therapy"},
        {"url": "/search?q=apples or oranges"},
        {"url": "/search?q=database design principles"},
        {"url": "/profile?id=123"},
        {"url": "/items?category=books"}
    ]
    results.append(benchmark_group("SQL Injection (RULE-SQLI-001)", sqli_detector, sqli_pos, sqli_neg))

    # 6. Cross-Site Scripting (XSS)
    xss_detector = XssDetector()
    xss_pos = [
        {"url": "/search?q=<script>alert('XSS')</script>"},
        {"url": "/search?q=<img src=x onerror=alert(1)>"},
        {"url": "/search?q=<svg onload=alert(document.cookie)>"},
        {"url": "/search?q=javascript:alert(1)"},
        {"url": "/search?q=<iframe src='http://evil.com'></iframe>"},
        {"url": "/search?q=<ScRiPt src=evil.js></sCrIpt>"},
        {"url": "/search?q=<svg/onload=confirm(1)>"},
        {"url": "/search?q=<BODY ONLOAD=alert(1)>"}
    ]
    xss_neg = [
        {"url": "/search?q=learn javascript programming"},
        {"url": "/search?q=theater script writing tips"},
        {"url": "/search?q=x < y and y > z"},
        {"url": "/articles?topic=ecmascript"},
        {"url": "/docs/index.html"},
        {"url": "/blog/web-development-trends"}
    ]
    results.append(benchmark_group("Cross-Site Scripting (RULE-XSS-001)", xss_detector, xss_pos, xss_neg))

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
