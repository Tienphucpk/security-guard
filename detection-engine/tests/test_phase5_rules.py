"""
Phase 5.2 - Security Testing & Rule-Based Detection Boundary Tests
Comprehensive Positive, Negative, and Boundary Verification for all 6 Detection Rules:
1. Brute Force Detection (RULE-BF-001)
2. Security Scanner Detection (RULE-SCAN-001)
3. Abnormal Traffic Rate (RULE-TRAFFIC-001)
4. Suspicious URL Probing (RULE-URL-001)
5. SQL Injection (RULE-SQLI-001)
6. Cross-Site Scripting (RULE-XSS-001)
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.rule_engine import RuleEngine
from analyzer.detectors.brute_force import BruteForceDetector
from analyzer.detectors.scanner import ScannerDetector
from analyzer.detectors.abnormal_traffic import AbnormalTrafficDetector
from analyzer.detectors.suspicious_url import SuspiciousUrlDetector
from analyzer.detectors.sql_injection import SqlInjectionDetector
from analyzer.detectors.xss import XssDetector


class TestPhase5DetectionRules(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine()
        self.engine.reset_state()

    # =========================================================================
    # Group 1: Brute Force Detection
    # Rule: >= 5 failed login attempts (POST /login, status 401) within 300s
    # =========================================================================
    def test_brute_force_positive(self):
        """Positive Test: 5 failed login attempts trigger BRUTE_FORCE alert"""
        detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
        test_ip = "192.168.100.1"
        res = None
        for i in range(5):
            res = detector.evaluate({
                "ip": test_ip,
                "method": "POST",
                "url": "/login",
                "statusCode": 401,
                "timestamp": time.time()
            })
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "BRUTE_FORCE")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["score"], 70.0)
        self.assertEqual(res["rule_id"], "RULE-BF-001")
        self.assertIn("192.168.100.1", res["reason"])

    def test_brute_force_boundary_threshold_minus_one(self):
        """Boundary Test: Exactly 4 attempts (threshold - 1) must NOT trigger alert"""
        detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
        test_ip = "192.168.100.2"
        for i in range(4):
            res = detector.evaluate({
                "ip": test_ip,
                "method": "POST",
                "url": "/login",
                "statusCode": 401,
                "timestamp": time.time()
            })
            self.assertIsNone(res, f"Attempt {i+1} should not trigger detection")

    def test_brute_force_boundary_threshold_exact(self):
        """Boundary Test: Exactly 5th attempt triggers alert"""
        detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
        test_ip = "192.168.100.3"
        for i in range(4):
            self.assertIsNone(detector.evaluate({
                "ip": test_ip, "method": "POST", "url": "/login", "statusCode": 401
            }))
        res = detector.evaluate({
            "ip": test_ip, "method": "POST", "url": "/login", "statusCode": 401
        })
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "BRUTE_FORCE")

    def test_brute_force_negative_successful_logins(self):
        """Negative Test: 10 successful logins (status 200) must NOT trigger alert"""
        detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
        test_ip = "192.168.100.4"
        for _ in range(10):
            res = detector.evaluate({
                "ip": test_ip, "method": "POST", "url": "/login", "statusCode": 200
            })
            self.assertIsNone(res)

    def test_brute_force_negative_get_method(self):
        """Negative Test: GET /login returning 401 must NOT trigger brute force (requires POST)"""
        detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
        test_ip = "192.168.100.5"
        for _ in range(6):
            res = detector.evaluate({
                "ip": test_ip, "method": "GET", "url": "/login", "statusCode": 401
            })
            self.assertIsNone(res)

    # =========================================================================
    # Group 2: Scanner Detection
    # Signatures: sqlmap, nikto, nmap, dirbuster, gobuster, wpscan, masscan
    # =========================================================================
    def test_scanner_positive_all_signatures(self):
        """Positive Test: All 7 supported automated scanner User-Agents are detected"""
        detector = ScannerDetector()
        signatures = [
            ("sqlmap/1.7#stable", "sqlmap"),
            ("Mozilla/5.0 Nikto/2.1.6", "nikto"),
            ("Nmap Scripting Engine (https://nmap.org)", "nmap"),
            ("DirBuster-1.0-RC1", "dirbuster"),
            ("gobuster/3.5", "gobuster"),
            ("WPScan v3.8.22", "wpscan"),
            ("masscan/1.3.2", "masscan")
        ]
        for ua, expected_sig in signatures:
            res = detector.evaluate({"userAgent": ua, "url": "/test"})
            self.assertIsNotNone(res, f"Scanner signature {expected_sig} failed to trigger")
            self.assertEqual(res["type"], "SCANNER_DETECTION")
            self.assertEqual(res["matched_pattern"], expected_sig)
            self.assertEqual(res["score"], 60.0)
            self.assertEqual(res["severity"], "HIGH")

    def test_scanner_boundary_case_insensitivity(self):
        """Boundary Test: Case-insensitive detection (e.g. SQLMAP, GoBuster)"""
        detector = ScannerDetector()
        res1 = detector.evaluate({"userAgent": "SQLMAP/1.6", "url": "/"})
        self.assertIsNotNone(res1)
        self.assertEqual(res1["matched_pattern"], "sqlmap")

        res2 = detector.evaluate({"userAgent": "GoBuster/3.1", "url": "/"})
        self.assertIsNotNone(res2)
        self.assertEqual(res2["matched_pattern"], "gobuster")

    def test_scanner_negative_legitimate_browsers(self):
        """Negative Test: Standard browsers (Chrome, Firefox, Safari, Edge, Mobile) must NOT trigger"""
        detector = ScannerDetector()
        legit_uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
            "curl/7.88.1",
            "PostmanRuntime/7.36.1"
        ]
        for ua in legit_uas:
            res = detector.evaluate({"userAgent": ua, "url": "/"})
            self.assertIsNone(res, f"Legitimate UA {ua} was falsely flagged")

    # =========================================================================
    # Group 3: Abnormal Traffic Rate
    # Rule: > 100 requests / 60 seconds from same IP (excluding internal health/logs)
    # =========================================================================
    def test_abnormal_traffic_positive(self):
        """Positive Test: Exceeding threshold triggers ABNORMAL_TRAFFIC"""
        detector = AbnormalTrafficDetector({"threshold": 100, "window_seconds": 60})
        test_ip = "192.168.200.1"
        now = time.time()
        res = None
        # Send 101 requests
        for i in range(101):
            res = detector.evaluate({
                "ip": test_ip,
                "url": "/search?q=test",
                "timestamp": now + (i * 0.1)
            })
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "ABNORMAL_TRAFFIC")
        self.assertEqual(res["severity"], "MEDIUM")
        self.assertEqual(res["score"], 40.0)

    def test_abnormal_traffic_boundary_exact_threshold(self):
        """Boundary Test: Exactly 100 requests (threshold) does NOT trigger (> 100 required)"""
        detector = AbnormalTrafficDetector({"threshold": 100, "window_seconds": 60})
        test_ip = "192.168.200.2"
        now = time.time()
        for i in range(100):
            res = detector.evaluate({
                "ip": test_ip,
                "url": "/api/items",
                "timestamp": now + (i * 0.1)
            })
            self.assertIsNone(res, f"Request {i+1} should not trigger (> 100 required)")

    def test_abnormal_traffic_boundary_one_above_threshold(self):
        """Boundary Test: Exactly 101st request triggers alert"""
        detector = AbnormalTrafficDetector({"threshold": 100, "window_seconds": 60})
        test_ip = "192.168.200.3"
        now = time.time()
        for i in range(100):
            detector.evaluate({
                "ip": test_ip, "url": "/api/items", "timestamp": now + (i * 0.1)
            })
        # 101st request
        res = detector.evaluate({
            "ip": test_ip, "url": "/api/items", "timestamp": now + 10.1
        })
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "ABNORMAL_TRAFFIC")

    def test_abnormal_traffic_negative_excluded_telemetry_routes(self):
        """Negative Test: High frequency internal telemetry routes (/api/health, /api/logs) do not trigger"""
        detector = AbnormalTrafficDetector({"threshold": 100, "window_seconds": 60})
        test_ip = "192.168.200.4"
        now = time.time()
        for i in range(150):
            res = detector.evaluate({
                "ip": test_ip,
                "url": "/api/health",
                "timestamp": now + (i * 0.1)
            })
            self.assertIsNone(res, "Health telemetry route should be excluded")

    # =========================================================================
    # Group 4: Suspicious URL Probing
    # Patterns: /.env, /.git/head, /.git/config, /wp-login.php, /web.config, /config.php, /phpinfo.php, /.ds_store, /server-status
    # =========================================================================
    def test_suspicious_url_positive_all_patterns(self):
        """Positive Test: All 9 suspicious target probe files are identified"""
        detector = SuspiciousUrlDetector()
        targets = [
            ("/.env", "/.env"),
            ("/.git/head", "/.git/head"),
            ("/.git/config", "/.git/config"),
            ("/wp-login.php", "/wp-login.php"),
            ("/web.config", "/web.config"),
            ("/config.php", "/config.php"),
            ("/phpinfo.php", "/phpinfo.php"),
            ("/.ds_store", "/.ds_store"),
            ("/server-status", "/server-status")
        ]
        for url, pat in targets:
            res = detector.evaluate({"url": url})
            self.assertIsNotNone(res, f"Target probe {url} failed to trigger")
            self.assertEqual(res["type"], "SUSPICIOUS_URL")
            self.assertEqual(res["matched_pattern"], pat)
            self.assertEqual(res["score"], 35.0)
            self.assertEqual(res["severity"], "MEDIUM")

    def test_suspicious_url_boundary_with_query_params(self):
        """Boundary Test: Target probe with complex query parameters e.g. /.env?version=1.0"""
        detector = SuspiciousUrlDetector()
        res = detector.evaluate({"url": "/.env?backup=true&format=raw"})
        self.assertIsNotNone(res)
        self.assertEqual(res["matched_pattern"], "/.env")

    def test_suspicious_url_negative_benign_urls(self):
        """Negative Test: Benign application URLs e.g. /search, /profile, /products"""
        detector = SuspiciousUrlDetector()
        benign_urls = [
            "/",
            "/search?q=environment",
            "/about-us",
            "/api/health",
            "/login",
            "/docs/readme.txt"
        ]
        for url in benign_urls:
            res = detector.evaluate({"url": url})
            self.assertIsNone(res, f"Benign URL {url} was falsely flagged")

    # =========================================================================
    # Group 5: SQL Injection Detection
    # Patterns: ' OR 1=1, union select, information_schema., sleep(, benchmark(, waitfor delay
    # =========================================================================
    def test_sql_injection_positive_patterns(self):
        """Positive Test: Classic and modern SQLi attack vectors are detected"""
        detector = SqlInjectionDetector()
        vectors = [
            "/search?q=' OR '1'='1",
            "/search?q=' OR 1=1--",
            "/products?cat=1' UNION SELECT username, password FROM users--",
            "/search?q=admin' AND SLEEP(5)--",
            "/search?q=1; WAITFOR DELAY '0:0:5'--",
            "/api/query?table=information_schema.columns"
        ]
        for v in vectors:
            res = detector.evaluate({"url": v})
            self.assertIsNotNone(res, f"SQLi vector failed: {v}")
            self.assertEqual(res["type"], "SQL_INJECTION")
            self.assertEqual(res["score"], 80.0)
            self.assertEqual(res["severity"], "HIGH")

    def test_sql_injection_boundary_in_post_body(self):
        """Boundary Test: SQL injection payload inside POST body payload"""
        detector = SqlInjectionDetector()
        res = detector.evaluate({
            "url": "/api/users",
            "method": "POST",
            "body": "{\"filter\": \"' OR 1=1--\"}"
        })
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "SQL_INJECTION")

    def test_sql_injection_negative_benign_queries(self):
        """Negative Test: Regular queries mentioning words 'union', 'sleep', or 'or' in normal prose"""
        detector = SqlInjectionDetector()
        benign = [
            "/search?q=european union economic report",
            "/search?q=sleep disorders and therapy",
            "/search?q=apples or oranges",
            "/search?q=database design principles"
        ]
        for url in benign:
            res = detector.evaluate({"url": url})
            self.assertIsNone(res, f"Benign query falsely flagged as SQLi: {url}")

    # =========================================================================
    # Group 6: Cross-Site Scripting (XSS)
    # Patterns: <script>, </script>, onload=, onerror=, javascript:, <iframe, <svg, document.cookie
    # =========================================================================
    def test_xss_positive_patterns(self):
        """Positive Test: Classic and event-handler XSS attack vectors are detected"""
        detector = XssDetector()
        vectors = [
            "/search?q=<script>alert('XSS')</script>",
            "/search?q=<img src=x onerror=alert(1)>",
            "/search?q=<svg onload=alert(document.cookie)>",
            "/search?q=javascript:alert(1)",
            "/search?q=<iframe src='http://evil.com'></iframe>"
        ]
        for v in vectors:
            res = detector.evaluate({"url": v})
            self.assertIsNotNone(res, f"XSS vector failed: {v}")
            self.assertEqual(res["type"], "XSS")
            self.assertEqual(res["score"], 75.0)
            self.assertEqual(res["severity"], "HIGH")

    def test_xss_boundary_mixed_case_and_obfuscated_tag(self):
        """Boundary Test: Mixed-case and spacing tags e.g. <sCrIpt >, <svg/onload=...>"""
        detector = XssDetector()
        vectors = [
            "/search?q=<ScRiPt src=evil.js></sCrIpt>",
            "/search?q=<svg/onload=confirm(1)>",
            "/search?q=<BODY ONLOAD=alert(1)>"
        ]
        for v in vectors:
            res = detector.evaluate({"url": v})
            self.assertIsNotNone(res, f"Obfuscated XSS vector failed: {v}")
            self.assertEqual(res["type"], "XSS")

    def test_xss_negative_benign_text(self):
        """Negative Test: Safe text mentioning 'script', 'javascript', or '<' in math"""
        detector = XssDetector()
        benign = [
            "/search?q=learn javascript programming",
            "/search?q=theater script writing tips",
            "/search?q=x < y and y > z",
            "/articles?topic=ecmascript"
        ]
        for url in benign:
            res = detector.evaluate({"url": url})
            self.assertIsNone(res, f"Benign text falsely flagged as XSS: {url}")


if __name__ == "__main__":
    unittest.main()
