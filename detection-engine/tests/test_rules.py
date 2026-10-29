"""
Unit Tests for Rule-Based Anomaly Detection Engines & Detectors
"""

import unittest
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.rule_engine import RuleEngine
from analyzer.detectors.brute_force import BruteForceDetector
from analyzer.detectors.scanner import ScannerDetector
from analyzer.detectors.abnormal_traffic import AbnormalTrafficDetector
from analyzer.detectors.suspicious_url import SuspiciousUrlDetector
from analyzer.detectors.sql_injection import SqlInjectionDetector
from analyzer.detectors.xss import XssDetector
from analyzer.risk_scorer import RiskScorer


class TestDetectionRules(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine()
        self.engine.reset_state()

    # -------------------------------------------------------------
    # 1. Brute Force Detection Tests
    # -------------------------------------------------------------
    def test_brute_force_below_threshold(self):
        detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
        # 4 failed login attempts
        for _ in range(4):
            res = detector.evaluate({
                "ip": "10.0.0.1",
                "method": "POST",
                "url": "/login",
                "statusCode": 401
            })
            self.assertIsNone(res)

    def test_brute_force_meets_threshold(self):
        detector = BruteForceDetector({"threshold": 5, "window_seconds": 300})
        # 4 failed attempts
        for _ in range(4):
            detector.evaluate({
                "ip": "10.0.0.2",
                "method": "POST",
                "url": "/login",
                "statusCode": 401
            })
        # 5th failed attempt triggers BRUTE_FORCE
        res = detector.evaluate({
            "ip": "10.0.0.2",
            "method": "POST",
            "url": "/login",
            "statusCode": 401
        })
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "BRUTE_FORCE")
        self.assertEqual(res["severity"], "HIGH")

    # -------------------------------------------------------------
    # 2. Scanner Detection Tests
    # -------------------------------------------------------------
    def test_scanner_detection_sqlmap(self):
        detector = ScannerDetector()
        res = detector.evaluate({
            "userAgent": "sqlmap/1.6.4#stable (https://sqlmap.org)",
            "url": "/search"
        })
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "SCANNER_DETECTION")
        self.assertEqual(res["matched_pattern"], "sqlmap")

    def test_scanner_detection_nikto_and_nmap(self):
        detector = ScannerDetector()
        for agent in ["Nikto/2.1.6", "Nmap Scripting Engine", "Gobuster v3.1.0"]:
            res = detector.evaluate({"userAgent": agent, "url": "/"})
            self.assertIsNotNone(res)
            self.assertEqual(res["type"], "SCANNER_DETECTION")

    def test_scanner_detection_normal_user_agent(self):
        detector = ScannerDetector()
        res = detector.evaluate({
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
            "url": "/dashboard"
        })
        self.assertIsNone(res)

    # -------------------------------------------------------------
    # 3. Abnormal Traffic Tests
    # -------------------------------------------------------------
    def test_abnormal_traffic_detection(self):
        # Configure a small threshold for fast unit testing
        detector = AbnormalTrafficDetector({"threshold": 10, "window_seconds": 60})
        for i in range(10):
            res = detector.evaluate({"ip": "192.168.1.99", "url": "/api/ping"})
            self.assertIsNone(res)

        # 11th request exceeds threshold 10
        res = detector.evaluate({"ip": "192.168.1.99", "url": "/api/ping"})
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "ABNORMAL_TRAFFIC")
        self.assertEqual(res["severity"], "MEDIUM")

    # -------------------------------------------------------------
    # 4. Suspicious URL Tests
    # -------------------------------------------------------------
    def test_suspicious_url_patterns(self):
        detector = SuspiciousUrlDetector()
        test_cases = [
            ("/.env", "/.env"),
            ("/.git/HEAD", "/.git/head"),
            ("/wp-login.php", "/wp-login.php"),
            ("/config.php", "/config.php"),
            ("/admin/.DS_Store", "/.ds_store")
        ]
        for url, expected_pat in test_cases:
            res = detector.evaluate({"url": url})
            self.assertIsNotNone(res, f"Failed to detect {url}")
            self.assertEqual(res["type"], "SUSPICIOUS_URL")

    def test_normal_url_not_flagged(self):
        detector = SuspiciousUrlDetector()
        res = detector.evaluate({"url": "/api/health"})
        self.assertIsNone(res)

    # -------------------------------------------------------------
    # 5. SQL Injection Tests
    # -------------------------------------------------------------
    def test_sql_injection_patterns(self):
        detector = SqlInjectionDetector()
        payloads = [
            "/search?q=' OR '1'='1",
            "/search?q=1' UNION SELECT username, password FROM users--",
            "/profile?id=5 AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(SLEEP(5)) FROM users)x)",
            "/search?q=%27%20OR%201%3D1", # URL-encoded ' OR 1=1
            "/data?filter=INFORMATION_SCHEMA.TABLES"
        ]
        for payload in payloads:
            res = detector.evaluate({"url": payload})
            self.assertIsNotNone(res, f"Failed on SQLi payload: {payload}")
            self.assertEqual(res["type"], "SQL_INJECTION")

    def test_sql_injection_benign_query(self):
        detector = SqlInjectionDetector()
        res = detector.evaluate({"url": "/search?q=cybersecurity-guard"})
        self.assertIsNone(res)

    # -------------------------------------------------------------
    # 6. XSS Tests
    # -------------------------------------------------------------
    def test_xss_patterns(self):
        detector = XssDetector()
        payloads = [
            "/search?q=<script>alert(1)</script>",
            "/search?q=<img src=x onerror=alert(document.cookie)>",
            "/search?q=javascript:alert('XSS')",
            "/search?q=<svg/onload=alert(1)>",
            "/profile?bio=%3Cscript%3Ealert(document.cookie)%3C/script%3E" # URL encoded
        ]
        for payload in payloads:
            res = detector.evaluate({"url": payload})
            self.assertIsNotNone(res, f"Failed on XSS payload: {payload}")
            self.assertEqual(res["type"], "XSS")

    def test_xss_benign_query(self):
        detector = XssDetector()
        res = detector.evaluate({"url": "/search?q=hello world"})
        self.assertIsNone(res)

    # -------------------------------------------------------------
    # 7. Rule Engine Multi-Rule & Risk Score Capping
    # -------------------------------------------------------------
    def test_multi_rule_evaluation_and_capped_score(self):
        # A request that matches both SQLi and Suspicious URL
        log = {
            "url": "/wp-login.php?user=' OR '1'='1",
            "userAgent": "sqlmap/1.7"
        }
        res = self.engine.analyze(log)
        self.assertTrue(res["detected"])
        types = [d["type"] for d in res["detections"]]
        self.assertIn("SQL_INJECTION", types)
        self.assertIn("SUSPICIOUS_URL", types)
        self.assertIn("SCANNER_DETECTION", types)
        # Sum of scores: 80 + 35 + 60 = 175 -> Capped at 100.0
        self.assertEqual(res["risk_score"], 100.0)
        self.assertEqual(res["severity"], "CRITICAL")

    # -------------------------------------------------------------
    # 8. Rule Enable/Disable Functionality
    # -------------------------------------------------------------
    def test_rule_disable_toggle(self):
        # Disable XSS rule
        self.engine.set_rule_enabled("xss", False)
        res = self.engine.analyze({"url": "/search?q=<script>alert(1)</script>"})
        self.assertFalse(res["detected"])
        self.assertEqual(res["risk_score"], 0.0)

        # Re-enable XSS rule
        self.engine.set_rule_enabled("xss", True)
        res2 = self.engine.analyze({"url": "/search?q=<script>alert(1)</script>"})
        self.assertTrue(res2["detected"])


if __name__ == "__main__":
    unittest.main()
