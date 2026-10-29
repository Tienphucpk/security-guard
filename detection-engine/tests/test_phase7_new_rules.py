"""
Phase 7 New Detection Rules Tests:
- Path Traversal (RULE-TRAV-001)
- Command Injection (RULE-CMDI-001)
Tests include positive, negative, boundary, and encoding variations.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.detectors.path_traversal import PathTraversalDetector
from analyzer.detectors.command_injection import CommandInjectionDetector
from analyzer.rule_engine import RuleEngine


class TestPhase7NewRules(unittest.TestCase):

    def setUp(self):
        self.trav_detector = PathTraversalDetector()
        self.cmdi_detector = CommandInjectionDetector()
        self.engine = RuleEngine()

    # =========================================================================
    # Path Traversal (RULE-TRAV-001)
    # =========================================================================
    def test_path_traversal_metadata(self):
        self.assertEqual(self.trav_detector.rule_id, "RULE-TRAV-001")
        self.assertEqual(self.trav_detector.category, "PATH_TRAVERSAL")
        self.assertEqual(self.trav_detector.severity, "HIGH")
        self.assertEqual(self.trav_detector.score, 75.0)

    def test_path_traversal_positive_unix(self):
        sample = {"url": "/download?file=../../../../etc/passwd"}
        res = self.trav_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "PATH_TRAVERSAL")
        self.assertEqual(res["rule_id"], "RULE-TRAV-001")

    def test_path_traversal_positive_windows(self):
        sample = {"url": "/files?path=..\\..\\windows\\win.ini"}
        res = self.trav_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "PATH_TRAVERSAL")

    def test_path_traversal_positive_encoded(self):
        sample = {"url": "/read?file=%2e%2e%2f%2e%2e%2fetc%2fshadow"}
        res = self.trav_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "PATH_TRAVERSAL")

    def test_path_traversal_negative_normal_url(self):
        samples = [
            {"url": "/products/item?id=101"},
            {"url": "/static/css/style.css"},
            {"url": "/search?q=relative..dots..in..text"}
        ]
        for s in samples:
            res = self.trav_detector.evaluate(s)
            self.assertIsNone(res, f"Should not trigger traversal on: {s['url']}")

    def test_path_traversal_boundary_disabled(self):
        self.trav_detector.enabled = False
        res = self.trav_detector.evaluate({"url": "/view?file=../../etc/passwd"})
        self.assertIsNone(res)
        self.trav_detector.enabled = True

    # =========================================================================
    # Command Injection (RULE-CMDI-001)
    # =========================================================================
    def test_command_injection_metadata(self):
        self.assertEqual(self.cmdi_detector.rule_id, "RULE-CMDI-001")
        self.assertEqual(self.cmdi_detector.category, "COMMAND_INJECTION")
        self.assertEqual(self.cmdi_detector.severity, "CRITICAL")
        self.assertEqual(self.cmdi_detector.score, 85.0)

    def test_command_injection_positive_semicolon(self):
        sample = {"url": "/api/ping?host=127.0.0.1; whoami"}
        res = self.cmdi_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "COMMAND_INJECTION")
        self.assertEqual(res["rule_id"], "RULE-CMDI-001")

    def test_command_injection_positive_pipe(self):
        sample = {"url": "/api/dns?ip=8.8.8.8 | id"}
        res = self.cmdi_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "COMMAND_INJECTION")

    def test_command_injection_positive_and_operator(self):
        sample = {"url": "/tools/check?target=127.0.0.1 && cat /etc/passwd"}
        res = self.cmdi_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "COMMAND_INJECTION")

    def test_command_injection_positive_subshell(self):
        sample = {"url": "/service?cmd=$(whoami)"}
        res = self.cmdi_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "COMMAND_INJECTION")

    def test_command_injection_positive_powershell(self):
        sample = {"url": "/api/run?arg=1; powershell -enc dGVzdA=="}
        res = self.cmdi_detector.evaluate(sample)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "COMMAND_INJECTION")

    def test_command_injection_negative_normal_request(self):
        samples = [
            {"url": "/search?q=id+card+verification"},
            {"url": "/articles/view?title=who+am+i+essay"},
            {"url": "/tools/calculator?formula=2*3;x=5"}
        ]
        for s in samples:
            res = self.cmdi_detector.evaluate(s)
            self.assertIsNone(res, f"Should not trigger command injection on: {s['url']}")

    def test_command_injection_boundary_disabled(self):
        self.cmdi_detector.enabled = False
        res = self.cmdi_detector.evaluate({"url": "/api/ping?ip=127.0.0.1; whoami"})
        self.assertIsNone(res)
        self.cmdi_detector.enabled = True

    # =========================================================================
    # RuleEngine Integration
    # =========================================================================
    def test_rule_engine_includes_all_eight_detectors(self):
        self.assertEqual(len(self.engine.detectors), 8)
        categories = [d.category for d in self.engine.detectors]
        self.assertIn("PATH_TRAVERSAL", categories)
        self.assertIn("COMMAND_INJECTION", categories)

    def test_rule_engine_analyzes_path_traversal(self):
        log = {"url": "/load?doc=../../../../etc/passwd", "method": "GET"}
        res = self.engine.analyze(log)
        self.assertTrue(res["detected"])
        types = [d["type"] for d in res["detections"]]
        self.assertIn("PATH_TRAVERSAL", types)
        self.assertGreaterEqual(res["risk_score"], 75.0)

    def test_rule_engine_analyzes_command_injection(self):
        log = {"url": "/ping?host=localhost | whoami", "method": "GET"}
        res = self.engine.analyze(log)
        self.assertTrue(res["detected"])
        types = [d["type"] for d in res["detections"]]
        self.assertIn("COMMAND_INJECTION", types)
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertGreaterEqual(res["risk_score"], 85.0)


if __name__ == "__main__":
    unittest.main()
