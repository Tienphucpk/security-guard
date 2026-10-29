"""
Detection Engine API Unit & Integration Tests
"""

import unittest
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import get_health, analyze_request, RequestLogPayload, analyze_batch_requests, BatchAnalysisPayload, get_rules


class TestDetectionEngineAPI(unittest.TestCase):

    def test_health_endpoint(self):
        result = get_health()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["service"], "detection-engine")
        self.assertEqual(result["version"], "1.0.0")

    def test_get_rules_endpoint(self):
        result = get_rules()
        self.assertEqual(result["status"], "ok")
        self.assertIsInstance(result["rules"], list)
        self.assertGreaterEqual(len(result["rules"]), 6)
        rule_categories = [r["category"].upper() for r in result["rules"]]
        self.assertIn("SQL_INJECTION", rule_categories)
        self.assertIn("XSS", rule_categories)
        self.assertIn("SCANNER_DETECTION", rule_categories)
        self.assertIn("BRUTE_FORCE", rule_categories)

    def test_analyze_normal_request(self):
        payload = RequestLogPayload(
            timestamp="2026-10-08T08:00:00.000Z",
            ip="127.0.0.1",
            method="GET",
            url="/search?q=normal_keyword",
            statusCode=200,
            userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            responseTime=25.0
        )
        result = analyze_request(payload)
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["risk_score"], 0.0)
        self.assertFalse(result["detected"])
        self.assertEqual(len(result["detections"]), 0)

    def test_analyze_sql_injection(self):
        payload = RequestLogPayload(
            url="/search?q=' OR '1'='1",
            ip="192.168.1.10",
            method="GET",
            statusCode=200
        )
        result = analyze_request(payload)
        self.assertTrue(result["detected"])
        self.assertGreaterEqual(result["risk_score"], 80.0)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["detections"][0]["type"], "SQL_INJECTION")

    def test_analyze_empty_and_null_fields(self):
        # Ensure engine never crashes on null, empty, or missing fields
        payload = RequestLogPayload(url=None, ip=None, userAgent=None)
        result = analyze_request(payload)
        self.assertFalse(result["detected"])
        self.assertEqual(result["risk_score"], 0.0)

    def test_analyze_batch_endpoint(self):
        logs = [
            RequestLogPayload(url="/", ip="127.0.0.1", statusCode=200),
            RequestLogPayload(url="/search?q=<script>alert(1)</script>", ip="10.0.0.5", statusCode=200)
        ]
        batch_payload = BatchAnalysisPayload(logs=logs)
        result = analyze_batch_requests(batch_payload)
        self.assertEqual(result["total_processed"], 2)
        self.assertEqual(result["anomalies_detected"], 1)
        self.assertEqual(len(result["results"]), 2)
        self.assertFalse(result["results"][0]["detected"])
        self.assertTrue(result["results"][1]["detected"])

    def test_ml_status_endpoint(self):
        from main import get_ml_status
        res = get_ml_status()
        self.assertEqual(res["status"], "ok")
        self.assertIn("mode", res)
        self.assertTrue(res["model_loaded"])
        self.assertEqual(res["model_version"], "1.0.0")

    def test_ml_shadow_mode_behavior(self):
        # In shadow mode, ML evaluates and returns ml_result but does not set detected=True on its own
        os.environ["DETECTION_ML_MODE"] = "shadow"
        payload = RequestLogPayload(
            url="/api/query?param=" + ("Z" * 1500),
            ip="10.1.2.3",
            statusCode=400,
            responseTime=350.0
        )
        result = analyze_request(payload)
        self.assertIn("ml_result", result)
        self.assertEqual(result["ml_result"]["mode"], "shadow")
        self.assertTrue(result["ml_result"]["is_anomaly"])
        # Should NOT trigger rule-based alert in shadow mode if no rules matched
        self.assertFalse(result["detected"])

    def test_ml_active_mode_behavior(self):
        # In active mode, ML anomaly promotes detected=True with ML_ANOMALY type
        os.environ["DETECTION_ML_MODE"] = "active"
        payload = RequestLogPayload(
            url="/api/query?param=" + ("Z" * 1500),
            ip="10.1.2.3",
            statusCode=400,
            responseTime=350.0
        )
        result = analyze_request(payload)
        self.assertTrue(result["detected"])
        self.assertEqual(result["ml_result"]["mode"], "active")
        detection_types = [d["type"] for d in result["detections"]]
        self.assertIn("ML_ANOMALY", detection_types)

        # Restore default shadow mode
        os.environ["DETECTION_ML_MODE"] = "shadow"


if __name__ == "__main__":
    unittest.main()
