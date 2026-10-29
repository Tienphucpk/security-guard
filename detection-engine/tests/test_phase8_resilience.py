"""
Phase 8 Resilience, Input Sanitization & Security Validation Test Suite
Tests input size limits, malformed inputs, missing model fallbacks,
and feature vector stability.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from analyzer.rule_engine import RuleEngine
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.feature_extractor import FeatureExtractor


class TestPhase8Resilience(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_batch_payload_exceeding_500_items_rejected(self):
        """Phase 8.2: Batch API rejects requests exceeding 500 items with 400 Bad Request"""
        logs = [{"url": f"/item?id={i}", "method": "GET", "statusCode": 200} for i in range(501)]
        res = self.client.post("/analyze/batch", json={"logs": logs})
        self.assertEqual(res.status_code, 400)
        self.assertIn("exceeds maximum limit of 500", res.json()["detail"])

    def test_batch_payload_empty_list_handled(self):
        """Phase 8.3: Empty batch payload completes successfully with total_processed = 0"""
        res = self.client.post("/analyze/batch", json={"logs": []})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_processed"], 0)
        self.assertEqual(data["anomalies_detected"], 0)
        self.assertEqual(len(data["results"]), 0)

    def test_extreme_numerical_inputs_clipped_without_crash(self):
        """Phase 8.3: Extreme response time and query length are safely clipped without throwing NaN"""
        extractor = FeatureExtractor(track_history=False)
        extreme_sample = {
            "url": "/search?q=" + ("X" * 10000),
            "method": "GET",
            "statusCode": 99999,
            "responseTime": 9999999999.0,
            "userAgent": "A" * 5000
        }
        vec = extractor.extract_vector(extreme_sample)
        self.assertEqual(len(vec), 11)
        # response_time_ms is clipped to [0, 60000]
        self.assertLessEqual(vec[2], 60000.0)
        # Ensure no NaN or Inf
        for val in vec:
            self.assertFalse(val != val, "Vector contains NaN")

    def test_missing_model_graceful_fallback(self):
        """Phase 8.3: Detector with non-existent artifact path degrades gracefully without throwing"""
        detector = IsolationForestAnomalyDetector(
            model_path="non/existent/path/model.joblib",
            metadata_path="non/existent/path/meta.json",
            auto_load=False
        )
        self.assertFalse(detector.is_available())
        res = detector.predict_log({"url": "/test", "method": "GET"})
        self.assertFalse(res["is_anomaly"])
        self.assertEqual(res["anomaly_score"], 0.0)
        self.assertFalse(res["model_available"])

    def test_empty_log_entry_analysis(self):
        """Phase 8.3: Completely empty dict sent to /analyze returns status 200 with detected=False"""
        res = self.client.post("/analyze", json={})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["detected"])
        self.assertEqual(data["risk_score"], 0.0)


if __name__ == "__main__":
    unittest.main()
