"""
Unit Tests for Isolation Forest Anomaly Detection Model
Tests model loading, fallback on missing artifact, prediction, score calibration,
internal telemetry exclusion, and training serialization.
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.train import train_model


class TestIsolationForestModel(unittest.TestCase):

    def setUp(self):
        self.detector = IsolationForestAnomalyDetector(auto_load=True)

    def test_model_loaded_successfully(self):
        self.assertTrue(self.detector.is_available())
        self.assertIsNotNone(self.detector.model)
        self.assertEqual(self.detector.metadata.get("model_version"), "1.0.0")

    def test_missing_model_fallback(self):
        detector = IsolationForestAnomalyDetector(
            model_path="non_existent_model.joblib",
            metadata_path="non_existent_metadata.json",
            auto_load=True
        )
        self.assertFalse(detector.is_available())

        res = detector.predict_log({"url": "/test", "method": "GET"})
        self.assertFalse(res["model_available"])
        self.assertFalse(res["is_anomaly"])
        self.assertEqual(res["anomaly_score"], 0.0)
        self.assertEqual(res["model_version"], "none")

    def test_benign_request_prediction(self):
        sample = {
            "url": "/search?q=laptop",
            "method": "GET",
            "statusCode": 200,
            "responseTime": 20.0,
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        res = self.detector.predict_log(sample)
        self.assertTrue(res["model_available"])
        self.assertFalse(res["is_anomaly"])
        self.assertLess(res["anomaly_score"], 50.0)

    def test_anomaly_request_prediction(self):
        sample = {
            "url": "/search?q=' UNION SELECT null, password FROM users--",
            "method": "GET",
            "statusCode": 200,
            "responseTime": 400.0,
            "userAgent": "Mozilla/5.0"
        }
        res = self.detector.predict_log(sample)
        self.assertTrue(res["model_available"])
        self.assertTrue(res["is_anomaly"])
        self.assertGreaterEqual(res["anomaly_score"], 60.0)

    def test_score_calibration_range(self):
        samples = [
            {"url": "/", "method": "GET", "statusCode": 200, "responseTime": 10.0},
            {"url": "/.env", "method": "GET", "statusCode": 404, "responseTime": 15.0},
            {"url": "/api/test?data=" + ("X" * 1000), "method": "POST", "statusCode": 500, "responseTime": 5000.0}
        ]
        for s in samples:
            res = self.detector.predict_log(s)
            self.assertGreaterEqual(res["anomaly_score"], 0.0)
            self.assertLessEqual(res["anomaly_score"], 100.0)

    def test_internal_telemetry_exclusion(self):
        samples = [
            {"url": "/api/health", "method": "GET"},
            {"url": "/api/logs?limit=50", "method": "GET"},
            {"url": "/api/alerts/stream", "method": "GET"}
        ]
        for s in samples:
            res = self.detector.predict_log(s)
            self.assertFalse(res["is_anomaly"])
            self.assertEqual(res["anomaly_score"], 0.0)
            self.assertIn("Internal telemetry", res["reason"])

    def test_training_and_serialization(self):
        temp_dir = tempfile.mkdtemp()
        try:
            saved_path = train_model(
                output_dir=temp_dir,
                n_samples=100,
                n_estimators=10,
                contamination=0.05
            )
            self.assertTrue(os.path.exists(saved_path))
            custom_detector = IsolationForestAnomalyDetector(
                model_path=saved_path,
                metadata_path=os.path.join(temp_dir, "model_metadata.json"),
                auto_load=True
            )
            self.assertTrue(custom_detector.is_available())
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
