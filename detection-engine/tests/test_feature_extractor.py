"""
Unit Tests for ML Feature Extractor
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.feature_extractor import FeatureExtractor, FEATURE_NAMES, FEATURE_SCHEMA_VERSION


class TestFeatureExtractor(unittest.TestCase):

    def setUp(self):
        self.extractor = FeatureExtractor(track_history=True)

    def test_schema_and_ordering(self):
        self.assertEqual(len(FEATURE_NAMES), 11)
        self.assertEqual(FEATURE_SCHEMA_VERSION, "1.0")

        sample = {
            "method": "GET",
            "url": "/search?q=test",
            "statusCode": 200,
            "responseTime": 15.5,
            "userAgent": "Mozilla/5.0",
            "ip": "127.0.0.1"
        }
        vec = self.extractor.extract_vector(sample)
        self.assertEqual(len(vec), 11)
        self.assertTrue(all(isinstance(v, (int, float)) for v in vec))

    def test_method_encoding(self):
        methods = [("GET", 0.0), ("POST", 1.0), ("PUT", 2.0), ("DELETE", 3.0),
                   ("PATCH", 4.0), ("HEAD", 5.0), ("OPTIONS", 6.0), ("UNKNOWN", 7.0)]
        for m, expected in methods:
            d = self.extractor.extract_dict({"method": m})
            self.assertEqual(d["method_code"], expected)

    def test_special_characters_count(self):
        sample = {
            "url": "/search?q=' OR 1=1; <script>#test"
        }
        d = self.extractor.extract_dict(sample)
        # Characters: ' (1), = (1), ; (1), < (1), > (1), # (1) -> 6 special chars
        self.assertGreaterEqual(d["special_char_count"], 5.0)

    def test_missing_and_invalid_fields(self):
        # Empty dictionary should produce safe default numeric values without raising exceptions
        d = self.extractor.extract_dict({})
        self.assertEqual(d["method_code"], 0.0)
        self.assertEqual(d["status_code"], 200.0)
        self.assertEqual(d["response_time_ms"], 0.0)
        self.assertEqual(d["special_char_count"], 0.0)
        self.assertEqual(d["url_length"], 1.0) # "/" default

        vec = self.extractor.extract_vector({})
        self.assertEqual(len(vec), 11)

    def test_suspicious_token_count(self):
        sample_clean = {"url": "/search?q=laptop", "userAgent": "Mozilla/5.0"}
        d_clean = self.extractor.extract_dict(sample_clean)
        self.assertEqual(d_clean["suspicious_token_count"], 0.0)

        sample_probe = {"url": "/.env", "userAgent": "nikto/2.1.6"}
        d_probe = self.extractor.extract_dict(sample_probe)
        self.assertEqual(d_probe["suspicious_token_count"], 2.0)

    def test_response_time_clipping(self):
        d_negative = self.extractor.extract_dict({"responseTime": -100})
        self.assertEqual(d_negative["response_time_ms"], 0.0)

        d_extreme = self.extractor.extract_dict({"responseTime": 9999999})
        self.assertEqual(d_extreme["response_time_ms"], 60000.0)

    def test_rolling_counters(self):
        ip = "192.168.1.55"
        self.extractor.reset_state()

        # Send 3 requests
        for i in range(3):
            d = self.extractor.extract_dict({"ip": ip, "method": "GET", "url": "/"})

        self.assertEqual(d["rolling_req_count_60s"], 3.0)
        self.assertEqual(d["rolling_failed_login_300s"], 0.0)

        # Send 2 failed logins
        for i in range(2):
            d = self.extractor.extract_dict({"ip": ip, "method": "POST", "url": "/login", "statusCode": 401})

        self.assertEqual(d["rolling_failed_login_300s"], 2.0)
        self.assertEqual(d["rolling_req_count_60s"], 5.0)

    def test_telemetry_exclusion(self):
        self.assertTrue(self.extractor.is_internal_telemetry("/api/health"))
        self.assertTrue(self.extractor.is_internal_telemetry("/api/logs?limit=5"))
        self.assertTrue(self.extractor.is_internal_telemetry("/api/alerts/stats"))
        self.assertFalse(self.extractor.is_internal_telemetry("/search?q=test"))
        self.assertFalse(self.extractor.is_internal_telemetry("/login"))


if __name__ == "__main__":
    unittest.main()
