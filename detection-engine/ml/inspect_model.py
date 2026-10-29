"""
Model Inspection Utility for Isolation Forest Anomaly Detection
Inspects model metadata, feature importances/tree structures, and tests
predictive inference on typical sample inputs.
"""

import os
import sys
import json
import logging
from typing import Dict, Any

from .isolation_forest_model import IsolationForestAnomalyDetector
from .feature_extractor import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml.inspect")


def inspect_model() -> None:
    detector = IsolationForestAnomalyDetector(auto_load=True)

    print("\n" + "=" * 60)
    print("         ISOLATION FOREST MODEL INSPECTION")
    print("=" * 60)

    if not detector.is_available():
        print("Status: MODEL NOT LOADED / NOT FOUND")
        print("Expected artifact: models/isolation_forest_v1.joblib")
        print("Expected metadata: models/model_metadata.json")
        print("=" * 60 + "\n")
        return

    print("Status               : LOADED & READY")
    print(f"Model Path           : {detector.model_path}")
    print(f"Metadata Path        : {detector.metadata_path}")
    print(f"Model Version        : {detector.metadata.get('model_version')}")
    print(f"Created At           : {detector.metadata.get('created_at')}")
    print(f"Feature Schema Ver   : {detector.metadata.get('feature_schema_version')}")
    print(f"Features Count       : {len(detector.metadata.get('feature_names', []))}")
    print(f"Hyperparameters      : {json.dumps(detector.metadata.get('hyperparameters', {}), indent=2)}")
    print(f"Effective Threshold  : {detector.metadata.get('effective_threshold')}")
    print("-" * 60)
    print("Sample Inferences:")

    test_cases = [
        {"name": "Normal Home Request", "log": {"url": "/", "method": "GET", "statusCode": 200, "responseTime": 15.0}},
        {"name": "Normal Search Query", "log": {"url": "/search?q=laptop", "method": "GET", "statusCode": 200, "responseTime": 22.0}},
        {"name": "SQL Injection Attack", "log": {"url": "/search?q=' OR '1'='1", "method": "GET", "statusCode": 200, "responseTime": 300.0}},
        {"name": "XSS Script Attack", "log": {"url": "/search?q=<script>alert(1)</script>", "method": "GET", "statusCode": 200, "responseTime": 20.0}},
        {"name": "Scanner User-Agent", "log": {"url": "/api/users", "method": "GET", "statusCode": 200, "userAgent": "sqlmap/1.7#stable"}},
        {"name": "Sensitive File Probe", "log": {"url": "/.env", "method": "GET", "statusCode": 404, "responseTime": 10.0}}
    ]

    for tc in test_cases:
        res = detector.predict_log(tc["log"])
        status_tag = "[ANOMALY]" if res.get("is_anomaly") else "[NORMAL] "
        print(f"  {status_tag} {tc['name']:<24} -> Score: {res.get('anomaly_score'):5.1f} | Raw: {res.get('raw_score'):7.4f}")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    inspect_model()
