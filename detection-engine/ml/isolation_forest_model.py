"""
Isolation Forest Anomaly Detection Model Wrapper
Handles model persistence, configuration, inference, calibration, and resilient fallback.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

from .feature_extractor import FeatureExtractor, FEATURE_NAMES, FEATURE_SCHEMA_VERSION

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models"))
DEFAULT_MODEL_FILE = os.path.join(DEFAULT_MODEL_DIR, "isolation_forest_v1.joblib")
DEFAULT_METADATA_FILE = os.path.join(DEFAULT_MODEL_DIR, "model_metadata.json")


class IsolationForestAnomalyDetector:
    def __init__(
        self,
        model_path: Optional[str] = None,
        metadata_path: Optional[str] = None,
        auto_load: bool = True
    ):
        self.model_path = model_path or DEFAULT_MODEL_FILE
        self.metadata_path = metadata_path or DEFAULT_METADATA_FILE
        self.model: Optional[IsolationForest] = None
        self.metadata: Dict[str, Any] = {}
        self.feature_extractor = FeatureExtractor(track_history=True)

        if auto_load:
            self.load()

    def load(self) -> bool:
        """
        Loads the trained IsolationForest model and its metadata.
        Returns True if successful, False otherwise.
        """
        if not os.path.exists(self.model_path) or not os.path.exists(self.metadata_path):
            self.model = None
            self.metadata = {}
            return False

        try:
            self.model = joblib.load(self.model_path)
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
            return True
        except Exception as e:
            logger.warning(f"[ML LOAD WARNING] Failed to load ML model artifact: {e}")
            self.model = None
            self.metadata = {}
            return False

    def is_available(self) -> bool:
        return self.model is not None and bool(self.metadata)

    def predict_vector(self, feature_vector: List[float]) -> Dict[str, Any]:
        """
        Runs ML anomaly inference on an extracted numerical feature vector.
        """
        if not self.is_available():
            return {
                "model_available": False,
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "raw_score": 0.0,
                "threshold": 0.0,
                "model_version": "none",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "reason": "Isolation Forest model not loaded or unavailable"
            }

        try:
            X = np.array([feature_vector], dtype=float)

            # decision_function: < 0 is considered anomalous by IsolationForest
            raw_decision = float(self.model.decision_function(X)[0])
            # score_samples: raw opposite of average path length (higher is normal, lower is anomalous)
            raw_sample_score = float(self.model.score_samples(X)[0])

            effective_threshold = float(self.metadata.get("effective_threshold", 0.0))
            is_anomaly = bool(raw_decision < effective_threshold)

            # Map raw score to human-interpretable 0-100 anomaly scale
            # In IsolationForest, raw_decision typically ranges between -0.5 (extreme anomaly) and +0.3 (very normal)
            # We map: negative values indicate anomaly, yielding higher score.
            # anomaly_score = max(0, min(100, (threshold - raw_decision) * 100))
            if is_anomaly:
                base_score = 60.0 + min(40.0, abs(raw_decision - effective_threshold) * 120.0)
            else:
                base_score = max(0.0, 50.0 - (raw_decision * 80.0))
            anomaly_score = round(float(np.clip(base_score, 0.0, 100.0)), 2)

            reason = (
                f"Statistical outlier detected in feature space (Decision score: {raw_decision:.4f}, "
                f"threshold: {effective_threshold:.4f})"
                if is_anomaly else "Request conforms to normal statistical distribution"
            )

            return {
                "model_available": True,
                "is_anomaly": is_anomaly,
                "anomaly_score": anomaly_score,
                "raw_score": round(raw_decision, 4),
                "threshold": effective_threshold,
                "model_version": self.metadata.get("model_version", "1.0.0"),
                "feature_schema_version": self.metadata.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
                "reason": reason
            }
        except Exception as e:
            logger.error(f"[ML INFERENCE ERROR] Anomaly prediction error: {e}")
            return {
                "model_available": True,
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "raw_score": 0.0,
                "threshold": 0.0,
                "model_version": self.metadata.get("model_version", "1.0.0"),
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "reason": f"Inference calculation error: {str(e)}"
            }

    def predict_log(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts features and predicts whether the HTTP request is an anomaly.
        """
        raw_url = str(log_entry.get("url") or "")
        # Do not flag internal telemetry as anomalies
        if self.feature_extractor.is_internal_telemetry(raw_url):
            return {
                "model_available": self.is_available(),
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "raw_score": 0.0,
                "threshold": 0.0,
                "model_version": self.metadata.get("model_version", "1.0.0") if self.is_available() else "none",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "reason": "Internal telemetry route excluded from anomaly scoring"
            }

        vec = self.feature_extractor.extract_vector(log_entry)
        result = self.predict_vector(vec)
        result["features"] = dict(zip(FEATURE_NAMES, vec))
        return result
