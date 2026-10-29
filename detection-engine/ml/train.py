"""
Model Training Script for Isolation Forest Anomaly Detection
Fits an Isolation Forest model on benign HTTP traffic baseline and exports
the model artifact and metadata.
"""

import os
import sys
import json
import argparse
import datetime
import logging
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

from .feature_extractor import FeatureExtractor, FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from .dataset import get_benign_training_samples

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml.train")


def train_model(
    output_dir: str = None,
    n_samples: int = 1200,
    n_estimators: int = 100,
    contamination: float = 0.03,
    random_state: int = 42
) -> str:
    if output_dir is None:
        output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models"))

    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "isolation_forest_v1.joblib")
    metadata_path = os.path.join(output_dir, "model_metadata.json")

    logger.info(f"Generating {n_samples} benign baseline HTTP training samples...")
    raw_samples = get_benign_training_samples(n_samples=n_samples)

    logger.info("Extracting numerical feature vectors...")
    extractor = FeatureExtractor(track_history=False)
    X = np.array([extractor.extract_vector(s) for s in raw_samples], dtype=float)

    logger.info(f"Training IsolationForest (n_estimators={n_estimators}, contamination={contamination}, random_state={random_state})...")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X)

    # Evaluate decision scores on training baseline
    decision_scores = model.decision_function(X)
    mean_decision = float(np.mean(decision_scores))
    std_decision = float(np.std(decision_scores))
    min_decision = float(np.min(decision_scores))
    max_decision = float(np.max(decision_scores))
    # Calibrate effective threshold at 1st percentile of benign baseline
    calibrated_threshold = min(-0.015, float(np.percentile(decision_scores, 1.0)))

    logger.info(f"Training Baseline Decision Scores: Mean={mean_decision:.4f}, Std={std_decision:.4f}, Min={min_decision:.4f}, Max={max_decision:.4f}, Calibrated Threshold={calibrated_threshold:.4f}")

    # Save model artifact
    logger.info(f"Saving model artifact to {model_path}...")
    joblib.dump(model, model_path, compress=3)

    metadata = {
        "model_version": "1.0.0",
        "model_name": "IsolationForestAnomalyDetector",
        "model_type": "IsolationForest",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "features_count": len(FEATURE_NAMES),
        "hyperparameters": {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": random_state
        },
        "training_sample_count": len(raw_samples),
        "effective_threshold": round(calibrated_threshold, 4),
        "baseline_metrics": {
            "mean_decision_score": round(mean_decision, 4),
            "std_decision_score": round(std_decision, 4),
            "min_decision_score": round(min_decision, 4),
            "max_decision_score": round(max_decision, 4)
        }
    }

    logger.info(f"Writing metadata to {metadata_path}...")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Model training completed successfully.")
    return model_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Isolation Forest Anomaly Detection Model")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory to save model artifact and metadata")
    parser.add_argument("--samples", type=int, default=1200, help="Number of training samples")
    parser.add_argument("--estimators", type=int, default=100, help="Number of trees")
    parser.add_argument("--contamination", type=float, default=0.03, help="Expected proportion of outliers")
    args = parser.parse_args()

    train_model(
        output_dir=args.output_dir,
        n_samples=args.samples,
        n_estimators=args.estimators,
        contamination=args.contamination
    )
