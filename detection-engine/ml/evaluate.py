"""
Model Evaluation Script for Isolation Forest Anomaly Detection
Evaluates the trained model against labeled holdout datasets, computes
precision, recall, F1, accuracy, and latency metrics.
"""

import os
import sys
import time
import json
import logging
from typing import Dict, Any
import numpy as np

from .isolation_forest_model import IsolationForestAnomalyDetector
from .dataset import get_labeled_evaluation_dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml.evaluate")


def evaluate_model(model_path: str = None, metadata_path: str = None) -> Dict[str, Any]:
    detector = IsolationForestAnomalyDetector(
        model_path=model_path,
        metadata_path=metadata_path,
        auto_load=True
    )

    if not detector.is_available():
        logger.error("Model artifact or metadata not found. Run 'train.py' first.")
        return {"status": "error", "message": "Model not available"}

    test_samples, y_true = get_labeled_evaluation_dataset()
    logger.info(f"Evaluating model on {len(test_samples)} labeled holdout samples ({y_true.count(0)} benign, {y_true.count(1)} anomaly)...")

    latencies_ms = []
    y_pred = []
    predictions_details = []

    for sample in test_samples:
        t0 = time.perf_counter()
        pred = detector.predict_log(sample)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        latencies_ms.append(elapsed_ms)
        is_anomaly = 1 if pred.get("is_anomaly") else 0
        y_pred.append(is_anomaly)
        predictions_details.append({
            "url": sample.get("url"),
            "method": sample.get("method"),
            "pred_anomaly": is_anomaly,
            "score": pred.get("anomaly_score"),
            "raw_score": pred.get("raw_score")
        })

    # Confusion matrix
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    avg_latency = float(np.mean(latencies_ms))
    p95_latency = float(np.percentile(latencies_ms, 95))
    max_latency = float(np.max(latencies_ms))

    report = {
        "status": "success",
        "sample_count": len(y_true),
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn
        },
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4)
        },
        "latency_ms": {
            "mean": round(avg_latency, 3),
            "p95": round(p95_latency, 3),
            "max": round(max_latency, 3)
        }
    }

    print("\n" + "=" * 60)
    print("      ISOLATION FOREST MODEL EVALUATION REPORT")
    print("=" * 60)
    print(f"Total Evaluated Samples : {len(y_true)}")
    print(f"True Positives (TP)     : {tp}")
    print(f"True Negatives (TN)     : {tn}")
    print(f"False Positives (FP)    : {fp}")
    print(f"False Negatives (FN)    : {fn}")
    print("-" * 60)
    print(f"Accuracy                : {accuracy * 100:.2f}%")
    print(f"Precision               : {precision * 100:.2f}%")
    print(f"Recall                  : {recall * 100:.2f}%")
    print(f"F1 Score                : {f1:.4f}")
    print("-" * 60)
    print(f"Avg Inference Latency   : {avg_latency:.3f} ms")
    print(f"p95 Inference Latency   : {p95_latency:.3f} ms")
    print("=" * 60 + "\n")

    return report


if __name__ == "__main__":
    evaluate_model()
