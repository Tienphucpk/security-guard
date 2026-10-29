"""
Phase 7.3 - Comprehensive Detection Benchmark Comparison
Evaluates Rule-Based Only, ML Only, and Hybrid (Rule + ML) on identical holdout dataset.
Computes TP, FP, TN, FN, Precision, Recall, F1, FPR, Category Breakdown, and Correlation Metrics.
"""

import os
import sys
import json
import time
from typing import Dict, Any, List, Tuple
from collections import defaultdict

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.rule_engine import RuleEngine
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.dataset import get_expanded_evaluation_dataset, get_unseen_evaluation_dataset


def run_benchmark(dataset_version: str = "v2") -> Dict[str, Any]:
    rule_engine = RuleEngine()
    ml_detector = IsolationForestAnomalyDetector(auto_load=True)

    if dataset_version in ("v3", "unseen"):
        samples, labels = get_unseen_evaluation_dataset()
        dataset_name = "Holdout Dataset Unseen v3 (Phase 8 Independent)"
        report_filename = "benchmark_report_unseen_v3.json"
    else:
        samples, labels = get_expanded_evaluation_dataset()
        dataset_name = "Holdout Dataset v2 (Phase 7)"
        report_filename = "benchmark_report.json"

    total_samples = len(samples)

    categories = defaultdict(lambda: {"total": 0, "rule_detected": 0, "ml_detected": 0, "hybrid_detected": 0})

    # Results arrays
    y_true = labels
    y_pred_rule = []
    y_pred_ml = []
    y_pred_hybrid = []

    rule_latencies_ms = []
    ml_latencies_ms = []

    ml_only_discoveries = []
    rule_only_discoveries = []
    missed_by_both = []
    ml_false_positives = []

    raw_alert_count_before_corr = 0
    correlated_alert_count = 0

    for idx, sample in enumerate(samples):
        cat = sample.get("category", "UNKNOWN")
        truth = labels[idx]
        categories[cat]["total"] += 1

        # 1. Rule-Based Evaluation
        t0 = time.perf_counter()
        rule_res = rule_engine.analyze(sample)
        rule_latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        is_rule_det = 1 if (rule_res.get("detected") and len(rule_res.get("detections", [])) > 0) else 0
        y_pred_rule.append(is_rule_det)
        if is_rule_det:
            categories[cat]["rule_detected"] += 1

        # 2. ML Evaluation
        t0 = time.perf_counter()
        ml_res = ml_detector.predict_log(sample)
        ml_latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        is_ml_det = 1 if ml_res.get("is_anomaly") else 0
        y_pred_ml.append(is_ml_det)
        if is_ml_det:
            categories[cat]["ml_detected"] += 1

        # 3. Hybrid Evaluation
        is_hybrid_det = 1 if (is_rule_det or is_ml_det) else 0
        y_pred_hybrid.append(is_hybrid_det)
        if is_hybrid_det:
            categories[cat]["hybrid_detected"] += 1

        # Discrepancy Tracking
        if truth == 0 and is_ml_det:
            ml_false_positives.append({
                "id": sample.get("id"),
                "url": sample.get("url"),
                "score": ml_res.get("anomaly_score"),
                "raw_score": ml_res.get("raw_score")
            })

        if truth == 1:
            if is_ml_det and not is_rule_det:
                ml_only_discoveries.append({
                    "id": sample.get("id"),
                    "category": cat,
                    "url": sample.get("url"),
                    "ml_score": ml_res.get("anomaly_score"),
                    "reason": ml_res.get("reason")
                })
            elif is_rule_det and not is_ml_det:
                rule_only_discoveries.append({
                    "id": sample.get("id"),
                    "category": cat,
                    "url": sample.get("url"),
                    "rule": [d["type"] for d in rule_res.get("detections", [])]
                })
            elif not is_rule_det and not is_ml_det:
                missed_by_both.append({
                    "id": sample.get("id"),
                    "category": cat,
                    "url": sample.get("url")
                })

        # Alert Counting & Correlation
        num_rule_alerts = len(rule_res.get("detections", []))
        num_ml_alerts = 1 if is_ml_det else 0
        raw_alert_count_before_corr += (num_rule_alerts + num_ml_alerts)
        if is_hybrid_det:
            correlated_alert_count += 1

    def calc_metrics(y_actual: List[int], y_pred: List[int]) -> Dict[str, float]:
        tp = sum(1 for a, p in zip(y_actual, y_pred) if a == 1 and p == 1)
        tn = sum(1 for a, p in zip(y_actual, y_pred) if a == 0 and p == 0)
        fp = sum(1 for a, p in zip(y_actual, y_pred) if a == 0 and p == 1)
        fn = sum(1 for a, p in zip(y_actual, y_pred) if a == 1 and p == 0)

        acc = (tp + tn) / len(y_actual) if len(y_actual) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr * 100, 2)
        }

    metrics_rule = calc_metrics(y_true, y_pred_rule)
    metrics_ml = calc_metrics(y_true, y_pred_ml)
    metrics_hybrid = calc_metrics(y_true, y_pred_hybrid)

    import numpy as np
    latency_summary = {
        "rule_ms": {
            "mean": round(float(np.mean(rule_latencies_ms)), 3),
            "p50": round(float(np.percentile(rule_latencies_ms, 50)), 3),
            "p95": round(float(np.percentile(rule_latencies_ms, 95)), 3),
            "p99": round(float(np.percentile(rule_latencies_ms, 99)), 3),
        },
        "ml_ms": {
            "mean": round(float(np.mean(ml_latencies_ms)), 3),
            "p50": round(float(np.percentile(ml_latencies_ms, 50)), 3),
            "p95": round(float(np.percentile(ml_latencies_ms, 95)), 3),
            "p99": round(float(np.percentile(ml_latencies_ms, 99)), 3),
        }
    }

    report = {
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_size": total_samples,
        "label_distribution": {
            "benign": y_true.count(0),
            "attack": y_true.count(1)
        },
        "configurations": {
            "config_a_rule_only": metrics_rule,
            "config_b_ml_only": metrics_ml,
            "config_c_hybrid": metrics_hybrid
        },
        "category_breakdown": dict(categories),
        "discrepancies": {
            "ml_false_positives_count": len(ml_false_positives),
            "ml_false_positives": ml_false_positives,
            "ml_additional_discoveries_count": len(ml_only_discoveries),
            "ml_additional_discoveries": ml_only_discoveries,
            "rule_only_discoveries_count": len(rule_only_discoveries),
            "rule_only_discoveries": rule_only_discoveries,
            "missed_by_both_count": len(missed_by_both),
            "missed_by_both": missed_by_both
        },
        "alert_correlation": {
            "raw_alerts_without_correlation": raw_alert_count_before_corr,
            "correlated_alerts": correlated_alert_count,
            "duplicates_suppressed": raw_alert_count_before_corr - correlated_alert_count
        },
        "latencies": latency_summary,
        "ml_model_metadata": ml_detector.metadata
    }

    # Print Formatted Report to stdout
    print("\n" + "=" * 78)
    print("      SECURITY GUARD — PHASE 7 DETECTION BENCHMARK REPORT")
    print("=" * 78)
    print(f"Total Samples: {total_samples} (Benign: {y_true.count(0)}, Attack: {y_true.count(1)})")
    print("-" * 78)
    print(f"{'Metric':<25} | {'Config A: Rule Only':<16} | {'Config B: ML Only':<16} | {'Config C: Hybrid':<16}")
    print("-" * 78)
    print(f"{'Accuracy (%)':<25} | {metrics_rule['accuracy']:<16} | {metrics_ml['accuracy']:<16} | {metrics_hybrid['accuracy']:<16}")
    print(f"{'Precision (%)':<25} | {metrics_rule['precision']:<16} | {metrics_ml['precision']:<16} | {metrics_hybrid['precision']:<16}")
    print(f"{'Recall (%)':<25} | {metrics_rule['recall']:<16} | {metrics_ml['recall']:<16} | {metrics_hybrid['recall']:<16}")
    print(f"{'F1-Score':<25} | {metrics_rule['f1_score']:<16} | {metrics_ml['f1_score']:<16} | {metrics_hybrid['f1_score']:<16}")
    print(f"{'False Positive Rate (%)':<25} | {metrics_rule['false_positive_rate']:<16} | {metrics_ml['false_positive_rate']:<16} | {metrics_hybrid['false_positive_rate']:<16}")
    print(f"{'True Positives (TP)':<25} | {metrics_rule['tp']:<16} | {metrics_ml['tp']:<16} | {metrics_hybrid['tp']:<16}")
    print(f"{'False Positives (FP)':<25} | {metrics_rule['fp']:<16} | {metrics_ml['fp']:<16} | {metrics_hybrid['fp']:<16}")
    print(f"{'True Negatives (TN)':<25} | {metrics_rule['tn']:<16} | {metrics_ml['tn']:<16} | {metrics_hybrid['tn']:<16}")
    print(f"{'False Negatives (FN)':<25} | {metrics_rule['fn']:<16} | {metrics_ml['fn']:<16} | {metrics_hybrid['fn']:<16}")
    print("-" * 78)
    print("Detection Rate by Category:")
    for cat_name, stats in categories.items():
        if cat_name == "BENIGN":
            continue
        tot = stats["total"]
        r_det = stats["rule_detected"]
        m_det = stats["ml_detected"]
        h_det = stats["hybrid_detected"]
        print(f"  - {cat_name:<20}: Rule={r_det}/{tot} ({r_det/tot*100:.0f}%) | ML={m_det}/{tot} ({m_det/tot*100:.0f}%) | Hybrid={h_det}/{tot} ({h_det/tot*100:.0f}%)")

    print("-" * 78)
    print(f"ML False Positives on Benign Traffic ({len(ml_false_positives)}/40):")
    for fp in ml_false_positives:
        print(f"  - [{fp['id']}] {fp['url']} (Score: {fp['score']}, Raw: {fp['raw_score']})")

    print("-" * 78)
    print("Alert Correlation Summary:")
    print(f"  Raw Alerts (Pre-correlation)   : {raw_alert_count_before_corr}")
    print(f"  Correlated Alerts Emitted      : {correlated_alert_count}")
    print(f"  Redundant Alerts Suppressed    : {raw_alert_count_before_corr - correlated_alert_count}")
    print("-" * 78)
    print("Latency Profile:")
    print(f"  Rule Engine Latency : Mean={latency_summary['rule_ms']['mean']}ms | p50={latency_summary['rule_ms']['p50']}ms | p95={latency_summary['rule_ms']['p95']}ms")
    print(f"  ML Inference Latency: Mean={latency_summary['ml_ms']['mean']}ms | p50={latency_summary['ml_ms']['p50']}ms | p95={latency_summary['ml_ms']['p95']}ms")
    print("=" * 78 + "\n")

    # Export report to JSON
    report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), f"../data/{report_filename}"))
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run Detection Benchmark")
    parser.add_argument("--dataset", choices=["v2", "v3", "unseen"], default="v2", help="Dataset version to evaluate")
    args = parser.parse_args()
    run_benchmark(dataset_version=args.dataset)
