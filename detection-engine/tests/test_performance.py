"""
Phase 7.6: Performance & Reliability Benchmarking
Measures Rule Evaluation Latency, ML Inference Latency, Combined Pipeline Latency,
Throughput, and Memory Usage across Warm-up and Measured Runs.
"""

import os
import sys
import time
import json
import tracemalloc
from typing import Dict, Any, List
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.rule_engine import RuleEngine
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.dataset import get_expanded_evaluation_dataset


def run_performance_benchmark(n_iterations: int = 5, warmup_runs: int = 15) -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print("      SECURITY GUARD — ENGINE PERFORMANCE & RELIABILITY TEST")
    print("=" * 70)

    tracemalloc.start()
    rule_engine = RuleEngine()
    ml_detector = IsolationForestAnomalyDetector(auto_load=True)
    samples, _ = get_expanded_evaluation_dataset()

    print(f"Dataset Size       : {len(samples)} distinct samples")
    print(f"Warm-up Executions : {warmup_runs} requests")
    print(f"Measured Cycles    : {n_iterations} cycles ({len(samples) * n_iterations} total requests)")

    # 1. Warm-up Phase
    for i in range(warmup_runs):
        s = samples[i % len(samples)]
        _ = rule_engine.analyze(s)
        _ = ml_detector.predict_log(s)

    # 2. Measurement Phase
    rule_latencies_ms: List[float] = []
    ml_latencies_ms: List[float] = []
    pipeline_latencies_ms: List[float] = []

    t_start = time.perf_counter()

    for cycle in range(n_iterations):
        for s in samples:
            # Rule Engine Latency
            t0 = time.perf_counter()
            r_res = rule_engine.analyze(s)
            t1 = time.perf_counter()
            rule_ms = (t1 - t0) * 1000.0
            rule_latencies_ms.append(rule_ms)

            # ML Inference Latency
            t2 = time.perf_counter()
            m_res = ml_detector.predict_log(s)
            t3 = time.perf_counter()
            ml_ms = (t3 - t2) * 1000.0
            ml_latencies_ms.append(ml_ms)

            # Total Detection Engine latency per request
            pipeline_latencies_ms.append(rule_ms + ml_ms)

    t_total = time.perf_counter() - t_start
    total_processed = len(rule_latencies_ms)
    throughput_rps = total_processed / t_total if t_total > 0 else 0.0

    def calc_stats(latencies: List[float]) -> Dict[str, float]:
        arr = np.array(latencies)
        return {
            "mean_ms": round(float(np.mean(arr)), 4),
            "median_p50_ms": round(float(np.percentile(arr, 50)), 4),
            "p95_ms": round(float(np.percentile(arr, 95)), 4),
            "p99_ms": round(float(np.percentile(arr, 99)), 4),
            "min_ms": round(float(np.min(arr)), 4),
            "max_ms": round(float(np.max(arr)), 4)
        }

    rule_stats = calc_stats(rule_latencies_ms)
    ml_stats = calc_stats(ml_latencies_ms)
    pipeline_stats = calc_stats(pipeline_latencies_ms)

    # Process Memory Footprint via tracemalloc
    current_b, peak_b = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_mb = round(current_b / (1024 * 1024), 2)
    peak_mb = round(peak_b / (1024 * 1024), 2)

    perf_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_requests_measured": total_processed,
        "total_duration_sec": round(t_total, 3),
        "throughput_rps": round(throughput_rps, 2),
        "rule_latency": rule_stats,
        "ml_latency": ml_stats,
        "pipeline_latency": pipeline_stats,
        "memory_usage_mb": {
            "allocated": rss_mb,
            "peak": peak_mb
        }
    }

    print("-" * 70)
    print(f"Total Requests Processed : {total_processed}")
    print(f"Elapsed Time             : {t_total:.3f} s")
    print(f"Throughput Rate          : {throughput_rps:.2f} req/sec")
    print("-" * 70)
    print("Latency Distribution (ms):")
    print(f"  Rule Engine (8 rules)  : Mean={rule_stats['mean_ms']} | p50={rule_stats['median_p50_ms']} | p95={rule_stats['p95_ms']} | p99={rule_stats['p99_ms']} | Max={rule_stats['max_ms']}")
    print(f"  ML Inference (IForest) : Mean={ml_stats['mean_ms']} | p50={ml_stats['median_p50_ms']} | p95={ml_stats['p95_ms']} | p99={ml_stats['p99_ms']} | Max={ml_stats['max_ms']}")
    print(f"  Combined Full Pipeline : Mean={pipeline_stats['mean_ms']} | p50={pipeline_stats['median_p50_ms']} | p95={pipeline_stats['p95_ms']} | p99={pipeline_stats['p99_ms']} | Max={pipeline_stats['max_ms']}")
    print("-" * 70)
    print(f"Memory Allocation        : {rss_mb} MB (Peak: {peak_mb} MB)")
    print("=" * 70 + "\n")

    out_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/performance_report.json"))
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(perf_report, f, indent=2)

    return perf_report


if __name__ == "__main__":
    run_performance_benchmark(n_iterations=5, warmup_runs=15)
