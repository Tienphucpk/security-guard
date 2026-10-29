"""
Phase 8.4 - End-to-End System Performance & Reliability Benchmarking
Measures:
1. Rule Engine latency (p50, p95, p99)
2. ML Isolation Forest latency (p50, p95, p99)
3. Detection Engine pipeline latency (p50, p95, p99)
4. End-to-End Web App HTTP Round-Trip latency (p50, p95, p99)
5. Throughput, error rates, timeout rates, memory footprint
"""

import os
import sys
import time
import json
import platform
import urllib.request
import urllib.parse
import tracemalloc
from typing import Dict, Any, List
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.rule_engine import RuleEngine
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.dataset import get_unseen_evaluation_dataset


def run_e2e_benchmark(n_cycles: int = 2, web_app_url: str = "http://127.0.0.1:3000") -> Dict[str, Any]:
    print("\n" + "=" * 76)
    print("      SECURITY GUARD — END-TO-END PERFORMANCE & RELIABILITY TEST (Phase 8.4)")
    print("=" * 76)

    tracemalloc.start()
    rule_engine = RuleEngine()
    ml_detector = IsolationForestAnomalyDetector(auto_load=True)
    samples, labels = get_unseen_evaluation_dataset()

    print(f"System Platform    : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python Runtime     : {platform.python_implementation()} {platform.python_version()}")
    print(f"Dataset Size       : {len(samples)} distinct independent samples")
    print(f"Measured Iterations: {n_cycles} cycles ({len(samples) * n_cycles} total requests)")
    print(f"Target Web App     : {web_app_url}")

    # 1. Warm-up Phase
    print("\nExecuting warm-up phase (10 requests)...")
    for i in range(10):
        s = samples[i % len(samples)]
        _ = rule_engine.analyze(s)
        _ = ml_detector.predict_log(s)

    # 2. Measurement Phase
    rule_latencies_ms: List[float] = []
    ml_latencies_ms: List[float] = []
    pipeline_latencies_ms: List[float] = []
    e2e_latencies_ms: List[float] = []

    completed_requests = 0
    failed_requests = 0
    timeout_requests = 0

    t_start = time.perf_counter()

    for cycle in range(n_cycles):
        for s in samples:
            # Step A: Rule Latency
            t0 = time.perf_counter()
            r_res = rule_engine.analyze(s)
            t1 = time.perf_counter()
            rule_ms = (t1 - t0) * 1000.0
            rule_latencies_ms.append(rule_ms)

            # Step B: ML Latency
            t2 = time.perf_counter()
            m_res = ml_detector.predict_log(s)
            t3 = time.perf_counter()
            ml_ms = (t3 - t2) * 1000.0
            ml_latencies_ms.append(ml_ms)

            # Step C: Combined Engine Latency
            pipeline_latencies_ms.append(rule_ms + ml_ms)

            # Step D: End-to-End HTTP Request to Web App
            # Only send GET requests through Web App /search or target path
            test_path = s.get("url", "/")
            # If path has query or is search, route to web app
            if not test_path.startswith("/"):
                test_path = "/" + test_path
            
            # Map test URL into search query or direct path
            url_to_fetch = f"{web_app_url}/search?q={urllib.parse.quote(test_path[:100])}"
            req_t0 = time.perf_counter()
            try:
                req = urllib.request.Request(url_to_fetch, headers={"User-Agent": s.get("userAgent", "SecurityGuard-PerfTest/1.0")})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    _ = resp.read(256)
                    req_t1 = time.perf_counter()
                    e2e_ms = (req_t1 - req_t0) * 1000.0
                    e2e_latencies_ms.append(e2e_ms)
                    completed_requests += 1
            except urllib.error.URLError as e:
                failed_requests += 1
            except TimeoutError:
                timeout_requests += 1

    t_total = time.perf_counter() - t_start
    total_processed = len(rule_latencies_ms)
    throughput_rps = total_processed / t_total if t_total > 0 else 0.0

    def calc_stats(latencies: List[float]) -> Dict[str, float]:
        if not latencies:
            return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
        arr = np.array(latencies)
        return {
            "mean_ms": round(float(np.mean(arr)), 3),
            "p50_ms": round(float(np.percentile(arr, 50)), 3),
            "p95_ms": round(float(np.percentile(arr, 95)), 3),
            "p99_ms": round(float(np.percentile(arr, 99)), 3),
            "min_ms": round(float(np.min(arr)), 3),
            "max_ms": round(float(np.max(arr)), 3)
        }

    rule_stats = calc_stats(rule_latencies_ms)
    ml_stats = calc_stats(ml_latencies_ms)
    pipeline_stats = calc_stats(pipeline_latencies_ms)
    e2e_stats = calc_stats(e2e_latencies_ms)

    current_b, peak_b = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_mb = round(current_b / (1024 * 1024), 2)
    peak_mb = round(peak_b / (1024 * 1024), 2)

    perf_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
            "python_version": platform.python_version()
        },
        "dataset_evaluated": "holdout_dataset_unseen_v3.json",
        "total_requests_measured": total_processed,
        "completed_http_requests": completed_requests,
        "failed_http_requests": failed_requests,
        "timeout_http_requests": timeout_requests,
        "error_rate_pct": round((failed_requests / total_processed) * 100, 2) if total_processed else 0.0,
        "timeout_rate_pct": round((timeout_requests / total_processed) * 100, 2) if total_processed else 0.0,
        "total_duration_sec": round(t_total, 3),
        "engine_throughput_rps": round(throughput_rps, 2),
        "latency_profiles": {
            "rule_engine": rule_stats,
            "ml_inference": ml_stats,
            "detection_pipeline": pipeline_stats,
            "end_to_end_http": e2e_stats
        },
        "memory_usage_mb": {
            "allocated": rss_mb,
            "peak": peak_mb
        }
    }

    print("-" * 76)
    print(f"Total Measured Requests : {total_processed}")
    print(f"Completed HTTP Requests : {completed_requests} (Errors: {failed_requests}, Timeouts: {timeout_requests})")
    print(f"Elapsed Benchmark Time  : {t_total:.3f} s")
    print(f"Engine Throughput Rate  : {throughput_rps:.2f} req/sec")
    print("-" * 76)
    print("Latency Distribution Summary (ms):")
    print(f"  Rule Engine (8 rules)  : Mean={rule_stats['mean_ms']} | p50={rule_stats['p50_ms']} | p95={rule_stats['p95_ms']} | p99={rule_stats['p99_ms']}")
    print(f"  ML Inference (IForest) : Mean={ml_stats['mean_ms']} | p50={ml_stats['p50_ms']} | p95={ml_stats['p95_ms']} | p99={ml_stats['p99_ms']}")
    print(f"  Combined Engine Pipe   : Mean={pipeline_stats['mean_ms']} | p50={pipeline_stats['p50_ms']} | p95={pipeline_stats['p95_ms']} | p99={pipeline_stats['p99_ms']}")
    print(f"  End-to-End HTTP RTT    : Mean={e2e_stats['mean_ms']} | p50={e2e_stats['p50_ms']} | p95={e2e_stats['p95_ms']} | p99={e2e_stats['p99_ms']}")
    print("-" * 76)
    print(f"Memory Allocation        : {rss_mb} MB (Peak Traced: {peak_mb} MB)")
    print("=" * 76 + "\n")

    out_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/performance_report_phase8.json"))
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(perf_report, f, indent=2)

    return perf_report


if __name__ == "__main__":
    run_e2e_benchmark(n_cycles=2)
