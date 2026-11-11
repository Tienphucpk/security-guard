# Benchmark Methodology & Experimental Setup

## 1. Objective & Hypothesis
The primary hypothesis of the SECURITY GUARD benchmark evaluation is:
> *A synergistic Adaptive Hybrid model combining pre-inspection multi-encoding normalization, deterministic regex signatures, and unsupervised Isolation Forest anomaly scoring significantly outperforms both Rule-Based-Only and ML-Only systems in F1-score, evasion resistance, and false-positive suppression, while maintaining low overhead (< 3ms).*

## 2. Experimental Setup & Environment
- **Operating System:** Windows 11 Enterprise (x86_64)
- **Node.js Runtime:** v24.15.0 (Express.js Gateway and Web App)
- **Python Environment:** Python 3.12 (scikit-learn Isolation Forest, FastAPI, Uvicorn)
- **Database Engine:** PostgreSQL 16 (`security_guard`)
- **Dataset Partitioning:** 
  - `train.jsonl`: 1,400 samples (70% - baseline fitting)
  - `validation.jsonl`: 300 samples (15% - hyperparameter tuning)
  - `test.jsonl`: 300 samples (15% - held-out independent evaluation: 200 Benign, 100 Multi-Vector Attacks)

## 3. Metrics Formulation
1. **Accuracy**: $(TP + TN) / (TP + TN + FP + FN)$
2. **Precision**: $TP / (TP + FP)$
3. **Recall / Detection Rate (TPR)**: $TP / (TP + FN)$
4. **Specificity (TNR)**: $TN / (TN + FP)$
5. **F1-Score**: $2 \cdot (\text{Precision} \cdot \text{Recall}) / (\text{Precision} + \text{Recall})$
6. **False Positive Rate (FPR)**: $FP / (FP + TN)$
7. **False Negative Rate (FNR)**: $FN / (TP + FN)$
8. **Blocking Success Rate**: $TP_{\text{enforced}} / \text{Total Attacks}$
9. **False Blocking Rate**: $FP_{\text{enforced}} / \text{Total Benign}$
10. **Throughput**: $1000 / \text{Latency}_{\text{mean}} \text{ (requests/second)}$

## 4. Reproducibility Instructions
To independently reproduce the benchmark results:
```powershell
cd D:\BM&ATTT\security-guard
.\detection-engine\venv\Scripts\python.exe scripts\benchmark\run-benchmark.py
```
Generated reports are stored in `reports/benchmark/` in JSON, CSV, and Markdown.
