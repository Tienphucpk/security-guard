"""
SECURITY GUARD - Detection Engine Service (Phase 3)
Microservice chịu trách nhiệm phân tích log và phát hiện hành vi bất thường theo Rule-Based Detection.
"""

from typing import List, Optional, Dict, Any
import os
from fastapi import FastAPI, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer.rule_engine import RuleEngine
from analyzer.risk_scorer import RiskScorer
from ml.isolation_forest_model import IsolationForestAnomalyDetector

app = FastAPI(
    title="SECURITY GUARD - Detection Engine API",
    description="Microservice phát hiện hành vi bất thường trên website qua phân tích log (Rule-Based Detection)",
    version="1.0.0"
)

# Enable CORS for communication from Dashboard and other services
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global rule engine instance
rule_engine = RuleEngine()
# Global ML anomaly detector instance
ml_detector = IsolationForestAnomalyDetector(auto_load=True)

# -------------------------------------------------------------
# Pydantic Data Models
# -------------------------------------------------------------
class RequestLogPayload(BaseModel):
    id: Optional[Any] = Field(None, example=1)
    timestamp: Optional[str] = Field(None, example="2026-10-08T08:00:00.000Z")
    ip: Optional[str] = Field(None, example="127.0.0.1")
    method: Optional[str] = Field(None, example="GET")
    url: Optional[str] = Field(None, example="/login")
    statusCode: Optional[int] = Field(None, example=200)
    status_code: Optional[int] = Field(None, example=200)
    userAgent: Optional[str] = Field(None, example="Mozilla/5.0")
    user_agent: Optional[str] = Field(None, example="Mozilla/5.0")
    responseTime: Optional[float] = Field(None, example=25.0)
    response_time_ms: Optional[float] = Field(None, example=25.0)
    body: Optional[Any] = Field(None, example="")

class DetectionDetail(BaseModel):
    type: str = Field(..., example="SQL_INJECTION")
    severity: str = Field(..., example="HIGH")
    score: float = Field(..., example=80.0)
    reason: str = Field(..., example="Matched SQL injection pattern: ' OR 1=1")
    matched_pattern: Optional[str] = Field(None, example="' OR 1=1")
    rule_id: Optional[str] = Field(None, example="RULE-SQLI-001")

class AnalysisResponse(BaseModel):
    detected: bool = Field(..., example=True)
    risk_score: float = Field(..., example=80.0)
    severity: str = Field(..., example="HIGH")
    detections: List[DetectionDetail] = Field(default_factory=list)
    # Backward compatibility with Phase 1/2 stubs
    status: str = Field("analyzed", example="analyzed")
    is_anomaly: bool = Field(False, example=False)
    matched_rules: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    # Phase 6 ML result
    ml_result: Optional[Dict[str, Any]] = Field(None, example={"is_anomaly": False, "anomaly_score": 25.0})

class BatchAnalysisPayload(BaseModel):
    logs: List[RequestLogPayload]

class BatchAnalysisResponse(BaseModel):
    total_processed: int
    anomalies_detected: int
    results: List[AnalysisResponse]

class HealthStatusResponse(BaseModel):
    status: str
    service: str
    version: str
    ml_mode: Optional[str] = "shadow"
    ml_model_loaded: Optional[bool] = False
    ml_model_version: Optional[str] = "none"

# -------------------------------------------------------------
# API Endpoints
# -------------------------------------------------------------
@app.get("/health", response_model=HealthStatusResponse, status_code=status.HTTP_200_OK)
def get_health() -> Dict[str, Any]:
    """
    Kiểm tra trạng thái hoạt động của Detection Engine.
    """
    ml_mode = os.getenv("DETECTION_ML_MODE", "shadow").lower().strip()
    return {
        "status": "ok",
        "service": "detection-engine",
        "version": "1.0.0",
        "ml_mode": ml_mode,
        "ml_model_loaded": ml_detector.is_available(),
        "ml_model_version": ml_detector.metadata.get("model_version", "none") if ml_detector.is_available() else "none"
    }

@app.get("/ml/status", status_code=status.HTTP_200_OK)
def get_ml_status() -> Dict[str, Any]:
    """
    Kiểm tra trạng thái chi tiết của module Machine Learning (Phase 6).
    """
    ml_mode = os.getenv("DETECTION_ML_MODE", "shadow").lower().strip()
    return {
        "status": "ok",
        "mode": ml_mode,
        "model_loaded": ml_detector.is_available(),
        "model_version": ml_detector.metadata.get("model_version", "none"),
        "feature_schema_version": ml_detector.metadata.get("feature_schema_version", "1.0"),
        "features_count": len(ml_detector.metadata.get("feature_names", [])),
        "hyperparameters": ml_detector.metadata.get("hyperparameters", {})
    }

@app.get("/rules", status_code=status.HTTP_200_OK)
def get_rules() -> Dict[str, Any]:
    """
    Liệt kê danh sách các luật phát hiện an ninh và trạng thái kích hoạt.
    """
    return {
        "status": "ok",
        "rules": [
            {
                "rule_id": d.rule_id,
                "name": d.name,
                "category": d.category,
                "severity": d.severity,
                "score": d.score,
                "enabled": d.enabled,
                "description": d.description
            }
            for d in rule_engine.detectors
        ]
    }

@app.post("/analyze", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
def analyze_request(log_entry: RequestLogPayload) -> Dict[str, Any]:
    """
    Phân tích đơn lẻ 1 bản ghi HTTP request log bằng Rule-based Engine và Machine Learning.
    """
    # Normalize dictionary representation
    data = log_entry.model_dump()
    # Normalize alternate field names
    if data.get("status_code") is not None and data.get("statusCode") is None:
        data["statusCode"] = data["status_code"]
    if data.get("user_agent") is not None and data.get("userAgent") is None:
        data["userAgent"] = data["user_agent"]
    if data.get("response_time_ms") is not None and data.get("responseTime") is None:
        data["responseTime"] = data["response_time_ms"]

    res = rule_engine.analyze(data)

    # Phase 6: Machine Learning Anomaly Detection
    ml_mode = os.getenv("DETECTION_ML_MODE", "shadow").lower().strip()
    ml_result = None

    if ml_mode == "disabled":
        ml_result = {
            "model_available": ml_detector.is_available(),
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "raw_score": 0.0,
            "threshold": 0.0,
            "model_version": ml_detector.metadata.get("model_version", "none"),
            "mode": "disabled",
            "reason": "Machine learning detection is disabled via DETECTION_ML_MODE"
        }
    else:
        try:
            ml_pred = ml_detector.predict_log(data)
            ml_pred["mode"] = ml_mode
            ml_result = ml_pred

            # In 'active' mode, if ML detects an anomaly and it wasn't already caught by rules
            if ml_mode == "active" and ml_pred.get("is_anomaly", False):
                ml_detection = {
                    "type": "ML_ANOMALY",
                    "severity": "HIGH" if ml_pred.get("anomaly_score", 0) >= 80.0 else "MEDIUM",
                    "score": float(ml_pred.get("anomaly_score", 65.0)),
                    "reason": f"Isolation Forest statistical anomaly ({ml_pred.get('reason', '')})",
                    "matched_pattern": f"score={ml_pred.get('anomaly_score')}",
                    "rule_id": "RULE-ML-001"
                }
                res["detections"].append(ml_detection)
                res["risk_score"], res["severity"] = RiskScorer.calculate(res["detections"])
                res["detected"] = True
        except Exception as e:
            # Resilient fallback: ML inference failure must never disrupt rule-based pipeline
            ml_result = {
                "model_available": ml_detector.is_available(),
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "raw_score": 0.0,
                "threshold": 0.0,
                "model_version": ml_detector.metadata.get("model_version", "none"),
                "mode": ml_mode,
                "reason": f"ML inference error: {str(e)}"
            }

    matched_rule_ids = [d.get("rule_id", d.get("type")) for d in res["detections"]]

    return {
        "detected": res["detected"],
        "risk_score": res["risk_score"],
        "severity": res["severity"],
        "detections": res["detections"],
        # Backward compatibility
        "status": "analyzed",
        "is_anomaly": res["detected"],
        "matched_rules": matched_rule_ids,
        "details": {
            "received_url": log_entry.url,
            "received_ip": log_entry.ip
        },
        "ml_result": ml_result
    }

@app.post("/analyze/batch", response_model=BatchAnalysisResponse, status_code=status.HTTP_200_OK)
def analyze_batch_requests(payload: BatchAnalysisPayload) -> Dict[str, Any]:
    """
    Phân tích một tập hợp bản ghi log dạng batch (tối đa 500 bản ghi/request).
    """
    if len(payload.logs) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch size exceeds maximum limit of 500 logs"
        )

    results: List[Dict[str, Any]] = []
    anomalies_count = 0

    for log_item in payload.logs:
        res = analyze_request(log_item)
        if res["detected"]:
            anomalies_count += 1
        results.append(res)

    return {
        "total_processed": len(payload.logs),
        "anomalies_detected": anomalies_count,
        "results": results
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
