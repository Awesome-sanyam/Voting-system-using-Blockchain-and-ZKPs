import os
import time
import numpy as np
import pandas as pd
import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="BlockVote Active Sentinel AI",
    description="IsolationForest anomaly detection for DDoS and voting fraud mitigation.",
    version="2.0.0"
)

# ── CORS: allow Django backend on port 8000 to call this service ─────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Model Loading ─────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
_model_load_time = None

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    _model_load_time = time.time()
    print(f"[Active Sentinel] IsolationForest model loaded from {MODEL_PATH}")
else:
    model = None
    print("WARNING: model.pkl not found. Run 'python train.py' to initialize the model.")


# ── Request/Response Models ───────────────────────────────────────────────────
class ThreatRequest(BaseModel):
    ip_address: str = Field(..., description="Requester IP address for audit logging")
    payload_size: float = Field(..., ge=0, description="Request payload size in bytes")
    request_velocity: float = Field(..., ge=0, description="Requests per second from this IP")

class ThreatResponse(BaseModel):
    is_anomalous: bool
    threat_score: float
    action: str


# ── Threat Analysis Endpoint ──────────────────────────────────────────────────
@app.post("/api/v1/analyze-threat/", response_model=ThreatResponse)
async def analyze_threat(request: ThreatRequest):
    """
    Evaluates incoming vote relay traffic using IsolationForest.
    Returns calibrated 0.05-0.99 threat score. Score > 0.70 triggers BLOCK.
    """
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="Active Sentinel model not loaded. Run 'python train.py' to initialize."
        )

    features = pd.DataFrame(
        [[request.payload_size, request.request_velocity]],
        columns=['payload_size', 'request_velocity']
    )
    prediction = model.predict(features)[0]
    decision = float(model.decision_function(features)[0])
    is_anomalous = bool(prediction == -1)

    # Calibrated 0.05-0.99 anomaly score: higher score = higher risk (> 0.70 = anomalous)
    if is_anomalous:
        threat_score = round(float(np.clip(0.75 - (decision * 1.5), 0.72, 0.99)), 2)
    else:
        threat_score = round(float(np.clip(0.50 - (decision * 1.2), 0.05, 0.65)), 2)

    return {
        "is_anomalous": is_anomalous,
        "threat_score": threat_score,
        "action": "BLOCK" if is_anomalous else "ALLOW"
    }


# ── Health Check Endpoint ─────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    """Returns model status and service readiness for Django health checks."""
    model_age = round(time.time() - _model_load_time) if _model_load_time else None
    return {
        "status": "Active Sentinel is running",
        "model_loaded": model is not None,
        "model_type": type(model).__name__ if model else None,
        "model_age_seconds": model_age,
        "version": "2.0.0"
    }


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "BlockVote Active Sentinel AI", "version": "2.0.0", "docs": "/docs"}