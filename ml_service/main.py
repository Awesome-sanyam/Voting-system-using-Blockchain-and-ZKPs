import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np

app = FastAPI(title="BlockVote Active Sentinel AI", version="1.0.0")

# Properly indented and using __file__
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None
    print("WARNING: model.pkl not found. Please run train.py first.")

class ThreatRequest(BaseModel):
    ip_address: str
    payload_size: float
    request_velocity: float

class ThreatResponse(BaseModel):
    is_anomalous: bool
    threat_score: float
    action: str

@app.post("/api/v1/analyze-threat/", response_model=ThreatResponse)
async def analyze_threat(request: ThreatRequest):
    if model is None:
        raise HTTPException(status_code=500, detail="ML Model is not loaded.")

    features = np.array([[request.payload_size, request.request_velocity]])
    prediction = model.predict(features)[0]
    threat_score = model.score_samples(features)[0]
    is_anomalous = bool(prediction == -1)
    
    return {
        "is_anomalous": is_anomalous,
        "threat_score": float(threat_score),
        "action": "BLOCK" if is_anomalous else "ALLOW"
    }

@app.get("/health")
async def health_check():
    return {"status": "Active Sentinel is running", "model_loaded": model is not None}