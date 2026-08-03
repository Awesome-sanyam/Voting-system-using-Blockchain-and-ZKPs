#!/bin/bash

STREAMING_CHUNK: Force-creating the ML service directories and files...

echo "1. Creating ml_service directory in the root folder..."
mkdir -p ml_service

echo "2. Writing train.py directly to disk..."
cat << 'EOF' > ml_service/train.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

print("1. Generating Synthetic Network Telemetry Data...")
np.random.seed(42)
normal_data = pd.DataFrame({
'payload_size': np.random.normal(2000, 200, 1000),
'request_velocity': np.random.normal(3, 1, 1000)
})

ddos_data = pd.DataFrame({
'payload_size': np.random.normal(2000, 200, 50),
'request_velocity': np.random.normal(80, 15, 50)

})

botnet_data = pd.DataFrame({
'payload_size': np.random.normal(8000, 500, 50),
'request_velocity': np.random.normal(15, 5, 50)
})

df = pd.concat([normal_data, ddos_data, botnet_data])

print("2. Training Isolation Forest AI Model...")
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(df[['payload_size', 'request_velocity']])

print("3. Exporting Trained Model...")
model_path = os.path.join(os.path.dirname(file), 'model.pkl')
joblib.dump(model, model_path)
print(f"✅ AI Model trained and saved successfully at: {model_path}")
EOF

echo "3. Writing main.py directly to disk..."
cat << 'EOF' > ml_service/main.py
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np

app = FastAPI(title="BlockVote Active Sentinel AI", version="1.0.0")

MODEL_PATH = os.path.join(os.path.dirname(file), 'model.pkl')
if os.path.exists(MODEL_PATH):
model = joblib.load(MODEL_PATH)
else:
model = None

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


EOF

echo "✅ ML Service files completely built!"
