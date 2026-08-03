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
# Ensure __file__ has double underscores on both sides!
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
joblib.dump(model, model_path)
print(f"✅ AI Model trained and saved successfully at: {model_path}")