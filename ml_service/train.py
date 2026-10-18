import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

print("1. Generating Synthetic Network Telemetry Data...")
np.random.seed(42)
normal_data = pd.DataFrame({
    'payload_size': np.random.uniform(150, 4500, 1200),
    'request_velocity': np.random.uniform(0.5, 5.0, 1200)
})

ddos_data = pd.DataFrame({
    'payload_size': np.random.uniform(500, 3000, 80),
    'request_velocity': np.random.normal(70, 15, 80)  
})

botnet_data = pd.DataFrame({
    'payload_size': np.random.uniform(25000, 150000, 60), 
    'request_velocity': np.random.normal(20, 5, 60)
})

df = pd.concat([normal_data, ddos_data, botnet_data])

print("2. Training Isolation Forest AI Model...")
model = IsolationForest(n_estimators=100, contamination=0.10, random_state=42)
model.fit(df[['payload_size', 'request_velocity']])

print("3. Exporting Trained Model...")
# Ensure __file__ has double underscores on both sides!
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
joblib.dump(model, model_path)
print(f"✅ AI Model trained and saved successfully at: {model_path}")