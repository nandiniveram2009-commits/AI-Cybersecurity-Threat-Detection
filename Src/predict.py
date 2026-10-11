"""
Prediction & Alert Generation Module.
Scans incoming network traffic samples and generates structured JSON security alerts.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

def simulate_realtime_prediction():
    print("[*] Initializing Threat Detection Inference Engine...")
    
    if not os.path.exists("models/threat_classifier.pkl") or not os.path.exists("models/scaler.pkl"):
        raise FileNotFoundError("Trained models not found! Run src/train.py first.")
        
    rf_clf = joblib.load("models/threat_classifier.pkl")
    scaler = joblib.load("models/scaler.pkl")
    le = joblib.load("models/protocol_encoder.pkl")
    
    # Simulate incoming real-time network packets
    np.random.seed(100)
    simulated_packets = pd.DataFrame({
        'duration': [0.1, 15.4, 0.0, 5.2, 0.05],
        'protocol_type': ['tcp', 'udp', 'tcp', 'icmp', 'tcp'],
        'src_bytes': [200, 10, 4500, 20, 1500],
        'dst_bytes': [400, 0, 120000, 0, 3000],
        'wrong_fragment': [0, 0, 2, 0, 0],
        'urgent': [0, 0, 0, 0, 0],
        'num_failed_logins': [0, 3, 0, 0, 0],
        'is_guest_login': [0, 0, 0, 0, 0],
        'diff_srv_rate': [0.01, 0.85, 0.0, 0.5, 0.02],
        'dst_host_count': [15, 200, 45, 120, 10]
    })
    
    simulated_packets['protocol_type'] = le.transform(simulated_packets['protocol_type'])
    scaled_packets = scaler.transform(simulated_packets)
    
    predictions = rf_clf.predict(scaled_packets)
    probabilities = rf_clf.predict_proba(scaled_packets)
    
    os.makedirs("outputs/alerts", exist_ok=True)
    alerts = []
    
    print("\n---------------- LIVE THREAT DETECTION FEED ----------------")
    for idx, pred in enumerate(predictions):
        confidence = np.max(probabilities[idx]) * 100
        status = "MALICIOUS" if pred == 1 else "BENIGN"
        severity = "HIGH" if confidence > 85 and status == "MALICIOUS" else ("MEDIUM" if status == "MALICIOUS" else "LOW")
        
        alert = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "packet_id": idx + 1,
            "classification": status,
            "severity": severity,
            "confidence_score": round(confidence, 2),
            "source_metrics": {
                "duration": simulated_packets.loc[idx, 'duration'],
                "src_bytes": simulated_packets.loc[idx, 'src_bytes'],
                "failed_logins": int(simulated_packets.loc[idx, 'num_failed_logins'])
            }
        }
        alerts.append(alert)
        print(f"Packet #{idx+1} -> Status: {status} | Severity: {severity} | Confidence: {confidence:.2f}%")
        
    alert_file = "outputs/alerts/latest_alerts.json"
    with open(alert_file, "w") as f:
        json.dump(alerts, f, indent=4)
    print(f"\n[+] Threat alerts successfully exported to {alert_file}")

if __name__ == "__main__":
    simulate_realtime_prediction()
