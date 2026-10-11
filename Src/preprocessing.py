"""
Preprocessing Module for AI-Powered Cybersecurity Threat Detection.
Handles dataset generation (simulation), cleaning, scaling, and encoding.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

def generate_synthetic_network_data(filepath="data/raw/network_traffic_sample.csv", n_samples=5000):
    """Generates a realistic synthetic network traffic dataset for simulation."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    np.random.seed(42)
    
    durations = np.random.exponential(scale=2.0, size=n_samples)
    protocol_types = np.random.choice(['tcp', 'udp', 'icmp'], size=n_samples, p=[0.7, 0.2, 0.1])
    src_bytes = np.random.exponential(scale=500, size=n_samples)
    dst_bytes = np.random.exponential(scale=1200, size=n_samples)
    wrong_fragment = np.random.choice([0, 1, 3], size=n_samples, p=[0.95, 0.03, 0.02])
    urgent = np.random.choice([0, 1], size=n_samples, p=[0.99, 0.01])
    num_failed_logins = np.random.poisson(lam=0.05, size=n_samples)
    is_guest_login = np.random.choice([0, 1], size=n_samples, p=[0.98, 0.02])
    diff_srv_rate = np.random.uniform(0.0, 1.0, size=n_samples)
    dst_host_count = np.random.randint(1, 256, size=n_samples)
    
    # Inject anomalies / attacks based on rules
    labels = []
    for i in range(n_samples):
        if num_failed_logins[i] > 1 or wrong_fragment[i] > 0:
            labels.append('BruteForce_Attack' if np.random.rand() > 0.4 else 'DoS_Attack')
        elif durations[i] > 10 and src_bytes[i] < 50:
            labels.append('Probe_Scan')
        else:
            labels.append('Normal')
            
    df = pd.DataFrame({
        'duration': durations,
        'protocol_type': protocol_types,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'wrong_fragment': wrong_fragment,
        'urgent': urgent,
        'num_failed_logins': num_failed_logins,
        'is_guest_login': is_guest_login,
        'diff_srv_rate': diff_srv_rate,
        'dst_host_count': dst_host_count,
        'label': labels
    })
    
    df.to_csv(filepath, index=False)
    print(f"[+] Synthetic dataset generated successfully at {filepath} with {n_samples} records.")
    return df

def load_and_preprocess_data(filepath="data/raw/network_traffic_sample.csv"):
    """Loads dataset, encodes categorical features, scales data, and splits into train/test."""
    if not os.path.exists(filepath):
        generate_synthetic_network_data(filepath)
        
    df = pd.read_csv(filepath)
    
    # Encode categorical column 'protocol_type'
    le = LabelEncoder()
    df['protocol_type'] = le.fit_transform(df['protocol_type'])
    
    # Save label encoder classes if needed
    os.makedirs("models", exist_ok=True)
    joblib.dump(le, "models/protocol_encoder.pkl")
    
    # Separate features and target
    X = df.drop(columns=['label'])
    # Convert multi-class labels into binary for simplicity (Normal vs Attack) or keep multi-class
    # Here we map 'Normal' to 0 and any attack to 1 for binary classification task
    y = df['label'].apply(lambda x: 0 if x == 'Normal' else 1)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scale numerical features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    joblib.dump(scaler, "models/scaler.pkl")
    
    print("[+] Data preprocessing completed successfully.")
    return X_train_scaled, X_test_scaled, y_train, y_test, X.columns
