"""
Model Training Module for AI-Powered Cybersecurity Threat Detection.
Trains a Random Forest Classifier and an Isolation Forest Anomaly Detector.
"""

import os
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from src.preprocessing import load_and_preprocess_data

def train_models():
    print("[*] Starting model training pipeline...")
    X_train, X_test, y_train, y_test, feature_names = load_and_preprocess_data()
    
    # 1. Train Supervised Threat Classifier (Random Forest)
    print("[*] Training Random Forest Threat Classifier...")
    rf_clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    rf_clf.fit(X_train, y_train)
    
    y_pred = rf_clf.predict(X_test)
    print("\n--- Random Forest Performance ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("Classification Report:\n", classification_report(y_test, y_pred))
    
    # 2. Train Unsupervised Anomaly Detector (Isolation Forest)
    print("[*] Training Isolation Forest Anomaly Detector...")
    # Train only on normal traffic (where y_train == 0) or whole set with contamination estimate
    iso_forest = IsolationForest(contamination=0.15, random_state=42)
    iso_forest.fit(X_train)
    
    # Save models
    os.makedirs("models", exist_ok=True)
    joblib.dump(rf_clf, "models/threat_classifier.pkl")
    joblib.dump(iso_forest, "models/anomaly_detector.pkl")
    print("[+] Models saved successfully to /models directory.")

if __name__ == "__main__":
    train_models()
