"""
Visualization Module.
Generates analytical charts for model performance and threat distribution.
"""

import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from src.preprocessing import load_and_preprocess_data

def generate_visualizations():
    print("[*] Generating security analytics visualizations...")
    os.makedirs("outputs/figures", exist_ok=True)
    
    X_train, X_test, y_train, y_test, feature_names = load_and_preprocess_data()
    
    if not os.path.exists("models/threat_classifier.pkl"):
        raise FileNotFoundError("Model not found. Train first using src/train.py")
        
    rf_clf = joblib.load("models/threat_classifier.pkl")
    y_pred = rf_clf.predict(X_test)
    
    # 1. Confusion Matrix Plot
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Threat'], yticklabels=['Normal', 'Threat'])
    plt.title('Cyber Threat Detection - Confusion Matrix', fontsize=14, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('Actual Label', fontsize=12)
    plt.tight_layout()
    cm_path = "outputs/figures/confusion_matrix.png"
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[+] Saved Confusion Matrix to {cm_path}")
    
    # 2. Feature Importance Plot
    plt.figure(figsize=(10, 6))
    importances = rf_clf.feature_importances_
    sorted_indices = importances.argsort()[::-1]
    
    plt.bar(range(len(importances)), importances[sorted_indices], align='center', color='teal')
    plt.xticks(range(len(importances)), [feature_names[i] for i in sorted_indices], rotation=45, ha='right')
    plt.title('Feature Importance in Threat Detection', fontsize=14, fontweight='bold')
    plt.xlabel('Network Features', fontsize=12)
    plt.ylabel('Importance Score', fontsize=12)
    plt.tight_layout()
    fi_path = "outputs/figures/feature_importance.png"
    plt.savefig(fi_path, dpi=300)
    plt.close()
    print(f"[+] Saved Feature Importance chart to {fi_path}")

if __name__ == "__main__":
    generate_visualizations()
