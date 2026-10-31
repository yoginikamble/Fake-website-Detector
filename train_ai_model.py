"""
AI / Machine Learning Model Training & Evaluation Script.
Fake Website Detector Using Web Security Analysis (TYCS Project).

Run this standalone script to train the Random Forest model and inspect
accuracy, confusion matrix, precision, recall, and feature importances.

Command to run:
    python train_ai_model.py
"""

import os
import sys
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer.ai_detector import (
    TRAINING_DATASET,
    FEATURE_NAMES,
    extract_ml_features,
    MODEL_PATH,
    MODEL_DIR
)


def main():
    print("=" * 70)
    print("   FAKE WEBSITE DETECTOR - AI / MACHINE LEARNING MODEL TRAINING")
    print("   Algorithm: Random Forest Classifier (Ensemble of Decision Trees)")
    print("=" * 70)

    # 1. Feature Extraction on Dataset
    print(f"\n[*] Extracting {len(FEATURE_NAMES)}-dimensional feature vectors for {len(TRAINING_DATASET)} samples...")
    X_list = []
    y_list = []

    for url, label in TRAINING_DATASET:
        vec, _ = extract_ml_features(url)
        X_list.append(vec)
        y_list.append(label)

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)

    # Count classes
    n_legit = int(np.sum(y == 0))
    n_phish = int(np.sum(y == 1))
    print(f"[+] Total Dataset Size: {len(X)} URLs")
    print(f"    - Legitimate URLs (Class 0): {n_legit}")
    print(f"    - Phishing URLs   (Class 1): {n_phish}")

    # 2. Train / Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"[*] Data Partitioning: Training Set = {len(X_train)}, Testing Set = {len(X_test)}")

    # 3. Model Training
    print("[*] Training Random Forest with 100 Estimators...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=2,
        random_state=42
    )
    rf.fit(X_train, y_train)

    # 4. Evaluation on Testing Set
    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred) * 100.0

    print("\n" + "-" * 70)
    print(f"[+] MODEL EVALUATION ACCURACY: {acc:.2f}%")
    print("-" * 70)

    print("\n[+] Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    True Legitimate  (TN): {cm[0][0]:<4} | False Phishing (FP): {cm[0][1]}")
    print(f"    False Legitimate (FN): {cm[1][0]:<4} | True Phishing  (TP): {cm[1][1]}")

    print("\n[+] Classification Report:")
    target_names = ["Legitimate (0)", "Phishing (1)"]
    print(classification_report(y_test, y_pred, target_names=target_names, digits=3))

    # 5. Feature Importances (Explainable AI / XAI)
    print("[+] Top Feature Importances (What the AI Learned):")
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx, 1):
        feat_name = FEATURE_NAMES[idx].replace("_", " ").title()
        pct = importances[idx] * 100
        bar = "#" * int(pct / 2)
        print(f"    {rank:2d}. {feat_name:<26} : {pct:5.2f}%  {bar}")

    # 6. Model Persistence
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(rf, MODEL_PATH)
    print(f"\n[+] Trained Model successfully saved to:\n    {MODEL_PATH}")

    # 7. Quick Sample Inference Test
    print("\n" + "=" * 70)
    print("   SAMPLE AI INFERENCE TEST (INCLUDING TYPOSQUATTING)")
    print("=" * 70)
    test_samples = [
        "https://www.google.com/",
        "https://go0gle.com/",
        "http://paypa1.com/login",
        "https://amaz0n.com/",
        "http://paypal-security-update.account-verify.xyz/login"
    ]
    for sample in test_samples:
        v, _ = extract_ml_features(sample)
        prob = rf.predict_proba(v.reshape(1, -1))[0]
        verdict = "PHISHING / TYPOSQUAT" if prob[1] >= 0.5 else "LEGITIMATE"
        print(f"  URL: {sample}")
        print(f"  --> AI Prediction: [{verdict}] (Phishing Probability: {prob[1]*100:.1f}%)\n")

    print("[*] Training pipeline finished successfully.")


if __name__ == "__main__":
    main()
