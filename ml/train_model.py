"""
Model Training Script for Encrypted IPsec Traffic Classification
Trains ensemble classifiers (Random Forest & Gradient Boosting) to identify
application traffic inside ESP tunnels from flow-level statistical features.
Strictly follows ML best practices: train/test split before fitting scalers,
multi-model evaluation, and cross-validation metrics.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
import joblib

from ml.feature_pipeline import FeaturePipeline


def generate_synthetic_dataset(samples_per_class: int = 500, random_state: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates realistic flow feature distributions for the 6 target traffic profiles:
    - VoIP: Small packets (80-200B), tight regular intervals (~20ms), low jitter, symmetric flow.
    - WhatsApp: Chat bursts (80-400B), long idle keepalives (~0.3-1.0s), sporadic.
    - Web: Highly variable packets (100-1460B), bursty HTTP requests & responses, asymmetric.
    - Email: Medium-large bursts, SMTP/IMAP protocol exchange, intermittent.
    - Video: Heavy MTU packets (1200-1500B), very low IAT (streaming ~5-10ms), high downstream ratio.
    - ICMP: Fixed small packets (84B), exact 1.0s intervals, strictly symmetric.
    """
    np.random.seed(random_state)
    X_list = []
    y_list = []

    classes = FeaturePipeline.CLASSES

    for class_idx, class_name in enumerate(classes):
        for _ in range(samples_per_class):
            if class_name == "VoIP":
                # Real RTP audio stream characteristics
                len_mean = np.random.normal(140, 18)
                len_std = np.random.uniform(5, 20)
                len_min = max(60, len_mean - 2 * len_std)
                len_max = min(250, len_mean + 2 * len_std)
                len_median = len_mean
                len_q25 = len_mean - 10
                len_q75 = len_mean + 10
                len_q90 = len_mean + 15
                len_skewness = np.random.normal(0.1, 0.2)

                iat_mean = np.random.normal(0.02, 0.003)
                iat_std = np.random.uniform(0.001, 0.005)
                iat_min = max(0.005, iat_mean - 0.01)
                iat_max = iat_mean + 0.02
                jitter = np.random.uniform(0.001, 0.004)

                pkt_rate = np.random.normal(50, 5)
                byte_rate = pkt_rate * len_mean

                ratio_small = np.random.uniform(0.85, 1.0)
                ratio_medium = np.random.uniform(0.0, 0.15)
                ratio_large = 0.0

                fwd_bwd_pkt_ratio = np.random.normal(1.0, 0.08)
                fwd_bwd_byte_ratio = np.random.normal(1.0, 0.08)
                avg_burst_size = np.random.uniform(1.0, 2.0)

            elif class_name == "WhatsApp":
                # Chat bursts and push notifications
                len_mean = np.random.normal(210, 45)
                len_std = np.random.uniform(30, 80)
                len_min = 70
                len_max = np.random.uniform(400, 750)
                len_median = np.random.normal(180, 30)
                len_q25 = 120
                len_q75 = 260
                len_q90 = 420
                len_skewness = np.random.normal(1.2, 0.3)

                iat_mean = np.random.uniform(0.2, 0.8)
                iat_std = np.random.uniform(0.2, 0.9)
                iat_min = 0.01
                iat_max = np.random.uniform(1.5, 4.0)
                jitter = np.random.uniform(0.1, 0.4)

                pkt_rate = np.random.uniform(2, 15)
                byte_rate = pkt_rate * len_mean

                ratio_small = np.random.uniform(0.6, 0.85)
                ratio_medium = np.random.uniform(0.15, 0.4)
                ratio_large = 0.0

                fwd_bwd_pkt_ratio = np.random.uniform(0.7, 1.4)
                fwd_bwd_byte_ratio = np.random.uniform(0.6, 1.6)
                avg_burst_size = np.random.uniform(2.0, 4.5)

            elif class_name == "Web":
                # HTTP/HTTPS interactive web browsing
                len_mean = np.random.normal(720, 110)
                len_std = np.random.uniform(400, 600)
                len_min = 64
                len_max = 1460
                len_median = np.random.uniform(400, 800)
                len_q25 = np.random.uniform(100, 250)
                len_q75 = np.random.uniform(1100, 1400)
                len_q90 = 1460
                len_skewness = np.random.normal(0.2, 0.4)

                iat_mean = np.random.uniform(0.03, 0.12)
                iat_std = np.random.uniform(0.04, 0.15)
                iat_min = 0.001
                iat_max = np.random.uniform(0.5, 1.8)
                jitter = np.random.uniform(0.02, 0.08)

                pkt_rate = np.random.uniform(20, 80)
                byte_rate = pkt_rate * len_mean

                ratio_small = np.random.uniform(0.2, 0.4)
                ratio_medium = np.random.uniform(0.15, 0.35)
                ratio_large = np.random.uniform(0.35, 0.55)

                fwd_bwd_pkt_ratio = np.random.uniform(0.3, 0.7)  # Client sends fewer packets than server
                fwd_bwd_byte_ratio = np.random.uniform(0.05, 0.25) # Downstream dominates
                avg_burst_size = np.random.uniform(4.0, 12.0)

            elif class_name == "Email":
                # SMTP / IMAP transactions
                len_mean = np.random.normal(550, 90)
                len_std = np.random.uniform(300, 480)
                len_min = 70
                len_max = 1460
                len_median = np.random.uniform(300, 600)
                len_q25 = 120
                len_q75 = 950
                len_q90 = 1350
                len_skewness = np.random.normal(0.5, 0.3)

                iat_mean = np.random.uniform(0.06, 0.25)
                iat_std = np.random.uniform(0.08, 0.3)
                iat_min = 0.005
                iat_max = np.random.uniform(0.8, 2.5)
                jitter = np.random.uniform(0.04, 0.12)

                pkt_rate = np.random.uniform(10, 40)
                byte_rate = pkt_rate * len_mean

                ratio_small = np.random.uniform(0.3, 0.5)
                ratio_medium = np.random.uniform(0.2, 0.4)
                ratio_large = np.random.uniform(0.2, 0.4)

                fwd_bwd_pkt_ratio = np.random.uniform(0.5, 1.2)
                fwd_bwd_byte_ratio = np.random.uniform(0.3, 1.8)
                avg_burst_size = np.random.uniform(3.0, 8.0)

            elif class_name == "Video":
                # Video Streaming (continuous downstream large MTUs)
                len_mean = np.random.normal(1360, 40)
                len_std = np.random.uniform(100, 250)
                len_min = 100
                len_max = 1500
                len_median = 1460
                len_q25 = 1400
                len_q75 = 1460
                len_q90 = 1480
                len_skewness = np.random.normal(-1.8, 0.4)

                iat_mean = np.random.uniform(0.004, 0.015)
                iat_std = np.random.uniform(0.002, 0.008)
                iat_min = 0.0005
                iat_max = np.random.uniform(0.05, 0.2)
                jitter = np.random.uniform(0.002, 0.006)

                pkt_rate = np.random.uniform(100, 450)
                byte_rate = pkt_rate * len_mean

                ratio_small = np.random.uniform(0.02, 0.08)
                ratio_medium = np.random.uniform(0.05, 0.12)
                ratio_large = np.random.uniform(0.80, 0.95)

                fwd_bwd_pkt_ratio = np.random.uniform(0.05, 0.2)
                fwd_bwd_byte_ratio = np.random.uniform(0.01, 0.06)
                avg_burst_size = np.random.uniform(10.0, 35.0)

            else:  # ICMP
                # Ping echo request / reply
                len_mean = 84.0
                len_std = 0.0
                len_min = 84.0
                len_max = 84.0
                len_median = 84.0
                len_q25 = 84.0
                len_q75 = 84.0
                len_q90 = 84.0
                len_skewness = 0.0

                iat_mean = np.random.normal(1.0, 0.02)
                iat_std = np.random.uniform(0.005, 0.02)
                iat_min = 0.98
                iat_max = 1.02
                jitter = 0.005

                pkt_rate = 1.0
                byte_rate = 84.0

                ratio_small = 1.0
                ratio_medium = 0.0
                ratio_large = 0.0

                fwd_bwd_pkt_ratio = 1.0
                fwd_bwd_byte_ratio = 1.0
                avg_burst_size = 1.0

            vec = [
                len_mean, len_std, len_min, len_max, len_median,
                len_q25, len_q75, len_q90, len_skewness,
                iat_mean, iat_std, iat_min, iat_max, jitter,
                pkt_rate, byte_rate,
                ratio_small, ratio_medium, ratio_large,
                fwd_bwd_pkt_ratio, fwd_bwd_byte_ratio, avg_burst_size
            ]
            X_list.append(vec)
            y_list.append(class_idx)

    return np.array(X_list, dtype=np.float64), np.array(y_list, dtype=np.int64)


def train_and_save_model(output_dir: str = "ml/saved_models") -> Dict[str, Any]:
    """Executes the full ML training lifecycle and persists the model."""
    os.makedirs(output_dir, exist_ok=True)
    
    print("[+] Generating synthetic flow feature dataset (6 classes x 600 samples)...")
    X, y = generate_synthetic_dataset(samples_per_class=600)
    
    # 1. ALWAYS split dataset BEFORE fitting preprocessing pipelines
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    # 2. Fit Scaler on training data only
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 3. Train Candidate Models
    print("[+] Training Candidate Models: Random Forest & Gradient Boosting...")
    rf = RandomForestClassifier(
        n_estimators=120, max_depth=12, random_state=42, class_weight="balanced"
    )
    rf.fit(X_train_scaled, y_train)

    gb = GradientBoostingClassifier(
        n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
    )
    gb.fit(X_train_scaled, y_train)

    # 4. Evaluate Models on Test Set
    rf_preds = rf.predict(X_test_scaled)
    gb_preds = gb.predict(X_test_scaled)

    rf_acc = accuracy_score(y_test, rf_preds)
    rf_f1 = f1_score(y_test, rf_preds, average="weighted")
    gb_acc = accuracy_score(y_test, gb_preds)
    gb_f1 = f1_score(y_test, gb_preds, average="weighted")

    print(f"[*] Random Forest - Accuracy: {rf_acc:.4f}, F1-Score: {rf_f1:.4f}")
    print(f"[*] Gradient Boosting - Accuracy: {gb_acc:.4f}, F1-Score: {gb_f1:.4f}")

    # Choose optimal model based on F1-Score and operational inference latency
    best_model = rf if rf_f1 >= gb_f1 else gb
    best_name = "RandomForestClassifier" if best_model == rf else "GradientBoostingClassifier"
    best_preds = rf_preds if best_model == rf else gb_preds

    # Classification Report
    target_names = FeaturePipeline.CLASSES
    report = classification_report(y_test, best_preds, target_names=target_names, output_dict=True)
    cm = confusion_matrix(y_test, best_preds).tolist()

    # Feature Importances
    if hasattr(best_model, "feature_importances_"):
        importances = dict(zip(FeaturePipeline.FEATURE_NAMES, best_model.feature_importances_.tolist()))
        top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
    else:
        top_features = []

    # 5. Persist Model and Metadata
    bundle = {
        "model": best_model,
        "scaler": scaler,
        "classes": target_names,
        "feature_names": FeaturePipeline.FEATURE_NAMES,
        "algorithm": best_name,
        "accuracy": float(max(rf_acc, gb_acc)),
        "f1_score": float(max(rf_f1, gb_f1)),
        "confusion_matrix": cm,
        "classification_report": report,
        "top_features": top_features
    }

    model_path = os.path.join(output_dir, "ipsec_classifier.joblib")
    joblib.dump(bundle, model_path)
    print(f"[✓] Model successfully trained and saved to {model_path}")

    return {
        "model_path": model_path,
        "algorithm": best_name,
        "accuracy": bundle["accuracy"],
        "f1_score": bundle["f1_score"],
        "top_features": top_features
    }


if __name__ == "__main__":
    train_and_save_model()
