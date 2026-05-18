"""
Train IsolationForest + LogisticRegression ensemble model on the generated dataset.
Saves model.pkl to backend/ml/model.pkl
"""
import os
import sys
import pickle
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

FEATURE_NAMES = [
    "payload_length", "num_special_chars", "has_sql_keywords", "has_xss_patterns",
    "has_path_traversal", "request_rate_1m", "request_rate_5m", "is_known_bad_ua",
    "entropy_payload", "num_query_params", "method_is_post",
]


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(script_dir)
    csv_path = os.path.join(backend_dir, "data", "requests_labeled.csv")

    if not os.path.exists(csv_path):
        print(f"[train_model] Dataset not found at {csv_path}. Run generate_dataset.py first.")
        sys.exit(1)

    print(f"[train_model] Loading dataset from {csv_path} ...")
    df = pd.read_csv(csv_path)

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    print(f"[train_model] Dataset shape: {X.shape}, class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    # ── Scaler (fit on entire dataset) ─────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print("[train_model] Scaler fitted.")

    # ── IsolationForest (unsupervised, full dataset) ────────────────────────────
    print("[train_model] Training IsolationForest(n_estimators=200, contamination=0.15) ...")
    if_model = IsolationForest(n_estimators=200, contamination=0.15, random_state=42, n_jobs=-1)
    if_model.fit(X_scaled)
    print("[train_model] IsolationForest training complete.")

    # ── LogisticRegression (labeled subset) ─────────────────────────────────────
    labeled_mask = y != -1  # all rows have 0/1 labels here
    X_lr = X_scaled[labeled_mask]
    y_lr = y[labeled_mask]

    X_train, X_test, y_train, y_test = train_test_split(
        X_lr, y_lr, test_size=0.2, random_state=42, stratify=y_lr
    )

    print("[train_model] Training LogisticRegression(max_iter=1000) ...")
    lr_model = LogisticRegression(max_iter=1000, random_state=42, class_weight="balanced")
    lr_model.fit(X_train, y_train)

    y_pred = lr_model.predict(X_test)
    print("\n[train_model] Classification Report (Logistic Regression):")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    # Print per-class precision / recall / F1
    from sklearn.metrics import precision_recall_fscore_support
    prec, rec, f1, support = precision_recall_fscore_support(y_test, y_pred)
    for cls, p, r, f, s in zip(["Normal", "Attack"], prec, rec, f1, support):
        print(f"  {cls:8s} — Precision: {p:.3f}  Recall: {r:.3f}  F1: {f:.3f}  Support: {s}")

    # ── Save model bundle ────────────────────────────────────────────────────────
    model_bundle = {
        "if_model": if_model,
        "lr_model": lr_model,
        "scaler": scaler,
        "trained_at": datetime.utcnow(),
        "feature_names": FEATURE_NAMES,
    }

    model_path = os.path.join(script_dir, "model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model_bundle, f)

    print(f"\n[train_model] Model bundle saved to {model_path}")
    print(f"[train_model] Done. Trained at {model_bundle['trained_at'].isoformat()}Z")


if __name__ == "__main__":
    main()
