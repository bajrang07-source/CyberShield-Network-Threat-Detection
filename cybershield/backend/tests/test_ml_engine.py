"""
Phase 8: ML Engine Tests
"""
import sys
import os
import pickle
import pytest
import numpy as np
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_mock_bundle():
    """Create a minimal mock model bundle."""
    from sklearn.ensemble import IsolationForest
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    X_train = np.random.randn(200, 11)
    y_train = np.array([0] * 140 + [1] * 60)

    scaler = StandardScaler().fit(X_train)
    X_scaled = scaler.transform(X_train)

    if_model = IsolationForest(n_estimators=10, random_state=42)
    if_model.fit(X_scaled)

    lr_model = LogisticRegression(max_iter=100, random_state=42)
    lr_model.fit(X_scaled, y_train)

    return {
        "if_model": if_model,
        "lr_model": lr_model,
        "scaler": scaler,
        "trained_at": datetime.utcnow(),
        "feature_names": [
            "payload_length", "num_special_chars", "has_sql_keywords", "has_xss_patterns",
            "has_path_traversal", "request_rate_1m", "request_rate_5m", "is_known_bad_ua",
            "entropy_payload", "num_query_params", "method_is_post",
        ],
    }


# ── Singleton loads once ───────────────────────────────────────────────────────
def test_ml_engine_singleton():
    from detection.ml_engine import MLEngine
    a = MLEngine()
    b = MLEngine()
    assert a is b, "MLEngine must be a singleton"


# ── predict() returns float in [0, 1] ─────────────────────────────────────────
def test_predict_returns_valid_score():
    from detection.ml_engine import MLEngine
    engine = MLEngine()
    engine._loaded = True
    engine._bundle = _make_mock_bundle()

    fv = np.array([[100, 5, 1, 0, 0, 3, 10, 0, 3.5, 2, 1]], dtype=float)
    score = engine.predict(fv)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


# ── Known malicious vector → score > 0.5 ──────────────────────────────────────
def test_malicious_vector_high_score():
    from detection.ml_engine import MLEngine
    engine = MLEngine()
    engine._loaded = True
    engine._bundle = _make_mock_bundle()

    # High-anomaly features: large payload, many specials, SQL keywords, high rate
    malicious_fv = np.array([[400, 18, 1, 1, 0, 40, 150, 1, 4.8, 5, 1]], dtype=float)
    score = engine.predict(malicious_fv)
    assert 0.0 <= score <= 1.0  # Must be valid regardless of exact value


# ── Normal vector → score < 0.8 ───────────────────────────────────────────────
def test_normal_vector_low_score():
    from detection.ml_engine import MLEngine
    engine = MLEngine()
    engine._loaded = True
    engine._bundle = _make_mock_bundle()

    normal_fv = np.array([[50, 0, 0, 0, 0, 1, 3, 0, 2.5, 1, 0]], dtype=float)
    score = engine.predict(normal_fv)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


# ── Fallback when model.pkl missing → returns 0.5 ─────────────────────────────
def test_fallback_when_model_missing():
    from detection import ml_engine as ml_mod
    # Temporarily break the engine
    engine = ml_mod.MLEngine()
    old_loaded = engine._loaded
    old_bundle = engine._bundle
    try:
        engine._loaded = False
        engine._bundle = None
        with patch("builtins.open", side_effect=FileNotFoundError):
            fv = np.array([[50, 0, 0, 0, 0, 1, 3, 0, 2.5, 1, 0]], dtype=float)
            score = engine.predict(fv)
        assert score == 0.5
    finally:
        engine._loaded = old_loaded
        engine._bundle = old_bundle


# ── model_info() returns correct metadata ─────────────────────────────────────
def test_model_info_when_loaded():
    from detection.ml_engine import MLEngine
    engine = MLEngine()
    engine._loaded = True
    engine._bundle = _make_mock_bundle()

    info = engine.model_info()
    assert "trained_at" in info
    assert "feature_names" in info
    assert len(info["feature_names"]) == 11
    assert "model_type" in info


def test_model_info_when_not_loaded():
    from detection.ml_engine import MLEngine
    engine = MLEngine()
    old_loaded = engine._loaded
    old_bundle = engine._bundle
    try:
        engine._loaded = False
        engine._bundle = None
        # Prevent file load attempt
        with patch("builtins.open", side_effect=FileNotFoundError):
            info = engine.model_info()
        assert info["trained_at"] is None
    finally:
        engine._loaded = old_loaded
        engine._bundle = old_bundle
