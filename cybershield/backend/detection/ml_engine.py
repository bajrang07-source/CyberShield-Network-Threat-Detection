"""
ML-based detection engine — singleton that lazy-loads model.pkl.
Returns an ensemble anomaly score between 0.0 (clean) and 1.0 (malicious).
"""
import os
import pickle
import logging
import threading
from datetime import datetime
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")


class MLEngine:
    """Thread-safe singleton ML engine."""

    _instance: Optional["MLEngine"] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._loaded = False
                    cls._instance._bundle = None
        return cls._instance

    def _load(self):
        if self._loaded:
            return
        try:
            with open(_MODEL_PATH, "rb") as f:
                self._bundle = pickle.load(f)
            self._loaded = True
            logger.info(
                "[MLEngine] Model loaded. Trained at: %s",
                self._bundle.get("trained_at", "unknown"),
            )
        except FileNotFoundError:
            logger.warning(
                "[MLEngine] model.pkl not found at %s. Falling back to 0.5.", _MODEL_PATH
            )
            self._loaded = False
            self._bundle = None

    def predict(self, feature_vector: np.ndarray) -> float:
        """
        Returns ensemble anomaly score in [0.0, 1.0].
        Higher = more likely malicious.
        """
        self._load()

        if not self._loaded or self._bundle is None:
            return 0.5  # fallback

        bundle = self._bundle
        scaler = bundle["scaler"]
        if_model = bundle["if_model"]
        lr_model = bundle["lr_model"]

        try:
            X = scaler.transform(feature_vector)

            # ── IsolationForest score ──────────────────────────────────────────
            if_raw = if_model.decision_function(X)[0]
            # Normalize using training score distribution boundaries
            # Typical range approximately [-0.5, 0.5]; clip to [-1, 1] then scale
            if_min, if_max = -0.5, 0.5
            if_normalized = (if_raw - if_min) / (if_max - if_min)
            if_normalized = float(np.clip(if_normalized, 0.0, 1.0))
            if_score = 1.0 - if_normalized  # invert: anomaly → high score

            # ── Logistic Regression score ──────────────────────────────────────
            lr_score = float(lr_model.predict_proba(X)[0, 1])

            # ── Ensemble ──────────────────────────────────────────────────────
            ensemble = 0.6 * if_score + 0.4 * lr_score
            return float(np.clip(ensemble, 0.0, 1.0))

        except Exception as exc:
            logger.error("[MLEngine] Prediction error: %s", exc)
            return 0.5

    def model_info(self) -> dict:
        """Return metadata about the loaded model."""
        self._load()
        if not self._loaded or self._bundle is None:
            return {"model_type": "none", "trained_at": None, "feature_names": []}

        trained_at = self._bundle.get("trained_at")
        return {
            "model_type": "IsolationForest + LogisticRegression (ensemble)",
            "trained_at": trained_at.isoformat() if isinstance(trained_at, datetime) else str(trained_at),
            "feature_names": self._bundle.get("feature_names", []),
        }

    @property
    def is_loaded(self) -> bool:
        self._load()
        return self._loaded


# Module-level singleton instance
ml_engine = MLEngine()
