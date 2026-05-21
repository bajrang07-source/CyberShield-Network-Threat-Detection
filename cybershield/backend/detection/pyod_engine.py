"""
detection/pyod_engine.py
────────────────────────────────────────────────────────────────────────────────
PyOD-based anomaly detection engine (Phase 2).

Uses two complementary algorithms from the PyOD library:
  • IsolationForest  — tree-based global anomaly detection
  • COPOD            — copula-based multivariate outlier detection

Both are trained on normal traffic baselines extracted from LogEvent objects.
The final score is the clamp-normalized average of both models' decision scores.

Key contract: if models are untrained, score() returns 0.5 (neutral) — NEVER crashes.
"""
from __future__ import annotations

import logging
import os
import pickle
from collections import Counter
from datetime import datetime
from typing import List, Optional

import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ml", "pyod_model.pkl",
)

# ── Lazy PyOD import ──────────────────────────────────────────────────────────
try:
    from pyod.models.iforest import IForest   # type: ignore
    from pyod.models.copod import COPOD       # type: ignore
    _PYOD_AVAILABLE = True
except ImportError:
    IForest = None   # type: ignore[assignment,misc]
    COPOD = None     # type: ignore[assignment,misc]
    _PYOD_AVAILABLE = False
    logger.warning(
        "[PyODEngine] 'pyod' package not installed. "
        "score() will return 0.5. Install: pip install pyod"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction (independent of existing feature_extractor.py)
# ─────────────────────────────────────────────────────────────────────────────

def _endpoint_hash(path: str) -> float:
    """Stable float hash of a URL path (0.0–1.0 range)."""
    if not path:
        return 0.0
    h = hash(path.split("?")[0].lower()) & 0xFFFFFF
    return h / float(0xFFFFFF)


def _special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    specials = sum(1 for c in text if c in "'\";<>/\\()==--")
    return min(specials / max(len(text), 1), 1.0)


def _extract_pyod_features(log_event) -> np.ndarray:
    """Extract a 6-element numeric feature vector from a LogEvent.

    Features:
      0  payload_length          (log-scaled)
      1  special_char_ratio      (0.0–1.0)
      2  request_freq_1min       (from payload['request_rate_1m'] if present)
      3  hour_of_day             (0–23, normalized to 0–1)
      4  day_of_week             (0–6, normalized to 0–1)
      5  endpoint_hash           (0.0–1.0 stable float)
    """
    raw = log_event.raw_data or ""
    payload = log_event.payload or {}

    payload_len = np.log1p(len(raw))
    spec_ratio = _special_char_ratio(raw)
    req_freq = float(payload.get("request_rate_1m", payload.get("rate", 1)))
    req_freq = np.log1p(req_freq)

    ts = log_event.timestamp if isinstance(log_event.timestamp, datetime) else datetime.utcnow()
    hour_norm = ts.hour / 23.0
    dow_norm = ts.weekday() / 6.0

    # path: prefer payload["path"], then payload["url"], else empty
    path = payload.get("path", payload.get("url", ""))
    ep_hash = _endpoint_hash(str(path))

    return np.array([[payload_len, spec_ratio, req_freq, hour_norm, dow_norm, ep_hash]], dtype=float)


# ─────────────────────────────────────────────────────────────────────────────
# Engine class
# ─────────────────────────────────────────────────────────────────────────────

class PyODEngine:
    """Dual-model anomaly scoring engine (IsolationForest + COPOD).

    Usage::

        engine = PyODEngine()
        engine.fit_baseline(log_events)     # train once on normal traffic
        score = engine.score(log_event)     # 0.0 (normal) – 1.0 (anomalous)
        engine.save_model()
    """

    def __init__(self) -> None:
        self._trained = False
        self._if_model = None
        self._copod_model = None

    # ── Training ──────────────────────────────────────────────────────────────

    def fit_baseline(self, events: list) -> None:
        """Train both models on a list of LogEvent objects (normal traffic).

        Args:
            events: List of :class:`~ingestion.schema.LogEvent` instances
                    representing baseline (clean) traffic.
        """
        if not _PYOD_AVAILABLE:
            logger.warning("[PyODEngine] PyOD not available — skipping fit_baseline.")
            return
        if len(events) < 5:
            logger.warning("[PyODEngine] Need at least 5 events to fit. Got %d.", len(events))
            return

        try:
            X = np.vstack([_extract_pyod_features(e) for e in events])
            self._if_model = IForest(contamination=0.1, random_state=42, n_estimators=100)
            self._if_model.fit(X)
            self._copod_model = COPOD(contamination=0.1)
            self._copod_model.fit(X)
            self._trained = True
            logger.info("[PyODEngine] Fitted on %d events.", len(events))
        except Exception as exc:
            logger.error("[PyODEngine] fit_baseline error: %s", exc)

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, log_event) -> float:
        """Return anomaly score 0.0 (normal) – 1.0 (highly anomalous).

        Returns 0.5 (neutral) if models are untrained or any error occurs.
        """
        if not self._trained or self._if_model is None or self._copod_model is None:
            return 0.5  # neutral — never alarm on untrained model

        try:
            X = _extract_pyod_features(log_event)

            # IsolationForest: decision_function is lower for outliers
            if_raw = float(self._if_model.decision_function(X)[0])
            # COPOD: decision_function also lower for outliers
            copod_raw = float(self._copod_model.decision_function(X)[0])

            # Normalize each to 0-1.  PyOD decision scores are negative for outliers.
            # Typical range [-1, 0.5]; we clip and invert so outlier→1.0
            def _norm(raw: float, lo: float = -1.0, hi: float = 0.5) -> float:
                normalized = (raw - lo) / max(hi - lo, 1e-9)
                inverted = 1.0 - float(np.clip(normalized, 0.0, 1.0))
                return inverted

            if_score    = _norm(if_raw)
            copod_score = _norm(copod_raw)
            combined    = (if_score + copod_score) / 2.0
            return float(np.clip(combined, 0.0, 1.0))

        except Exception as exc:
            logger.warning("[PyODEngine] score() error: %s — returning 0.5", exc)
            return 0.5

    # ── Persistence ───────────────────────────────────────────────────────────

    def save_model(self, path: str = _DEFAULT_MODEL_PATH) -> None:
        """Persist trained models to *path*."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            bundle = {
                "if_model":    self._if_model,
                "copod_model": self._copod_model,
                "trained":     self._trained,
                "saved_at":    datetime.utcnow(),
            }
            with open(path, "wb") as f:
                pickle.dump(bundle, f)
            logger.info("[PyODEngine] Model saved to %s", path)
        except Exception as exc:
            logger.error("[PyODEngine] save_model error: %s", exc)

    def load_model(self, path: str = _DEFAULT_MODEL_PATH) -> None:
        """Load persisted models from *path*.

        Falls back to untrained state (score=0.5) if file is missing or corrupt.
        """
        try:
            with open(path, "rb") as f:
                bundle = pickle.load(f)
            self._if_model    = bundle.get("if_model")
            self._copod_model = bundle.get("copod_model")
            self._trained     = bool(bundle.get("trained", False))
            saved_at = bundle.get("saved_at", "unknown")
            logger.info("[PyODEngine] Model loaded from %s (saved: %s)", path, saved_at)
        except FileNotFoundError:
            logger.info("[PyODEngine] No saved model at %s — starting untrained.", path)
        except Exception as exc:
            logger.warning("[PyODEngine] load_model error: %s — starting untrained.", exc)

    @property
    def is_trained(self) -> bool:
        return self._trained


# Module-level singleton — load from disk if available
pyod_engine = PyODEngine()
pyod_engine.load_model()
