"""
detection/timeseries_engine.py
────────────────────────────────────────────────────────────────────────────────
Time-series behavioral analysis engine (Phase 2).

Maintains a sliding window of recent LogEvents per source IP and computes
statistical features to detect bot-like patterns, scanners, and request floods.

No external dependencies beyond the standard library — deliberately avoids
tsfresh for zero-install overhead while implementing equivalent feature logic.
"""
from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Optional

logger = logging.getLogger(__name__)

# ── Configuration constants ───────────────────────────────────────────────────
_WINDOW_SECONDS  = 300          # 5-minute sliding window
_MAX_EVENTS_TOTAL = 1000        # global cap across all IPs
_MAX_EVENTS_PER_IP = 200        # per-IP deque cap
_MIN_EVENTS_FOR_SCORE = 3       # fewer events → return 0.0 (insufficient data)

# Threshold-based score contributions
_THRESHOLD_REQ_COUNT    = 60    # requests in window before high-freq penalty
_THRESHOLD_STD_INTERVAL = 0.1   # seconds — below this = bot-like regularity
_THRESHOLD_UNIQUE_EP    = 30    # unique endpoints before scanner penalty


# ─────────────────────────────────────────────────────────────────────────────
# Lightweight event record (avoids dependency on full LogEvent for in-memory store)
# ─────────────────────────────────────────────────────────────────────────────

class _Record:
    __slots__ = ("ts", "path", "action")

    def __init__(self, ts: float, path: str, action: str):
        self.ts = ts           # epoch float
        self.path = path       # URL path (endpoint)
        self.action = action   # "allow" | "block" | "fail" | etc.


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(paths: list) -> float:
    """Compute Shannon entropy of endpoint distribution."""
    if not paths:
        return 0.0
    counter: Dict[str, int] = {}
    for p in paths:
        counter[p] = counter.get(p, 0) + 1
    n = len(paths)
    return -sum((c / n) * math.log2(c / n) for c in counter.values())


def _mean_and_std(values: list) -> tuple:
    """Return (mean, std) for a list of floats."""
    if not values:
        return 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    return mean, math.sqrt(variance)


# ─────────────────────────────────────────────────────────────────────────────
# Engine class
# ─────────────────────────────────────────────────────────────────────────────

class TimeseriesEngine:
    """Sliding-window, per-IP time-series anomaly detector.

    Usage::

        engine = TimeseriesEngine()
        engine.record(log_event)           # call for every ingested event
        score = engine.score("10.0.0.1")   # 0.0 (normal) – 1.0 (bot/scanner)
    """

    def __init__(self) -> None:
        # Per-IP deque of _Record instances within the sliding window
        self._windows: Dict[str, Deque[_Record]] = defaultdict(
            lambda: deque(maxlen=_MAX_EVENTS_PER_IP)
        )
        # Total event counter across all IPs (for global cap enforcement)
        self._total_events: int = 0

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def record(self, log_event) -> None:
        """Record a LogEvent in the sliding window for its source IP.

        This is additive — call it for every event that flows through the system.
        """
        try:
            ip = str(getattr(log_event, "source_ip", "0.0.0.0") or "0.0.0.0")
            payload = getattr(log_event, "payload", {}) or {}
            ts = getattr(log_event, "timestamp", None)
            epoch = ts.timestamp() if isinstance(ts, datetime) else time.time()

            path = str(payload.get("path", payload.get("url", "/")))
            action = str(getattr(log_event, "action", "none") or "none")

            # Prune events outside the window BEFORE appending
            self._prune_ip(ip, epoch)

            rec = _Record(ts=epoch, path=path, action=action)
            self._windows[ip].append(rec)
            self._total_events += 1

            # Global cap: drop oldest IP's oldest events if over limit
            if self._total_events > _MAX_EVENTS_TOTAL:
                self._evict_oldest()

        except Exception as exc:
            logger.debug("[TimeseriesEngine] record() error: %s", exc)

    def _prune_ip(self, ip: str, now: float) -> None:
        """Remove records outside the sliding window for a single IP."""
        dq = self._windows.get(ip)
        if not dq:
            return
        cutoff = now - _WINDOW_SECONDS
        while dq and dq[0].ts < cutoff:
            dq.popleft()
            self._total_events = max(0, self._total_events - 1)

    def _evict_oldest(self) -> None:
        """Evict the oldest events across all IPs to stay under the global cap."""
        now = time.time()
        for ip, dq in list(self._windows.items()):
            self._prune_ip(ip, now)
            if not dq:
                del self._windows[ip]
            if self._total_events <= _MAX_EVENTS_TOTAL * 0.9:
                break

    # ── Feature extraction ────────────────────────────────────────────────────

    def extract_features(self, ip: str) -> Optional[Dict]:
        """Extract time-series features for *ip* over the last 5 minutes.

        Returns:
            dict of features, or None if fewer than 3 events in the window.
        """
        try:
            now = time.time()
            self._prune_ip(ip, now)
            dq = self._windows.get(ip)

            if not dq or len(dq) < _MIN_EVENTS_FOR_SCORE:
                return None

            records = list(dq)
            n = len(records)

            # Inter-arrival intervals
            timestamps = [r.ts for r in records]
            intervals = [timestamps[i+1] - timestamps[i] for i in range(n - 1)]
            mean_interval, std_interval = _mean_and_std(intervals)

            # Endpoint diversity
            paths = [r.path for r in records]
            unique_endpoints = len(set(paths))
            ep_entropy = _shannon_entropy(paths)

            # Error / failure rate
            fail_keywords = {"fail", "error", "block", "deny", "reject"}
            error_count = sum(
                1 for r in records
                if any(kw in r.action.lower() for kw in fail_keywords)
            )
            error_rate = error_count / n

            return {
                "request_count":       n,
                "mean_interval_sec":   mean_interval,
                "std_interval_sec":    std_interval,
                "unique_endpoints":    unique_endpoints,
                "error_rate":          error_rate,
                "endpoint_entropy":    ep_entropy,
                "window_seconds":      _WINDOW_SECONDS,
            }
        except Exception as exc:
            logger.debug("[TimeseriesEngine] extract_features(%s) error: %s", ip, exc)
            return None

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, ip: str) -> float:
        """Return time-series anomaly score 0.0 (normal) – 1.0 (bot/scanner).

        Returns 0.0 if fewer than 3 events in the window (insufficient data).
        """
        try:
            features = self.extract_features(ip)
            if features is None:
                return 0.0

            raw = 0.0

            # ── Rule 1: High request count (flood / DoS) ──────────────────────
            req = features["request_count"]
            if req > _THRESHOLD_REQ_COUNT:
                # Scale 0.4 for 60 req, up to 0.7 for 300+
                flood_contrib = min(0.4 + 0.3 * (req - _THRESHOLD_REQ_COUNT) / 240.0, 0.7)
                raw += flood_contrib

            # ── Rule 2: Bot-like regularity (very low std_interval) ───────────
            std = features["std_interval_sec"]
            if std < _THRESHOLD_STD_INTERVAL and features["mean_interval_sec"] > 0:
                raw += 0.3

            # ── Rule 3: Scanner pattern (high unique endpoints) ───────────────
            unique_ep = features["unique_endpoints"]
            if unique_ep > _THRESHOLD_UNIQUE_EP:
                scan_contrib = min(0.3 + 0.2 * (unique_ep - _THRESHOLD_UNIQUE_EP) / 70.0, 0.5)
                raw += scan_contrib

            # Clamp and return
            return float(min(raw, 1.0))

        except Exception as exc:
            logger.warning("[TimeseriesEngine] score(%s) error: %s", ip, exc)
            return 0.0

    @property
    def tracked_ip_count(self) -> int:
        """Number of IPs currently tracked in memory."""
        return len(self._windows)


# Module-level singleton
ts_engine = TimeseriesEngine()
