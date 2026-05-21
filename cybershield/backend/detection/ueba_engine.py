"""
detection/ueba_engine.py
────────────────────────────────────────────────────────────────────────────────
User and Entity Behavior Analytics engine (Phase 2).

Maintains rolling per-user behavioral profiles and scores new LogEvents against
the established baseline.  No external dependencies beyond the standard library
and the Phase 1 LogEvent schema.

Key design choices:
  • Unknown user → 0.3 (slight elevation, not an alarm)
  • All scoring is additive and clamped to 0.0–1.0
  • Profiles are persisted as JSON for restartability
"""
from __future__ import annotations

import json
import logging
import math
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_DEFAULT_PROFILES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ml", "ueba_profiles.json",
)

# ── Scoring weights ───────────────────────────────────────────────────────────
_W_HOUR      = 0.35   # unusual login hour
_W_ENDPOINT  = 0.25   # new endpoint never seen before
_W_RATE      = 0.25   # request rate spike
_W_UA        = 0.15   # new user agent not in baseline


# ─────────────────────────────────────────────────────────────────────────────
# UserProfile
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UserProfile:
    """Rolling 30-day behavioral fingerprint for a single user."""
    user_id: str
    typical_login_hours: List[int] = field(default_factory=list)       # list of ints 0-23
    endpoint_counter: Dict[str, int] = field(default_factory=dict)     # path → count
    typical_user_agents: List[str] = field(default_factory=list)       # known UA strings
    # Rate tracking: list of epoch-second timestamps of recent requests
    recent_request_times: List[float] = field(default_factory=list)    # last 1000 timestamps
    avg_requests_per_hour: float = 0.0
    total_events: int = 0
    last_seen: Optional[str] = None   # ISO string

    # 30-day rolling window in seconds
    _WINDOW = 30 * 24 * 3600

    def update(self, log_event) -> None:
        """Incorporate a new LogEvent into this profile."""
        ts = log_event.timestamp if isinstance(log_event.timestamp, datetime) else datetime.utcnow()
        now_epoch = ts.timestamp()

        # Prune old timestamps beyond 30-day window
        cutoff = now_epoch - self._WINDOW
        self.recent_request_times = [t for t in self.recent_request_times if t >= cutoff]
        self.recent_request_times.append(now_epoch)
        # Keep at most 5000 timestamps to bound memory
        if len(self.recent_request_times) > 5000:
            self.recent_request_times = self.recent_request_times[-5000:]

        # Update hour distribution
        self.typical_login_hours.append(ts.hour)
        if len(self.typical_login_hours) > 500:
            self.typical_login_hours = self.typical_login_hours[-500:]

        # Update endpoint counter
        payload = log_event.payload or {}
        path = payload.get("path", payload.get("url", ""))
        if path:
            self.endpoint_counter[str(path)] = self.endpoint_counter.get(str(path), 0) + 1

        # Update user agent
        ua = log_event.payload.get("user_agent", "") if isinstance(log_event.payload, dict) else ""
        if ua and ua not in self.typical_user_agents:
            self.typical_user_agents.append(ua)
            if len(self.typical_user_agents) > 50:
                self.typical_user_agents = self.typical_user_agents[-50:]

        # Recompute avg_requests_per_hour
        window_hours = max(
            (now_epoch - min(self.recent_request_times)) / 3600.0, 1.0
        ) if self.recent_request_times else 1.0
        self.avg_requests_per_hour = len(self.recent_request_times) / window_hours

        self.total_events += 1
        self.last_seen = ts.isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "typical_login_hours": self.typical_login_hours,
            "endpoint_counter": self.endpoint_counter,
            "typical_user_agents": self.typical_user_agents,
            "recent_request_times": self.recent_request_times[-200:],  # truncate for JSON size
            "avg_requests_per_hour": self.avg_requests_per_hour,
            "total_events": self.total_events,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "UserProfile":
        p = cls(user_id=d.get("user_id", "unknown"))
        p.typical_login_hours = d.get("typical_login_hours", [])
        p.endpoint_counter = d.get("endpoint_counter", {})
        p.typical_user_agents = d.get("typical_user_agents", [])
        p.recent_request_times = d.get("recent_request_times", [])
        p.avg_requests_per_hour = d.get("avg_requests_per_hour", 0.0)
        p.total_events = d.get("total_events", 0)
        p.last_seen = d.get("last_seen")
        return p


# ─────────────────────────────────────────────────────────────────────────────
# Scoring helpers
# ─────────────────────────────────────────────────────────────────────────────

def _hour_anomaly_score(profile: UserProfile, hour: int) -> float:
    """Score how unusual *hour* is relative to historical login hours.

    Returns 0.0 if hour is common, up to 1.0 if never seen.
    Uses a soft Gaussian-weighted neighbourhood: hour within ±1h of any
    historical hour gets a low score.
    """
    if not profile.typical_login_hours:
        return 0.0  # no baseline → can't judge

    hour_counts = Counter(profile.typical_login_hours)
    total = sum(hour_counts.values()) or 1

    # Circular distance (0-11 max on a 24h clock)
    def _circular_dist(a: int, b: int) -> int:
        return min(abs(a - b), 24 - abs(a - b))

    # Weighted score of neighbours
    weighted = 0.0
    for h, cnt in hour_counts.items():
        dist = _circular_dist(h, hour)
        weight = math.exp(-dist * dist / 4.0)   # Gaussian σ≈2h
        weighted += (cnt / total) * weight

    # weighted ∈ [0,1]; invert so rarity → high score
    return float(np.clip(1.0 - weighted, 0.0, 1.0)) if weighted < 1.0 else 0.0


# ── Numpy import for clip ─────────────────────────────────────────────────────
try:
    import numpy as np
    _CLIP = np.clip
except ImportError:
    def _CLIP(v, lo, hi): return max(lo, min(hi, v))  # type: ignore[assignment]


def _endpoint_anomaly_score(profile: UserProfile, path: str) -> float:
    """Score how unusual an endpoint is relative to the user's history."""
    if not profile.endpoint_counter:
        return 0.0
    if path in profile.endpoint_counter:
        # Known endpoint — score by relative frequency (rare = higher score)
        total = sum(profile.endpoint_counter.values()) or 1
        freq = profile.endpoint_counter[path] / total
        return float(_CLIP(1.0 - freq * 10, 0.0, 0.6))  # cap at 0.6 for known paths
    return 0.8  # completely new endpoint


def _rate_anomaly_score(profile: UserProfile, current_rpm: float) -> float:
    """Score request rate spike relative to the user's rolling average."""
    baseline = profile.avg_requests_per_hour
    if baseline < 1.0:
        return 0.0  # no baseline
    # current_rpm is per-minute; convert to per-hour
    current_rph = current_rpm * 60.0
    ratio = current_rph / baseline
    if ratio <= 2.0:
        return 0.0
    elif ratio <= 5.0:
        return 0.3
    elif ratio <= 10.0:
        return 0.6
    return 0.9


# ─────────────────────────────────────────────────────────────────────────────
# Engine class
# ─────────────────────────────────────────────────────────────────────────────

class UEBAEngine:
    """User and Entity Behavior Analytics engine.

    Usage::

        engine = UEBAEngine()
        engine.load_profiles()           # restore from disk
        engine.update_baseline(event)    # after every event
        score = engine.score(event)      # 0.0 (normal) – 1.0 (suspicious)
        engine.save_profiles()
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, UserProfile] = {}

    # ── Profile management ────────────────────────────────────────────────────

    def _get_or_create(self, user_id: str) -> UserProfile:
        if user_id not in self._profiles:
            self._profiles[user_id] = UserProfile(user_id=user_id)
        return self._profiles[user_id]

    def update_baseline(self, log_event) -> None:
        """Incorporate *log_event* into the relevant user's profile.

        If user_id is empty/None, the event is attributed to a special
        "__anonymous__" bucket.
        """
        try:
            uid = str(log_event.user_id or "__anonymous__")
            profile = self._get_or_create(uid)
            profile.update(log_event)
        except Exception as exc:
            logger.warning("[UEBAEngine] update_baseline error: %s", exc)

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, log_event) -> float:
        """Return user-behavior anomaly score 0.0 (normal) – 1.0 (suspicious).

        Returns 0.3 (slight elevation) for unknown users — not a full alarm.
        Returns 0.5 on any internal error.
        """
        try:
            uid = str(log_event.user_id or "__anonymous__")

            if uid not in self._profiles or self._profiles[uid].total_events < 5:
                # Unknown or barely-seen user → slight elevation only
                return 0.3

            profile = self._profiles[uid]
            ts = (log_event.timestamp if isinstance(log_event.timestamp, datetime)
                  else datetime.utcnow())
            payload = log_event.payload or {}

            # ── Component scores ──────────────────────────────────────────────
            hour_score     = _hour_anomaly_score(profile, ts.hour)
            path           = str(payload.get("path", payload.get("url", "")))
            endpoint_score = _endpoint_anomaly_score(profile, path)
            current_rpm    = float(payload.get("request_rate_1m", 1))
            rate_score     = _rate_anomaly_score(profile, current_rpm)

            # User agent deviation
            ua = str(payload.get("user_agent", ""))
            ua_score = 0.0
            if ua and profile.typical_user_agents and ua not in profile.typical_user_agents:
                ua_score = 0.4  # new UA not in history

            # ── Weighted composite ────────────────────────────────────────────
            composite = (
                _W_HOUR     * hour_score
                + _W_ENDPOINT * endpoint_score
                + _W_RATE     * rate_score
                + _W_UA       * ua_score
            )
            return float(_CLIP(composite, 0.0, 1.0))

        except Exception as exc:
            logger.warning("[UEBAEngine] score() error: %s — returning 0.5", exc)
            return 0.5

    # ── Persistence ───────────────────────────────────────────────────────────

    def save_profiles(self, path: str = _DEFAULT_PROFILES_PATH) -> None:
        """Persist all user profiles to a JSON file."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                "saved_at": datetime.utcnow().isoformat(),
                "profiles": {uid: p.to_dict() for uid, p in self._profiles.items()},
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info("[UEBAEngine] %d profiles saved to %s", len(self._profiles), path)
        except Exception as exc:
            logger.error("[UEBAEngine] save_profiles error: %s", exc)

    def load_profiles(self, path: str = _DEFAULT_PROFILES_PATH) -> None:
        """Load user profiles from a JSON file.

        Falls back to empty profiles if the file is missing or corrupt.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            profiles_raw = data.get("profiles", {})
            self._profiles = {uid: UserProfile.from_dict(d) for uid, d in profiles_raw.items()}
            logger.info("[UEBAEngine] Loaded %d profiles from %s", len(self._profiles), path)
        except FileNotFoundError:
            logger.info("[UEBAEngine] No profiles file at %s — starting fresh.", path)
        except Exception as exc:
            logger.warning("[UEBAEngine] load_profiles error: %s — starting fresh.", exc)

    @property
    def profile_count(self) -> int:
        return len(self._profiles)


# Module-level singleton
ueba_engine = UEBAEngine()
ueba_engine.load_profiles()
