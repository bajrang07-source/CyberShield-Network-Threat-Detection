"""
detection/fidelity_ranker.py
────────────────────────────────────────────────────────────────────────────────
FidelityRanker — weighted ensemble combiner for all detection signals (Phase 2).

Combines scores from five detection sources into a single authoritative
FidelityResult.  Also provides in-memory deduplication to suppress alert storms.

The existing risk_score in ThreatResult is NOT replaced — fidelity is an extra
enrichment field added alongside it.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Weight configuration ──────────────────────────────────────────────────────
WEIGHTS: Dict[str, float] = {
    "rule":             0.25,
    "ml_random_forest": 0.20,
    "pyod":             0.20,
    "ueba":             0.20,
    "timeseries":       0.15,
}

# Verify weights sum to 1.0 at import time (fast sanity check)
_weight_sum = sum(WEIGHTS.values())
assert abs(_weight_sum - 1.0) < 1e-9, f"WEIGHTS must sum to 1.0, got {_weight_sum}"

# ── Tier thresholds ───────────────────────────────────────────────────────────
_TIER_THRESHOLDS = [
    (0.75, "CRITICAL"),
    (0.55, "HIGH"),
    (0.35, "MEDIUM"),
    (0.0,  "LOW"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FidelityResult:
    """Output of FidelityRanker.rank()."""
    combined_score:   float                        # 0.0–1.0
    tier:             str                          # LOW | MEDIUM | HIGH | CRITICAL
    dominant_signal:  str                          # name of highest-contributing source
    scores_breakdown: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "combined_score":   round(self.combined_score, 4),
            "tier":             self.tier,
            "dominant_signal":  self.dominant_signal,
            "scores_breakdown": {k: round(v, 4) for k, v in self.scores_breakdown.items()},
        }


# ─────────────────────────────────────────────────────────────────────────────
# FidelityRanker
# ─────────────────────────────────────────────────────────────────────────────

class FidelityRanker:
    """Weighted ensemble combiner with in-memory event deduplication.

    Usage::

        ranker = FidelityRanker()

        result = ranker.rank({
            "rule":             0.9,
            "ml_random_forest": 0.7,
            "pyod":             0.5,
            "ueba":             0.3,
            "timeseries":       0.2,
        })
        # result.combined_score, result.tier, result.dominant_signal

        is_dup = ranker.deduplicate(event_id, ip, attack_type)
    """

    def __init__(self) -> None:
        # dedup store: (ip, attack_type) → (first_seen_epoch, count)
        self._dedup: Dict[str, tuple] = {}

    # ── Ranking ───────────────────────────────────────────────────────────────

    def rank(self, scores: Dict[str, float]) -> FidelityResult:
        """Combine per-source scores into a FidelityResult.

        Args:
            scores: Dict mapping source names to floats in [0.0, 1.0].
                    Missing keys are treated as 0.0.
                    Values outside [0,1] are silently clamped.

        Returns:
            :class:`FidelityResult` with combined_score, tier, and breakdown.
        """
        # ── Clamp and fill ────────────────────────────────────────────────────
        clamped: Dict[str, float] = {}
        for source, weight in WEIGHTS.items():
            raw = float(scores.get(source, 0.0))
            clamped[source] = max(0.0, min(1.0, raw))

        # ── Weighted sum ──────────────────────────────────────────────────────
        combined = sum(clamped[src] * w for src, w in WEIGHTS.items())
        combined = max(0.0, min(1.0, combined))

        # ── Tier classification ───────────────────────────────────────────────
        tier = "LOW"
        for threshold, label in _TIER_THRESHOLDS:
            if combined >= threshold:
                tier = label
                break

        # ── Dominant signal (highest weighted contribution) ───────────────────
        contributions = {src: clamped[src] * WEIGHTS[src] for src in WEIGHTS}
        dominant_signal = max(contributions, key=contributions.get)

        return FidelityResult(
            combined_score=round(combined, 4),
            tier=tier,
            dominant_signal=dominant_signal,
            scores_breakdown=clamped,
        )

    # ── Deduplication ─────────────────────────────────────────────────────────

    def deduplicate(
        self,
        event_id: str,
        ip: str,
        attack_type: Optional[str],
        window_seconds: int = 300,
    ) -> bool:
        """Check whether (ip, attack_type) was already seen within *window_seconds*.

        Args:
            event_id:       Unique event identifier (stored for reference).
            ip:             Source IP address.
            attack_type:    Attack category string (or None for clean traffic).
            window_seconds: Dedup TTL in seconds (default 5 minutes).

        Returns:
            True  → duplicate; caller should increment count, not create new alert.
            False → new event; create the alert as normal.
        """
        if not attack_type:
            return False  # clean traffic is never deduplicated

        key = f"{ip}:{attack_type}"
        now = time.time()

        # Lazy expire — clean up stale entries while we're here
        stale = [k for k, (seen_at, _) in self._dedup.items()
                 if now - seen_at > window_seconds]
        for k in stale:
            del self._dedup[k]

        if key in self._dedup:
            seen_at, count = self._dedup[key]
            if now - seen_at <= window_seconds:
                # Still within window — it's a duplicate
                self._dedup[key] = (seen_at, count + 1)
                return True
            # Expired — treat as new
            del self._dedup[key]

        # First occurrence in this window
        self._dedup[key] = (now, 1)
        return False

    def dedup_count(self, ip: str, attack_type: str) -> int:
        """Return how many times (ip, attack_type) has been seen in the current window."""
        key = f"{ip}:{attack_type}"
        entry = self._dedup.get(key)
        return entry[1] if entry else 0


# Module-level singleton
fidelity_ranker = FidelityRanker()
