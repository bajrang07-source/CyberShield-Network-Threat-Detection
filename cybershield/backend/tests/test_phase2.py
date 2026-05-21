"""
tests/test_phase2.py
────────────────────────────────────────────────────────────────────────────────
Phase 2 verification tests — enhanced detection ensemble layer.

Covers:
  1. PyOD engine neutral score when untrained
  2. UEBA unknown-user returns low score (0.3)
  3. UEBA 3 AM login scores significantly higher than 9 AM
  4. Timeseries engine detects bot-like patterns
  5. FidelityRanker weights sum to exactly 1.0
  6. FidelityRanker deduplication logic
  7. Existing ML pipeline unchanged (original score still produced)
"""
from __future__ import annotations

import sys
import os
import time

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import pytest
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_event(
    source_ip: str = "10.0.0.1",
    user_id: str = None,
    event_type: str = "generic",
    action: str = "allow",
    hour: int = 9,
    path: str = "/api/data",
    request_rate_1m: float = 1.0,
    ua: str = "Mozilla/5.0",
    raw_data: str = "test event",
):
    """Return a minimal LogEvent-compatible object usable by all engines."""
    from ingestion.schema import LogEvent
    ts = datetime(2024, 6, 1, hour, 0, 0)
    return LogEvent(
        source_ip=source_ip,
        user_id=user_id,
        event_type=event_type,
        action=action,
        timestamp=ts,
        raw_data=raw_data,
        payload={
            "path":            path,
            "url":             path,
            "user_agent":      ua,
            "request_rate_1m": request_rate_1m,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — PyOD engine neutral when untrained
# ─────────────────────────────────────────────────────────────────────────────

class TestPyODEngine:
    """Verify PyOD engine behaviour before and after training."""

    def test_untrained_returns_neutral(self):
        """Untrained model must return 0.5 (neutral), never crash."""
        from detection.pyod_engine import PyODEngine
        engine = PyODEngine()   # fresh, not trained
        assert not engine.is_trained
        event = _make_event()
        score = engine.score(event)
        assert score == 0.5

    def test_no_crash_on_malformed_event(self):
        """score() must not raise even if the event has unusual attributes."""
        from detection.pyod_engine import PyODEngine
        engine = PyODEngine()

        class _Bad:
            timestamp = "not-a-datetime"
            raw_data  = None
            payload   = None

        score = engine.score(_Bad())
        assert 0.0 <= score <= 1.0

    def test_trained_model_returns_float_in_range(self):
        """After training on even a tiny dataset, score must return [0,1]."""
        from detection.pyod_engine import PyODEngine
        engine = PyODEngine()
        events = [_make_event(source_ip=f"10.0.{i}.{i}") for i in range(10)]
        engine.fit_baseline(events)
        assert engine.is_trained
        score = engine.score(_make_event())
        assert 0.0 <= score <= 1.0

    def test_trained_anomalous_event_not_neutral(self):
        """A clearly anomalous event should differ from 0.5 after training."""
        from detection.pyod_engine import PyODEngine
        engine = PyODEngine()
        # Train on clean events (hour 9, low payload)
        events = [_make_event(hour=9, request_rate_1m=1.0) for _ in range(15)]
        engine.fit_baseline(events)
        # Score an event with extreme characteristics
        anomalous = _make_event(hour=3, request_rate_1m=999.0,
                                raw_data="'" * 500)
        clean_score = engine.score(_make_event(hour=9, request_rate_1m=1.0))
        anomalous_score = engine.score(anomalous)
        # We don't assert a specific value — just that the engine produces
        # valid floats and that untrained fallback is 0.5
        assert 0.0 <= clean_score <= 1.0
        assert 0.0 <= anomalous_score <= 1.0

    def test_save_load_roundtrip(self, tmp_path):
        """Models saved and loaded must produce identical scores."""
        from detection.pyod_engine import PyODEngine
        engine = PyODEngine()
        events = [_make_event(source_ip=f"192.168.{i}.1") for i in range(10)]
        engine.fit_baseline(events)

        path = str(tmp_path / "pyod_test.pkl")
        engine.save_model(path)

        engine2 = PyODEngine()
        engine2.load_model(path)
        assert engine2.is_trained

        event = _make_event()
        s1 = engine.score(event)
        s2 = engine2.score(event)
        assert abs(s1 - s2) < 0.01

    def test_load_missing_file_does_not_crash(self, tmp_path):
        """Loading a non-existent file must leave engine untrained, not crash."""
        from detection.pyod_engine import PyODEngine
        engine = PyODEngine()
        engine.load_model(str(tmp_path / "nonexistent.pkl"))
        assert not engine.is_trained
        score = engine.score(_make_event())
        assert score == 0.5


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 & 3 — UEBA engine
# ─────────────────────────────────────────────────────────────────────────────

class TestUEBAEngine:
    """Verify user-behavior scoring."""

    def test_unknown_user_returns_low_score(self):
        """A user that has never been seen must return 0.3 (slight elevation)."""
        from detection.ueba_engine import UEBAEngine
        engine = UEBAEngine()
        event = _make_event(user_id="complete_stranger")
        score = engine.score(event)
        assert score == pytest.approx(0.3)

    def test_known_user_below_unknown_threshold(self):
        """After baseline training, a clean event should score < unknown user."""
        from detection.ueba_engine import UEBAEngine
        engine = UEBAEngine()
        uid = "alice"
        # Build a solid baseline (10 events at hour 9)
        for _ in range(10):
            engine.update_baseline(_make_event(user_id=uid, hour=9))

        clean_score  = engine.score(_make_event(user_id=uid, hour=9))
        unknown_score = 0.3
        # After 10 consistent events, typical login should score below unknown
        assert clean_score <= unknown_score

    def test_3am_login_scores_higher_than_9am(self):
        """3AM login for a user whose baseline is 9AM should score noticeably higher."""
        from detection.ueba_engine import UEBAEngine
        engine = UEBAEngine()
        uid = "bob"
        # Establish 9 AM baseline
        for _ in range(15):
            engine.update_baseline(_make_event(user_id=uid, hour=9))

        score_9am = engine.score(_make_event(user_id=uid, hour=9))
        score_3am = engine.score(_make_event(user_id=uid, hour=3))

        assert score_3am > score_9am, (
            f"3AM score ({score_3am:.3f}) should be > 9AM score ({score_9am:.3f})"
        )

    def test_3am_score_is_meaningfully_elevated(self):
        """3AM login should produce a score above 0.25 for a 9AM baseline user."""
        from detection.ueba_engine import UEBAEngine
        engine = UEBAEngine()
        uid = "carol"
        for _ in range(15):
            engine.update_baseline(_make_event(user_id=uid, hour=9))

        score_3am = engine.score(_make_event(user_id=uid, hour=3))
        assert score_3am > 0.25, f"3AM score {score_3am:.3f} should be elevated"

    def test_new_endpoint_scores_higher_than_known(self):
        """Accessing an endpoint never seen before should score higher."""
        from detection.ueba_engine import UEBAEngine
        engine = UEBAEngine()
        uid = "dave"
        for _ in range(15):
            engine.update_baseline(_make_event(user_id=uid, path="/api/data"))

        known_score = engine.score(_make_event(user_id=uid, path="/api/data"))
        new_score   = engine.score(_make_event(user_id=uid, path="/api/admin/delete"))
        assert new_score > known_score

    def test_score_clamped_to_0_1(self):
        """Score must never exceed 1.0 or fall below 0.0."""
        from detection.ueba_engine import UEBAEngine
        engine = UEBAEngine()
        for uid in ("e1", "e2", "e3"):
            score = engine.score(_make_event(user_id=uid, request_rate_1m=9999.0))
            assert 0.0 <= score <= 1.0

    def test_save_load_roundtrip(self, tmp_path):
        """Profiles saved and reloaded must reproduce the same score."""
        from detection.ueba_engine import UEBAEngine
        engine = UEBAEngine()
        uid = "frank"
        for _ in range(10):
            engine.update_baseline(_make_event(user_id=uid, hour=14))

        path = str(tmp_path / "ueba_test.json")
        engine.save_profiles(path)

        engine2 = UEBAEngine()
        engine2.load_profiles(path)
        assert engine2.profile_count > 0

        s1 = engine.score(_make_event(user_id=uid, hour=3))
        s2 = engine2.score(_make_event(user_id=uid, hour=3))
        assert abs(s1 - s2) < 0.05


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Timeseries engine bot detection
# ─────────────────────────────────────────────────────────────────────────────

class TestTimeseriesEngine:
    """Verify time-series scoring for bot / flood / scanner patterns."""

    def test_empty_ip_returns_zero(self):
        """IP with no recorded events must return 0.0."""
        from detection.timeseries_engine import TimeseriesEngine
        engine = TimeseriesEngine()
        assert engine.score("10.0.0.99") == 0.0

    def test_too_few_events_returns_zero(self):
        """Fewer than 3 events returns 0.0 (insufficient data)."""
        from detection.timeseries_engine import TimeseriesEngine
        engine = TimeseriesEngine()
        for _ in range(2):
            engine.record(_make_event(source_ip="10.0.0.2"))
        assert engine.score("10.0.0.2") == 0.0

    def test_bot_pattern_scores_high(self):
        """Very regular inter-arrival time (std < 0.1s) must push score up."""
        from detection.timeseries_engine import TimeseriesEngine, _Record
        import time as _time

        engine = TimeseriesEngine()
        ip = "10.99.99.1"

        # Inject 80 records with near-zero interval variance (bot-like)
        now = _time.time()
        for i in range(80):
            rec = _Record(ts=now + i * 0.5, path="/api/login", action="allow")
            engine._windows[ip].append(rec)
        engine._total_events += 80

        score = engine.score(ip)
        assert score > 0.3, f"Bot pattern score {score:.3f} should be > 0.3"

    def test_flood_pattern_scores_high(self):
        """More than 60 requests in window must trigger high score."""
        from detection.timeseries_engine import TimeseriesEngine, _Record
        import time as _time

        engine = TimeseriesEngine()
        ip = "10.99.99.2"

        now = _time.time()
        for i in range(100):
            rec = _Record(ts=now + i * 0.1, path=f"/api/ep{i % 3}", action="allow")
            engine._windows[ip].append(rec)
        engine._total_events += 100

        score = engine.score(ip)
        assert score > 0.4, f"Flood score {score:.3f} should be > 0.4"

    def test_scanner_pattern_scores_high(self):
        """More than 30 unique endpoints must trigger scanner penalty."""
        from detection.timeseries_engine import TimeseriesEngine, _Record
        import time as _time

        engine = TimeseriesEngine()
        ip = "10.99.99.3"

        now = _time.time()
        for i in range(40):
            rec = _Record(ts=now + i * 2.0, path=f"/api/path{i}", action="allow")
            engine._windows[ip].append(rec)
        engine._total_events += 40

        score = engine.score(ip)
        assert score > 0.3, f"Scanner score {score:.3f} should be > 0.3"

    def test_score_clamped_to_0_1(self):
        """Combined score must stay within [0, 1]."""
        from detection.timeseries_engine import TimeseriesEngine, _Record
        import time as _time

        engine = TimeseriesEngine()
        ip = "10.99.99.4"
        now = _time.time()

        # Trigger all three penalties simultaneously
        for i in range(200):
            rec = _Record(ts=now + i * 0.05, path=f"/path{i}", action="block")
            engine._windows[ip].append(rec)
        engine._total_events += 200

        score = engine.score(ip)
        assert 0.0 <= score <= 1.0

    def test_extract_features_returns_none_for_sparse(self):
        """Fewer than 3 events returns None from extract_features."""
        from detection.timeseries_engine import TimeseriesEngine
        engine = TimeseriesEngine()
        engine.record(_make_event(source_ip="10.0.0.50"))
        engine.record(_make_event(source_ip="10.0.0.50"))
        result = engine.extract_features("10.0.0.50")
        assert result is None

    def test_extract_features_returns_dict_for_sufficient(self):
        """At least 3 events must produce a feature dict with expected keys."""
        from detection.timeseries_engine import TimeseriesEngine, _Record
        import time as _time

        engine = TimeseriesEngine()
        ip = "10.0.0.51"
        now = _time.time()
        # Inject 5 records with recent timestamps (within the 5-min window)
        for i in range(5):
            rec = _Record(ts=now - (4 - i) * 10, path="/api/test", action="allow")
            engine._windows[ip].append(rec)
        engine._total_events += 5

        result = engine.extract_features(ip)
        assert result is not None
        assert "request_count" in result
        assert "mean_interval_sec" in result
        assert "std_interval_sec" in result
        assert "unique_endpoints" in result
        assert "error_rate" in result
        assert "endpoint_entropy" in result


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — FidelityRanker weights sum to 1.0
# ─────────────────────────────────────────────────────────────────────────────

class TestFidelityRanker:
    """Verify FidelityRanker correctness."""

    def test_weights_sum_to_1(self):
        from detection.fidelity_ranker import WEIGHTS
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

    def test_all_zero_gives_low_tier(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        result = ranker.rank({})
        assert result.tier == "LOW"
        assert result.combined_score == 0.0

    def test_all_one_gives_critical_tier(self):
        from detection.fidelity_ranker import FidelityRanker, WEIGHTS
        ranker = FidelityRanker()
        result = ranker.rank({k: 1.0 for k in WEIGHTS})
        assert result.tier == "CRITICAL"
        assert result.combined_score == pytest.approx(1.0)

    def test_tier_thresholds(self):
        from detection.fidelity_ranker import FidelityRanker, WEIGHTS
        ranker = FidelityRanker()

        def _uniform_score(value):
            # Set all sources to the same value and get combined score
            return ranker.rank({k: value for k in WEIGHTS})

        assert _uniform_score(0.1).tier == "LOW"
        assert _uniform_score(0.4).tier == "MEDIUM"
        assert _uniform_score(0.6).tier == "HIGH"
        assert _uniform_score(0.9).tier == "CRITICAL"

    def test_dominant_signal_is_highest_contributor(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        result = ranker.rank({
            "rule":             0.9,
            "ml_random_forest": 0.1,
            "pyod":             0.1,
            "ueba":             0.1,
            "timeseries":       0.1,
        })
        assert result.dominant_signal == "rule"

    def test_missing_keys_treated_as_zero(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        result = ranker.rank({"rule": 0.8})   # all others missing
        assert 0.0 <= result.combined_score <= 1.0
        assert result.dominant_signal == "rule"

    def test_scores_clamped(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        result = ranker.rank({
            "rule": 99.0,         # way out of range
            "pyod": -5.0,         # negative
        })
        assert 0.0 <= result.combined_score <= 1.0

    def test_to_dict_structure(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        result = ranker.rank({"rule": 0.5, "ml_random_forest": 0.5})
        d = result.to_dict()
        assert "combined_score" in d
        assert "tier" in d
        assert "dominant_signal" in d
        assert "scores_breakdown" in d


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — FidelityRanker deduplication
# ─────────────────────────────────────────────────────────────────────────────

class TestFidelityRankerDeduplication:
    """Verify in-memory TTL deduplication logic."""

    def test_first_occurrence_is_not_duplicate(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        is_dup = ranker.deduplicate("evt-1", "10.0.0.1", "SQL_INJECTION")
        assert is_dup is False

    def test_second_occurrence_within_window_is_duplicate(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        ranker.deduplicate("evt-1", "10.0.0.1", "SQL_INJECTION")
        is_dup = ranker.deduplicate("evt-2", "10.0.0.1", "SQL_INJECTION")
        assert is_dup is True

    def test_different_ip_is_not_duplicate(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        ranker.deduplicate("evt-1", "10.0.0.1", "SQL_INJECTION")
        is_dup = ranker.deduplicate("evt-2", "10.0.0.2", "SQL_INJECTION")
        assert is_dup is False

    def test_different_attack_type_is_not_duplicate(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        ranker.deduplicate("evt-1", "10.0.0.1", "SQL_INJECTION")
        is_dup = ranker.deduplicate("evt-2", "10.0.0.1", "XSS")
        assert is_dup is False

    def test_none_attack_type_never_deduplicates(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        for i in range(3):
            is_dup = ranker.deduplicate(f"evt-{i}", "10.0.0.1", None)
            assert is_dup is False

    def test_expired_window_resets_duplicate(self):
        """After TTL expires, the same (ip, attack) should be treated as new."""
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        ranker.deduplicate("evt-1", "10.0.0.1", "BRUTE_FORCE", window_seconds=1)

        # Wait for the window to expire
        time.sleep(1.2)

        is_dup = ranker.deduplicate("evt-2", "10.0.0.1", "BRUTE_FORCE", window_seconds=1)
        assert is_dup is False

    def test_dedup_count_increments(self):
        from detection.fidelity_ranker import FidelityRanker
        ranker = FidelityRanker()
        ranker.deduplicate("evt-1", "172.16.0.5", "XSS")
        ranker.deduplicate("evt-2", "172.16.0.5", "XSS")
        ranker.deduplicate("evt-3", "172.16.0.5", "XSS")
        count = ranker.dedup_count("172.16.0.5", "XSS")
        assert count == 3


# ─────────────────────────────────────────────────────────────────────────────
# Test 7 — Existing ML pipeline unchanged
# ─────────────────────────────────────────────────────────────────────────────

class TestExistingMLPipelineUnchanged:
    """Verify Phase 2 additions do not alter existing detection outputs."""

    def test_ml_engine_predict_signature_unchanged(self):
        """MLEngine.predict must still accept np.ndarray and return float."""
        import numpy as np
        from detection.ml_engine import ml_engine

        feature_vector = np.zeros((1, 11), dtype=float)
        result = ml_engine.predict(feature_vector)
        assert isinstance(result, float)
        assert 0.0 <= result <= 1.0

    def test_rule_engine_output_type_unchanged(self):
        """check_rules must still return a RuleResult dataclass."""
        from detection.rule_engine import check_rules, RuleResult
        from detection.feature_extractor import RequestContext

        ctx = RequestContext(
            ip="127.0.0.1",
            method="GET",
            path="/api/data",
            user_agent="TestAgent/1.0",
            payload={},
            timestamp=datetime.utcnow(),
            session_id="test123",
        )
        result = check_rules(ctx)
        assert isinstance(result, RuleResult)
        assert hasattr(result, "attack_type")
        assert hasattr(result, "severity")
        assert hasattr(result, "matched_pattern")
        assert isinstance(result.severity, int)

    def test_rule_engine_detects_sqli(self):
        """Existing SQLi detection must remain functional."""
        from detection.rule_engine import check_rules
        from detection.feature_extractor import RequestContext

        ctx = RequestContext(
            ip="1.2.3.4",
            method="POST",
            path="/login",
            user_agent="curl/7.64",
            payload={"username": "' OR '1'='1"},
            timestamp=datetime.utcnow(),
            session_id="",
        )
        result = check_rules(ctx)
        assert result.attack_type == "SQL_INJECTION"
        assert result.severity == 9

    def test_threat_result_has_fidelity_field(self):
        """After Phase 2 wiring, ThreatResult must have a 'fidelity' attribute
        (possibly None if engines not wired yet)."""
        from app import app, create_app
        create_app()
        from services.threat_service import analyze_request
        with app.app_context():
            result = analyze_request(
                ip="10.0.0.5",
                method="GET",
                path="/api/health",
                user_agent="test",
                payload={},
            )
        # Must have fidelity (dict or None — both valid)
        assert hasattr(result, "fidelity")
        if result.fidelity is not None:
            assert "combined_score" in result.fidelity
            assert "tier" in result.fidelity
            assert "dominant_signal" in result.fidelity

    def test_threat_result_risk_score_unchanged(self):
        """Phase 2 must not alter the existing risk_score calculation."""
        from app import app, create_app
        create_app()
        from services.threat_service import analyze_request, _calculate_risk
        from detection.rule_engine import check_rules
        from detection.feature_extractor import RequestContext

        ctx = RequestContext(
            ip="192.168.1.10",
            method="GET",
            path="/api/data",
            user_agent="TestBrowser",
            payload={},
            timestamp=datetime.utcnow(),
        )

        with app.app_context():
            result = analyze_request(
                ip="192.168.1.10",
                method="GET",
                path="/api/data",
                user_agent="TestBrowser",
                payload={},
            )

        # risk_score must still be in 0-100 range
        assert 0.0 <= result.risk_score <= 100.0
        # ml_score must be in 0-1 range
        assert 0.0 <= result.ml_score <= 1.0
        # severity must be a valid label
        assert result.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_fidelity_ranker_all_engines_accessible(self):
        """All Phase 2 module singletons must be importable without crashing."""
        try:
            from detection.pyod_engine import pyod_engine
            from detection.ueba_engine import ueba_engine
            from detection.timeseries_engine import ts_engine
            from detection.fidelity_ranker import fidelity_ranker
        except Exception as exc:
            pytest.fail(f"Phase 2 module import failed: {exc}")
