"""
Phase 8: Integration tests — full detection pipeline per attack type.
Uses Flask test client with monkeypatched Redis.
"""
import sys
import os
import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class MockRedis:
    """Minimal Redis mock for testing."""
    def __init__(self):
        self._data = {}
        self._pipeline_calls = []

    def exists(self, key): return 0
    def get(self, key): return None
    def set(self, key, val): self._data[key] = val
    def setex(self, key, ttl, val): self._data[key] = val
    def incr(self, key):
        self._data[key] = self._data.get(key, 0) + 1
        return self._data[key]
    def expire(self, key, ttl): return True
    def delete(self, *keys):
        for k in keys: self._data.pop(k, None)
    def ping(self): return True

    def pipeline(self):
        m = MagicMock()
        m.incr = MagicMock(return_value=m)
        m.expire = MagicMock(return_value=m)
        m.execute = MagicMock(return_value=[2, True, 5, True])
        return m


@pytest.fixture
def mock_redis():
    return MockRedis()


@pytest.fixture
def detection_pipeline(mock_redis):
    """Returns a function that runs the full detection pipeline."""
    from detection.feature_extractor import RequestContext, extract_features
    from detection.rule_engine import check_rules
    from detection.ml_engine import ml_engine
    from config import config

    def run(path, payload, method="POST", rate_1m=1, user_agent="TestClient/1.0"):
        ctx = RequestContext(
            ip="10.0.0.1",
            method=method,
            path=path,
            user_agent=user_agent,
            payload=payload,
            timestamp=datetime.utcnow(),
            session_id="test-session",
        )
        ctx._rate_1m = rate_1m

        fv = extract_features(ctx, mock_redis)
        rule_result = check_rules(ctx)
        ml_score = ml_engine.predict(fv)

        rule_component = rule_result.severity * 10
        ml_component = ml_score * 40
        freq_component = min(rate_1m * 2, 20)
        risk_score = min(rule_component + ml_component + freq_component, 100.0)

        if risk_score >= config.CRITICAL_THRESHOLD:
            severity = "CRITICAL"
        elif risk_score >= config.HIGH_THRESHOLD:
            severity = "HIGH"
        elif risk_score >= config.MEDIUM_THRESHOLD:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": risk_score,
            "attack_type": rule_result.attack_type,
            "severity": severity,
            "ml_score": ml_score,
            "rule_severity": rule_result.severity,
        }

    return run


# ── SQL Injection ──────────────────────────────────────────────────────────────
def test_sqli_pipeline(detection_pipeline):
    result = detection_pipeline(
        path="/api/search",
        payload={"q": "' OR 1=1 UNION SELECT * FROM users--"},
    )
    assert result["attack_type"] == "SQL_INJECTION"
    assert result["risk_score"] >= 40, f"Expected HIGH+ risk, got {result['risk_score']}"
    assert result["severity"] in ("HIGH", "CRITICAL")


# ── XSS ───────────────────────────────────────────────────────────────────────
def test_xss_pipeline(detection_pipeline):
    result = detection_pipeline(
        path="/api/comment",
        payload={"body": "<script>alert(document.cookie)</script>"},
    )
    assert result["attack_type"] == "XSS"
    assert result["risk_score"] >= 40
    assert result["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


# ── Brute Force ────────────────────────────────────────────────────────────────
def test_brute_force_pipeline(detection_pipeline):
    result = detection_pipeline(
        path="/api/auth/login",
        payload={"username": "admin", "password": "test"},
        method="POST",
        rate_1m=15,
    )
    assert result["attack_type"] == "BRUTE_FORCE"
    assert result["risk_score"] >= 40
    assert result["rule_severity"] == 6


# ── Path Traversal ─────────────────────────────────────────────────────────────
def test_path_traversal_pipeline(detection_pipeline):
    result = detection_pipeline(
        path="/api/download",
        payload={"file": "../../etc/passwd"},
        method="GET",
    )
    assert result["attack_type"] == "PATH_TRAVERSAL"
    assert result["risk_score"] >= 40


# ── Clean Request ──────────────────────────────────────────────────────────────
def test_clean_pipeline(detection_pipeline):
    result = detection_pipeline(
        path="/api/products",
        payload={"page": 1, "category": "electronics"},
        method="GET",
        rate_1m=1,
    )
    assert result["attack_type"] is None
    assert result["risk_score"] < 60, f"Clean request should not be HIGH+, got {result['risk_score']}"
    assert result["severity"] in ("LOW", "MEDIUM")


# ── Honeypot ───────────────────────────────────────────────────────────────────
def test_honeypot_pipeline(detection_pipeline):
    result = detection_pipeline(
        path="/.env",
        payload={},
        method="GET",
    )
    assert result["attack_type"] == "HONEYPOT_TRAP"
    assert result["risk_score"] >= 80
    assert result["severity"] == "CRITICAL"
