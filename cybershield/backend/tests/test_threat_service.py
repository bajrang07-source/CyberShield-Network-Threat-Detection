"""
Tests for ThreatService — centralized detection orchestration.
Verifies that the service correctly wraps existing detection engines.
"""
import sys
import os
import pytest
import numpy as np
from unittest.mock import MagicMock, patch
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def mock_redis():
    """Mock Redis that simulates rate counters."""
    redis = MagicMock()
    redis.exists.return_value = 0
    redis.pipeline.return_value.__enter__ = MagicMock(return_value=MagicMock(
        incr=MagicMock(), expire=MagicMock(),
        execute=MagicMock(return_value=[1, True, 1, True])
    ))
    redis.pipeline.return_value.__exit__ = MagicMock(return_value=False)
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    redis.pipeline.return_value = pipe
    return redis


@pytest.fixture
def flask_app():
    """Minimal Flask app for DB context."""
    from flask import Flask
    from models.db import db as _db

    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'test'
    app.config['JWT_SECRET_KEY'] = 'test-jwt'

    _db.init_app(app)
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


# ── Test: Feature extractor produces correct shape ────────────────────────────

def test_feature_extractor_shape(mock_redis):
    from detection.feature_extractor import RequestContext, extract_features

    ctx = RequestContext(
        ip='127.0.0.1',
        method='GET',
        path='/api/test',
        user_agent='Mozilla/5.0',
        payload={'q': 'hello'},
        timestamp=datetime.utcnow(),
    )
    fv = extract_features(ctx, mock_redis)
    assert fv.shape == (1, 11), f"Expected (1,11), got {fv.shape}"


# ── Test: SQL injection detected by rule engine ───────────────────────────────

def test_rule_engine_detects_sqli():
    from detection.feature_extractor import RequestContext
    from detection.rule_engine import check_rules

    ctx = RequestContext(
        ip='1.2.3.4',
        method='POST',
        path='/api/search',
        user_agent='curl/7.0',
        payload={'q': "' OR 1=1 UNION SELECT * FROM users--"},
        timestamp=datetime.utcnow(),
    )
    result = check_rules(ctx)
    assert result.attack_type == 'SQL_INJECTION'
    assert result.severity >= 8


# ── Test: XSS detected by rule engine ────────────────────────────────────────

def test_rule_engine_detects_xss():
    from detection.feature_extractor import RequestContext
    from detection.rule_engine import check_rules

    ctx = RequestContext(
        ip='1.2.3.4',
        method='POST',
        path='/api/comment',
        user_agent='Mozilla/5.0',
        payload={'text': "<script>alert('xss')</script>"},
        timestamp=datetime.utcnow(),
    )
    result = check_rules(ctx)
    assert result.attack_type == 'XSS'
    assert result.severity >= 7


# ── Test: Path traversal detected ────────────────────────────────────────────

def test_rule_engine_detects_path_traversal():
    from detection.feature_extractor import RequestContext
    from detection.rule_engine import check_rules

    ctx = RequestContext(
        ip='1.2.3.4',
        method='GET',
        path='/api/files?name=../../etc/passwd',
        user_agent='Mozilla/5.0',
        payload={},
        timestamp=datetime.utcnow(),
    )
    result = check_rules(ctx)
    assert result.attack_type == 'PATH_TRAVERSAL'


# ── Test: Clean request has no attack type ────────────────────────────────────

def test_rule_engine_clean_request():
    from detection.feature_extractor import RequestContext
    from detection.rule_engine import check_rules

    ctx = RequestContext(
        ip='10.0.0.1',
        method='GET',
        path='/api/products',
        user_agent='Mozilla/5.0',
        payload={'page': 1, 'limit': 10},
        timestamp=datetime.utcnow(),
    )
    result = check_rules(ctx)
    assert result.attack_type is None
    assert result.severity == 0


# ── Test: Risk score calculation ──────────────────────────────────────────────

def test_risk_score_calculation():
    from services.threat_service import _calculate_risk

    # High rule severity + high ML score → should be critical
    score = _calculate_risk(rule_severity=9, ml_score=0.9, rate_1m=5)
    assert score >= 80, f"Expected critical risk, got {score}"

    # Clean request
    clean_score = _calculate_risk(rule_severity=0, ml_score=0.1, rate_1m=1)
    assert clean_score < 40, f"Expected low risk, got {clean_score}"

    # Capped at 100
    capped = _calculate_risk(rule_severity=10, ml_score=1.0, rate_1m=50)
    assert capped == 100.0


# ── Test: Severity label logic ────────────────────────────────────────────────

def test_severity_labels():
    from services.threat_service import _severity_label

    assert _severity_label(85.0) == 'CRITICAL'
    assert _severity_label(65.0) == 'HIGH'
    assert _severity_label(45.0) == 'MEDIUM'
    assert _severity_label(10.0) == 'LOW'


# ── Test: Action mapping ──────────────────────────────────────────────────────

def test_action_for_severity():
    from services.threat_service import _action_for_severity

    assert _action_for_severity('CRITICAL') == 'block'
    assert _action_for_severity('HIGH') == 'monitor'
    assert _action_for_severity('MEDIUM') == 'monitor'
    assert _action_for_severity('LOW') == 'allow'


# ── Test: ThreatService full pipeline (mocked DB + emit) ─────────────────────

def test_threat_service_full_pipeline(flask_app, mock_redis):
    from services.threat_service import analyze_request

    with flask_app.app_context():
        with patch('services.threat_service._persist_and_emit'):
            result = analyze_request(
                ip='10.0.0.1',
                method='POST',
                path='/api/search',
                user_agent='sqlmap/1.0',
                payload={'q': "' OR 1=1--"},
                site_id=None,
                redis_client=mock_redis,
            )

    assert result is not None
    assert result.risk_score > 0
    assert result.attack_type is not None
    assert result.severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    assert result.action in ('allow', 'monitor', 'block')
    assert result.id is not None


# ── Test: ML engine loads and predicts ────────────────────────────────────────

def test_ml_engine_predict():
    from detection.ml_engine import ml_engine

    # Create a dummy feature vector (11 features)
    fv = np.array([[100, 5, 1, 0, 0, 3, 10, 0, 2.5, 2, 1]], dtype=float)
    score = ml_engine.predict(fv)
    assert 0.0 <= score <= 1.0, f"ML score out of range: {score}"


# ── Test: Per-site threshold override ────────────────────────────────────────

def test_per_site_threshold_override():
    from services.threat_service import _severity_label

    # Site with lower critical threshold
    custom = {'critical': 60.0, 'high': 45.0, 'medium': 30.0}
    assert _severity_label(62.0, custom) == 'CRITICAL'   # would be HIGH without override
    assert _severity_label(32.0, custom) == 'MEDIUM'     # would be LOW without override
