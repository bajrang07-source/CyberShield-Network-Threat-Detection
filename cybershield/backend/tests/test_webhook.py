"""
Tests for webhook delivery — retry logic and HMAC signing.
"""
import sys
import os
import json
import hashlib
import hmac
import pytest
from unittest.mock import patch, MagicMock, call
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def mock_result():
    """Fake ThreatResult for webhook tests."""
    from services.threat_service import ThreatResult
    return ThreatResult(
        id='evt-001',
        site_id='site-uuid-001',
        ip='1.2.3.4',
        method='POST',
        path='/api/login',
        user_agent='sqlmap/1.0',
        payload_snippet='{"q": "OR 1=1"}',
        risk_score=95.0,
        attack_type='SQL_INJECTION',
        matched_pattern='SQLI: OR 1=1',
        ml_score=0.92,
        severity='CRITICAL',
        action='block',
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
        session_id='sess-001',
    )


# ── Test: HMAC signing ────────────────────────────────────────────────────────

def test_hmac_signature_generation():
    from webhooks.dispatcher import _sign_payload

    secret = 'my-webhook-secret'
    body = '{"event": "threat.critical"}'
    sig = _sign_payload(secret, body)

    # Verify manually
    expected = hmac.new(
        secret.encode('utf-8'),
        body.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    assert sig == expected


# ── Test: Successful delivery on first try ────────────────────────────────────

def test_successful_delivery_first_attempt():
    from webhooks.dispatcher import _send_with_retry

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch('webhooks.dispatcher.http_requests.post', return_value=mock_response) as mock_post:
        result = _send_with_retry('https://example.com/hook', {'event': 'test'})

    assert result is True
    assert mock_post.call_count == 1


# ── Test: Retry on server error then succeed ──────────────────────────────────

def test_retry_on_server_error():
    from webhooks.dispatcher import _send_with_retry

    fail_resp = MagicMock()
    fail_resp.status_code = 503
    success_resp = MagicMock()
    success_resp.status_code = 200

    with patch('webhooks.dispatcher.http_requests.post',
               side_effect=[fail_resp, fail_resp, success_resp]) as mock_post:
        with patch('webhooks.dispatcher.time.sleep'):
            result = _send_with_retry('https://example.com/hook', {'event': 'test'})

    assert result is True
    assert mock_post.call_count == 3  # 2 failures + 1 success


# ── Test: All retries exhausted returns False ─────────────────────────────────

def test_all_retries_exhausted():
    from webhooks.dispatcher import _send_with_retry

    fail_resp = MagicMock()
    fail_resp.status_code = 500

    with patch('webhooks.dispatcher.http_requests.post', return_value=fail_resp):
        with patch('webhooks.dispatcher.time.sleep'):
            result = _send_with_retry('https://example.com/hook', {'event': 'test'})

    assert result is False


# ── Test: Network error triggers retry ───────────────────────────────────────

def test_network_error_triggers_retry():
    from webhooks.dispatcher import _send_with_retry
    import requests as req_lib

    success_resp = MagicMock()
    success_resp.status_code = 200

    with patch('webhooks.dispatcher.http_requests.post',
               side_effect=[req_lib.exceptions.ConnectionError('timeout'), success_resp]) as mock_post:
        with patch('webhooks.dispatcher.time.sleep'):
            result = _send_with_retry('https://example.com/hook', {'event': 'test'})

    assert result is True
    assert mock_post.call_count == 2


# ── Test: Signature included in headers ──────────────────────────────────────

def test_signature_included_when_secret_provided():
    from webhooks.dispatcher import _send_with_retry

    captured_headers = {}

    def mock_post(url, data, headers, timeout):
        captured_headers.update(headers)
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch('webhooks.dispatcher.http_requests.post', side_effect=mock_post):
        _send_with_retry('https://example.com/hook', {'event': 'test'}, secret='my-secret')

    assert 'X-CyberShield-Signature' in captured_headers
    assert captured_headers['X-CyberShield-Signature'].startswith('sha256=')


# ── Test: No signature when no secret ────────────────────────────────────────

def test_no_signature_without_secret():
    from webhooks.dispatcher import _send_with_retry

    captured_headers = {}

    def mock_post(url, data, headers, timeout):
        captured_headers.update(headers)
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch('webhooks.dispatcher.http_requests.post', side_effect=mock_post):
        _send_with_retry('https://example.com/hook', {'event': 'test'}, secret=None)

    assert 'X-CyberShield-Signature' not in captured_headers
