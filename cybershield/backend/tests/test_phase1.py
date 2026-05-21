"""
tests/test_phase1.py
────────────────────────────────────────────────────────────────────────────────
Phase 1 verification tests — universal log ingestion layer.

Covers:
  1. JSON / dict normalisation
  2. CEF string normalisation
  3. Syslog string normalisation (RFC-3164)
  4. Unstructured free-text normalisation
  5. Elasticsearch client graceful failure (no server running)
  6. POST /api/ingest/siem route returns 200 with valid JWT
"""
from __future__ import annotations

import sys
import os

# Ensure the backend directory is on the path when running from the repo root
_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import pytest
from datetime import datetime

# ── Ingestion layer imports ───────────────────────────────────────────────────
from ingestion.schema import LogEvent
from ingestion.log_normalizer import LogNormalizer
from ingestion.siem_ingestor import SiemIngestor
from ingestion.edr_ingestor import EdrIngestor
from ingestion.auth_ingestor import AuthIngestor
from ingestion.unstructured_parser import UnstructuredParser


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def normalizer():
    return LogNormalizer()


@pytest.fixture(scope="module")
def flask_test_client():
    """Create a Flask test client with a valid JWT token pre-configured."""
    # App import is deferred so tests that don't need Flask don't touch it
    from app import app, create_app
    create_app()
    app.config["TESTING"] = True
    app.config["JWT_SECRET_KEY"] = app.config.get("JWT_SECRET_KEY", "test-secret")

    with app.test_client() as client:
        # Obtain a JWT via the login endpoint
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "cybershield123"},
            content_type="application/json",
        )
        token = None
        if resp.status_code == 200:
            token = resp.get_json().get("access_token")
        yield client, token


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — JSON / dict normalisation
# ─────────────────────────────────────────────────────────────────────────────

class TestJsonNormalization:
    """Verify that dict input produces a valid LogEvent with mapped fields."""

    SAMPLE = {
        "src_ip": "192.168.1.100",
        "user_id": "alice",
        "event_type": "login_failure",
        "action": "block",
        "timestamp": "2024-06-01T10:00:00Z",
        "extra_field": "extra_value",
    }

    def test_returns_log_event(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        assert isinstance(event, LogEvent)

    def test_source_system(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        assert event.source_system == "siem"

    def test_ip_resolved(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        assert event.source_ip == "192.168.1.100"

    def test_user_id_resolved(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        assert event.user_id == "alice"

    def test_event_type_resolved(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        assert event.event_type == "login_failure"

    def test_action_resolved(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        assert event.action == "block"

    def test_timestamp_parsed(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        assert isinstance(event.timestamp, datetime)
        assert event.timestamp.year == 2024

    def test_event_id_is_uuid(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        import uuid
        uuid.UUID(event.event_id)   # raises ValueError if not a valid UUID

    def test_to_dict_round_trip(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        d = event.to_dict()
        assert d["source_ip"] == "192.168.1.100"
        assert d["user_id"] == "alice"
        assert "event_id" in d
        assert "timestamp" in d

    def test_from_dict_round_trip(self, normalizer):
        event = normalizer.normalize(self.SAMPLE, "siem")
        reconstructed = LogEvent.from_dict(event.to_dict())
        assert reconstructed.event_id == event.event_id
        assert reconstructed.source_ip == event.source_ip
        assert reconstructed.user_id == event.user_id

    def test_ip_aliases(self, normalizer):
        """Ensure multiple IP field names all resolve correctly."""
        for alias in ("src_ip", "sourceIP", "source_ip", "ip", "client_ip"):
            data = {alias: "10.0.0.1", "event_type": "test"}
            event = normalizer.normalize(data, "siem")
            assert event.source_ip == "10.0.0.1", f"alias '{alias}' failed"

    def test_siem_ingestor(self):
        ingestor = SiemIngestor()
        event = ingestor.ingest(self.SAMPLE)
        assert event.source_system == "siem"
        assert event.source_ip == "192.168.1.100"


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — CEF normalisation
# ─────────────────────────────────────────────────────────────────────────────

class TestCefNormalization:
    """Verify that a CEF string is correctly parsed."""

    CEF_STRING = (
        "CEF:0|Palo Alto Networks|PAN-OS|10.0|THREAT|SQL Injection|7|"
        "src=203.0.113.5 dst=10.1.1.1 act=blocked suser=bob rt=1717200000000"
    )

    def test_returns_log_event(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert isinstance(event, LogEvent)

    def test_source_system(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert event.source_system == "siem"

    def test_ip_extracted(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert event.source_ip == "203.0.113.5"

    def test_user_extracted(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert event.user_id == "bob"

    def test_event_type_is_name(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert event.event_type == "SQL Injection"

    def test_action_extracted(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert event.action == "blocked"

    def test_payload_contains_vendor(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert event.payload.get("vendor") == "Palo Alto Networks"

    def test_raw_data_preserved(self, normalizer):
        event = normalizer.normalize(self.CEF_STRING, "siem")
        assert "CEF:0" in event.raw_data

    def test_edr_ingestor_with_cef(self):
        ingestor = EdrIngestor()
        event = ingestor.ingest(self.CEF_STRING)
        assert event.source_system == "edr"
        assert event.source_ip == "203.0.113.5"


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — Syslog normalisation
# ─────────────────────────────────────────────────────────────────────────────

class TestSyslogNormalization:
    """Verify that RFC-3164 syslog strings are parsed correctly."""

    SYSLOG_3164 = "<34>Jun  1 10:05:00 192.168.0.1 sshd[1234]: Failed password for root from 10.0.0.5 port 22"
    SYSLOG_5424 = "<165>1 2024-06-01T10:00:00Z mymachine.example.com sshd 1234 - - Failed password for invalid user bob from 198.51.100.5 port 22 ssh2"

    def test_rfc3164_returns_log_event(self, normalizer):
        event = normalizer.normalize(self.SYSLOG_3164, "siem")
        assert isinstance(event, LogEvent)

    def test_rfc3164_source_system(self, normalizer):
        event = normalizer.normalize(self.SYSLOG_3164, "siem")
        assert event.source_system == "siem"

    def test_rfc3164_ip_from_message(self, normalizer):
        event = normalizer.normalize(self.SYSLOG_3164, "siem")
        # The message contains "10.0.0.5"; hostname is "192.168.0.1"
        assert event.source_ip in ("192.168.0.1", "10.0.0.5")

    def test_rfc3164_timestamp_parsed(self, normalizer):
        event = normalizer.normalize(self.SYSLOG_3164, "siem")
        assert isinstance(event.timestamp, datetime)

    def test_rfc3164_raw_preserved(self, normalizer):
        event = normalizer.normalize(self.SYSLOG_3164, "siem")
        assert "Failed password" in event.raw_data

    def test_rfc5424_returns_log_event(self, normalizer):
        event = normalizer.normalize(self.SYSLOG_5424, "siem")
        assert isinstance(event, LogEvent)

    def test_rfc5424_event_type_contains_app(self, normalizer):
        event = normalizer.normalize(self.SYSLOG_5424, "siem")
        assert "sshd" in event.event_type

    def test_auth_ingestor_with_syslog(self):
        ingestor = AuthIngestor()
        event = ingestor.ingest(self.SYSLOG_3164)
        assert event.source_system == "auth"


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Unstructured normalisation
# ─────────────────────────────────────────────────────────────────────────────

class TestUnstructuredNormalization:
    """Verify that free-text input is captured verbatim with basic IP extraction."""

    FREE_TEXT = "ALERT: Suspicious connection from 172.16.0.99 detected at 10:25 UTC."

    def test_returns_log_event(self, normalizer):
        event = normalizer.normalize(self.FREE_TEXT, "system_log")
        assert isinstance(event, LogEvent)

    def test_event_type_is_unstructured(self, normalizer):
        event = normalizer.normalize(self.FREE_TEXT, "system_log")
        assert event.event_type == "unstructured"

    def test_ip_extracted_from_text(self, normalizer):
        event = normalizer.normalize(self.FREE_TEXT, "system_log")
        assert event.source_ip == "172.16.0.99"

    def test_raw_data_preserved(self, normalizer):
        event = normalizer.normalize(self.FREE_TEXT, "system_log")
        assert event.raw_data == self.FREE_TEXT

    def test_no_ip_defaults_to_zero(self, normalizer):
        event = normalizer.normalize("No IP here at all.", "system_log")
        assert event.source_ip == "0.0.0.0"

    def test_unstructured_parser_ingestor(self):
        parser = UnstructuredParser()
        event = parser.ingest(self.FREE_TEXT)
        assert event.source_system == "system_log"
        assert event.source_ip == "172.16.0.99"

    def test_schema_from_dict(self, normalizer):
        event = normalizer.normalize(self.FREE_TEXT, "system_log")
        d = event.to_dict()
        reconstructed = LogEvent.from_dict(d)
        assert reconstructed.event_id == event.event_id
        assert reconstructed.raw_data == self.FREE_TEXT


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — Elasticsearch client graceful failure
# ─────────────────────────────────────────────────────────────────────────────

class TestEsClientGracefulFailure:
    """Verify that ES being unavailable never crashes the application."""

    def test_index_event_returns_false_when_disconnected(self):
        """Instantiate a client pointing at a port that is (almost certainly)
        not running ES and verify that index_event() returns False, not raises.
        """
        from storage.es_client import ElasticsearchClient
        client = ElasticsearchClient(host="127.0.0.1", port=19200)
        event = LogEvent(source_ip="1.2.3.4", event_type="test")
        result = client.index_event(event)
        assert result is False

    def test_index_incident_returns_false_when_disconnected(self):
        from storage.es_client import ElasticsearchClient
        client = ElasticsearchClient(host="127.0.0.1", port=19200)
        result = client.index_incident({"id": "test-1", "type": "malware"})
        assert result is False

    def test_search_events_returns_empty_list_when_disconnected(self):
        from storage.es_client import ElasticsearchClient
        client = ElasticsearchClient(host="127.0.0.1", port=19200)
        results = client.search_events({"query": {"match_all": {}}})
        assert results == []

    def test_get_event_by_id_returns_none_when_disconnected(self):
        from storage.es_client import ElasticsearchClient
        client = ElasticsearchClient(host="127.0.0.1", port=19200)
        result = client.get_event_by_id("non-existent-id")
        assert result is None

    def test_is_connected_false_when_disconnected(self):
        from storage.es_client import ElasticsearchClient
        client = ElasticsearchClient(host="127.0.0.1", port=19200)
        assert client.is_connected is False

    def test_no_exception_raised_on_index(self):
        """The critical contract: zero exceptions bubble up to the caller."""
        from storage.es_client import ElasticsearchClient
        client = ElasticsearchClient(host="127.0.0.1", port=19200)
        event = LogEvent(source_ip="9.9.9.9", event_type="test")
        try:
            client.index_event(event)
        except Exception as exc:
            pytest.fail(f"es_client.index_event raised an exception: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — POST /api/ingest/siem route
# ─────────────────────────────────────────────────────────────────────────────

class TestIngestSiemRoute:
    """Verify that the new Flask route returns 200 with a valid JWT."""

    SAMPLE_SIEM_EVENT = {
        "src_ip": "10.10.10.1",
        "event_type": "malware_detected",
        "action": "quarantine",
        "user": "bob",
    }

    def test_siem_route_returns_200(self, flask_test_client):
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token — check ADMIN_USER/ADMIN_PASS in config")

        resp = client.post(
            "/api/ingest/siem",
            json=self.SAMPLE_SIEM_EVENT,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_siem_route_returns_event_id(self, flask_test_client):
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token")

        resp = client.post(
            "/api/ingest/siem",
            json=self.SAMPLE_SIEM_EVENT,
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.get_json()
        assert "event_id" in data
        assert data["event_id"] is not None

    def test_siem_route_returns_correct_source_system(self, flask_test_client):
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token")

        resp = client.post(
            "/api/ingest/siem",
            json=self.SAMPLE_SIEM_EVENT,
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.get_json()
        assert data.get("source_system") == "siem"

    def test_siem_route_confidence_is_populated(self, flask_test_client):
        """confidence is now populated after Phase 2/3."""
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token")

        resp = client.post(
            "/api/ingest/siem",
            json=self.SAMPLE_SIEM_EVENT,
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.get_json()
        assert data.get("confidence") is not None

    def test_siem_route_without_jwt_returns_401(self, flask_test_client):
        client, _ = flask_test_client
        resp = client.post(
            "/api/ingest/siem",
            json=self.SAMPLE_SIEM_EVENT,
        )
        assert resp.status_code == 401

    def test_siem_route_accepts_array(self, flask_test_client):
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token")

        events = [self.SAMPLE_SIEM_EVENT, {**self.SAMPLE_SIEM_EVENT, "user": "carol"}]
        resp = client.post(
            "/api/ingest/siem",
            json=events,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("total") == 2

    def test_edr_route_returns_200(self, flask_test_client):
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token")

        resp = client.post(
            "/api/ingest/edr",
            json={"ip": "192.168.5.5", "event_type": "process_injection", "action": "kill"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_auth_route_returns_200(self, flask_test_client):
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token")

        resp = client.post(
            "/api/ingest/auth",
            json={"source_ip": "10.1.2.3", "user_id": "dave", "event_type": "mfa_failure"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_logs_route_returns_200_with_plain_text(self, flask_test_client):
        client, token = flask_test_client
        if token is None:
            pytest.skip("Could not obtain JWT token")

        resp = client.post(
            "/api/ingest/logs",
            data="WARN: Connection from 203.0.113.77 blocked",
            content_type="text/plain",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
