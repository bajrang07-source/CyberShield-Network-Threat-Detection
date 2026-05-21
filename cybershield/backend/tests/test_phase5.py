"""
tests/test_phase5.py
────────────────────────────────────────────────────────────────────────────────
Phase 5 verification tests — Incident API & SOC Extensions.

Tests:
  - test_get_incidents_returns_200
  - test_get_incident_by_id
  - test_incident_action_resolve_updates_status
  - test_get_mitre_heatmap_returns_dict
  - test_soc_stats_endpoint_returns_all_fields
  - test_existing_api_routes_unchanged
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime

# ── Ensure backend is on the path ─────────────────────────────────────────────
_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import pytest
from flask_jwt_extended import create_access_token
from app import app
from models.incident import Incident


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["JWT_SECRET_KEY"] = "test-secret"
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def access_token():
    with app.app_context():
        return create_access_token(identity="admin")


@pytest.fixture
def mock_es(monkeypatch):
    """Mock the Elasticsearch client to return fake data."""
    class MockES:
        is_connected = True
        
        class _MockInnerES:
            def search(self, index, body, size=None, **kwargs):
                if "mitre_techniques" in str(body):
                    return {
                        "aggregations": {
                            "mitre_techniques": {
                                "buckets": [
                                    {"key": "T1110", "doc_count": 5},
                                    {"key": "T1190", "doc_count": 2},
                                ]
                            }
                        }
                    }
                if "range" in str(body) and "created_at" in str(body):
                    # SOC stats query
                    return {
                        "hits": {"total": {"value": 10}},
                        "aggregations": {
                            "status_open": {"doc_count": 4},
                            "critical_open": {"doc_count": 1},
                            "total_events": {"value": 15},
                        }
                    }
                return {"hits": {"hits": []}}

        def __init__(self):
            self._es = self._MockInnerES()

        def search_events(self, query, index, size=100):
            # For list_incidents
            inc_id = str(uuid.uuid4())
            return [{
                "incident_id": inc_id,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "updated_at": datetime.utcnow().isoformat() + "Z",
                "severity": "HIGH",
                "status": "OPEN",
                "title": "Test Incident",
                "affected_systems": [],
                "related_ips": [],
                "related_users": [],
                "related_event_ids": [],
                "timeline": [],
                "mitre_techniques": [],
                "attack_chain": [],
                "playbook": None,
                "analyst_notes": "",
                "event_count": 1,
            }]

        def get_event_by_id(self, event_id, index):
            # For get_incident
            if event_id == "not-found":
                return None
            return {
                "incident_id": event_id,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "updated_at": datetime.utcnow().isoformat() + "Z",
                "severity": "CRITICAL",
                "status": "OPEN",
                "title": "Specific Incident",
                "affected_systems": [],
                "related_ips": [],
                "related_users": [],
                "related_event_ids": [],
                "timeline": [],
                "mitre_techniques": ["T1110"],
                "attack_chain": [],
                "playbook": "MOCK PLAYBOOK TEXT",
                "analyst_notes": "",
                "event_count": 1,
            }

        def index_incident(self, doc):
            return True

    import api.incident_routes as inc_mod
    monkeypatch.setattr(inc_mod, "es_client", MockES())
    
    # Also patch for threat_service if any tests reach there
    import services.threat_service as ts_mod
    try:
        monkeypatch.setattr(ts_mod.es_client, "is_connected", True, raising=False)
    except:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_get_incidents_returns_200(client, access_token, mock_es):
    """GET /api/incidents should return paginated list from ES."""
    res = client.get(
        "/api/incidents",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "incidents" in data
    assert len(data["incidents"]) > 0


def test_get_incident_by_id(client, access_token, mock_es):
    """GET /api/incidents/<id> should return full incident."""
    inc_id = str(uuid.uuid4())
    res = client.get(
        f"/api/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["incident"]["incident_id"] == inc_id
    assert data["incident"]["playbook"] == "MOCK PLAYBOOK TEXT"

    # Test 404
    res_404 = client.get(
        "/api/incidents/not-found",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert res_404.status_code == 404


def test_incident_action_resolve_updates_status(client, access_token, mock_es, monkeypatch):
    """POST /api/incidents/<id>/action with 'resolve' or 'dismiss'."""
    inc_id = str(uuid.uuid4())
    
    # Mock emit to prevent actual socket calls
    import api.events as events_mod
    monkeypatch.setattr(events_mod, "_get_socketio", lambda: None)
    monkeypatch.setattr(events_mod, "_emit", lambda *a, **kw: None)

    # Test resolve
    res_resolve = client.post(
        f"/api/incidents/{inc_id}/action",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"action": "resolve"}
    )
    assert res_resolve.status_code == 200
    assert res_resolve.get_json()["new_status"] == "RESOLVED"

    # Test dismiss (Phase 5 addition)
    res_dismiss = client.post(
        f"/api/incidents/{inc_id}/action",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"action": "dismiss"}
    )
    assert res_dismiss.status_code == 200
    assert res_dismiss.get_json()["new_status"] == "FALSE_POSITIVE"


def test_get_mitre_heatmap_returns_dict(client, access_token, mock_es):
    """GET /api/mitre/heatmap should return {technique: count}."""
    res = client.get(
        "/api/mitre/heatmap",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["heatmap"]["T1110"] == 5
    assert data["heatmap"]["T1190"] == 2


def test_soc_stats_endpoint_returns_all_fields(client, access_token, mock_es):
    """GET /api/soc/stats should return all requested stats fields."""
    res = client.get(
        "/api/soc/stats",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    
    stats = data["stats"]
    assert "total_alerts_today" in stats
    assert "deduplicated_count" in stats
    assert "analyst_fatigue_ratio" in stats
    assert "open_incidents" in stats
    assert "critical_count" in stats
    assert "mean_time_to_detect_minutes" in stats
    
    # Verify mock values
    assert stats["total_alerts_today"] == 10
    assert stats["open_incidents"] == 4
    assert stats["critical_count"] == 1
    assert stats["deduplicated_count"] == 5  # 15 total events - 10 incidents


def test_existing_api_routes_unchanged(client):
    """Spot check original routes to ensure Phase 5 didn't break them."""
    # 1. /api/health
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    assert res_health.get_json()["status"] == "ok"
    
    # 2. /api/auth/login (missing creds)
    res_auth = client.post("/api/auth/login", json={})
    assert res_auth.status_code == 401
    
    # 3. Honeypot routes
    res_hp = client.get("/wp-login.php")
    assert res_hp.status_code == 404
    assert "Not Found" in res_hp.get_data(as_text=True)
