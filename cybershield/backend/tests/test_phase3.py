"""
tests/test_phase3.py
────────────────────────────────────────────────────────────────────────────────
Phase 3 verification tests — incident correlation engine and MITRE mapper.

Covers:
  1. MITRE mapper correctly mapping SQLi to T1190
  2. MITRE mapper correctly mapping Bruteforce to T1110
  3. CorrelationEngine ignoring low-fidelity events
  4. CorrelationEngine creating incidents for HIGH/CRITICAL events
  5. CorrelationEngine merging new events into existing OPEN incidents
  6. Incident model serialization round-trip (to_dict / from_es_doc)
"""
from __future__ import annotations

import sys
import os
import time

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import pytest
import uuid
from datetime import datetime, timezone

from ingestion.schema import LogEvent
from models.incident import Incident
from correlation.mitre_mapper import MitreMapper
from correlation.correlation_engine import CorrelationEngine
from detection.fidelity_ranker import FidelityResult


# ─────────────────────────────────────────────────────────────────────────────
# Mocks and Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_event(
    event_type: str = "generic",
    source_ip: str = "10.0.0.1",
    user_id: str = None,
    payload: dict = None,
    raw_data: str = "",
) -> LogEvent:
    return LogEvent(
        source_system="siem",
        event_type=event_type,
        source_ip=source_ip,
        user_id=user_id,
        timestamp=datetime.utcnow(),
        payload=payload or {},
        raw_data=raw_data,
    )

def _make_fidelity(tier: str = "HIGH", score: float = 0.8) -> FidelityResult:
    return FidelityResult(
        combined_score=score,
        tier=tier,
        dominant_signal="rule",
        scores_breakdown={}
    )


# A dummy ES client to mock Elasticsearch interactions in the tests
class MockESClient:
    def __init__(self):
        self.is_connected = True
        self.indexed_events = []
        self.indexed_incidents = {}
        
    def index_event(self, event):
        self.indexed_events.append(event)
        return True
        
    def index_incident(self, incident_doc):
        inc_id = incident_doc.get("incident_id")
        if inc_id:
            self.indexed_incidents[inc_id] = incident_doc
        return True
        
    def search_events(self, query, index, size=10):
        if index == "cybershield-incidents":
            # Very basic mock for finding OPEN incidents by IP
            should_clauses = query.get("query", {}).get("bool", {}).get("should", [])
            has_ip_query = any("related_ips" in clause.get("term", {}) for clause in should_clauses)
            
            if has_ip_query:
                ip = [c["term"]["related_ips"] for c in should_clauses if "related_ips" in c["term"]][0]
                results = []
                for inc in self.indexed_incidents.values():
                    if inc.get("status") == "OPEN" and ip in inc.get("related_ips", []):
                        results.append(inc)
                # Sort descending by created_at
                return sorted(results, key=lambda x: x.get("created_at", ""), reverse=True)[:size]
        return []
        
    def get_event_by_id(self, doc_id, index):
        if index == "cybershield-incidents":
            return self.indexed_incidents.get(doc_id)
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Test 1 & 2 — MITRE Mapper
# ─────────────────────────────────────────────────────────────────────────────

class TestMitreMapper:
    
    def test_mitre_mapper_sqli_returns_T1190(self):
        mapper = MitreMapper()
        # Ensure it has loaded techniques (it tries to load automatically)
        if mapper.technique_count == 0:
            pytest.skip("MITRE JSON file not found or empty.")
            
        event = _make_event(event_type="sql_injection", payload={"path": "/login?user=' OR 1=1--"})
        techniques = mapper.map_from_event(event)
        
        assert "T1190" in techniques
        
    def test_mitre_mapper_bruteforce_returns_T1110(self):
        mapper = MitreMapper()
        if mapper.technique_count == 0:
            pytest.skip("MITRE JSON file not found or empty.")
            
        event = _make_event(event_type="brute_force")
        techniques = mapper.map_from_event(event)
        
        assert "T1110" in techniques

    def test_mitre_mapper_no_match_returns_empty(self):
        mapper = MitreMapper()
        event = _make_event(event_type="benign_activity", payload={"foo": "bar"})
        techniques = mapper.map_from_event(event)
        
        assert techniques == []


# ─────────────────────────────────────────────────────────────────────────────
# Test 3, 4, 5 — Correlation Engine
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationEngine:

    @pytest.fixture(autouse=True)
    def patch_es(self, monkeypatch):
        # Patch ES client in the correlation engine to use our mock
        mock_es = MockESClient()
        monkeypatch.setattr("correlation.correlation_engine.es_client", mock_es)
        self.mock_es = mock_es

    def test_correlation_engine_low_fidelity_returns_none(self):
        engine = CorrelationEngine()
        event = _make_event()
        fidelity = _make_fidelity(tier="LOW", score=0.2)
        
        incident = engine.correlate(event, fidelity)
        assert incident is None

    def test_correlation_engine_medium_fidelity_returns_none(self):
        engine = CorrelationEngine()
        event = _make_event()
        fidelity = _make_fidelity(tier="MEDIUM", score=0.5)
        
        incident = engine.correlate(event, fidelity)
        assert incident is None

    def test_correlation_engine_creates_incident_for_critical(self):
        engine = CorrelationEngine()
        event = _make_event(event_type="sql_injection", source_ip="192.168.1.50")
        fidelity = _make_fidelity(tier="CRITICAL", score=0.95)
        
        incident = engine.correlate(event, fidelity)
        
        assert incident is not None
        assert incident.severity == "CRITICAL"
        assert incident.status == "OPEN"
        assert "192.168.1.50" in incident.related_ips
        assert event.event_id in incident.related_event_ids
        
        # Verify it was indexed
        assert incident.incident_id in self.mock_es.indexed_incidents

    def test_correlation_engine_merges_into_existing_incident(self):
        engine = CorrelationEngine()
        
        # 1. First event creates an incident
        event1 = _make_event(event_type="brute_force", source_ip="10.0.0.99")
        fidelity1 = _make_fidelity(tier="HIGH", score=0.8)
        
        incident1 = engine.correlate(event1, fidelity1)
        assert incident1 is not None
        assert len(incident1.related_event_ids) == 1
        
        # 2. Second event from same IP should merge
        event2 = _make_event(event_type="xss", source_ip="10.0.0.99")
        fidelity2 = _make_fidelity(tier="CRITICAL", score=0.9)
        
        incident2 = engine.correlate(event2, fidelity2)
        
        assert incident2 is not None
        assert incident2.incident_id == incident1.incident_id # Same ID
        assert len(incident2.related_event_ids) == 2
        assert event1.event_id in incident2.related_event_ids
        assert event2.event_id in incident2.related_event_ids
        # Severity should ratchet up to CRITICAL
        assert incident2.severity == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — Incident Serialization
# ─────────────────────────────────────────────────────────────────────────────

class TestIncidentSerialization:

    def test_incident_serialization_roundtrip(self):
        # Create a populated incident
        incident = Incident(
            severity="HIGH",
            status="OPEN",
            title="Test Incident",
            affected_systems=["siem", "edr"],
            related_ips=["1.2.3.4", "5.6.7.8"],
            related_users=["alice", "bob"],
            mitre_techniques=["T1110", "T1190"],
            analyst_notes="Looks suspicious.",
        )
        incident.add_event("evt-123", "[SIEM] sql_injection from 1.2.3.4")
        
        # Serialize to dict suitable for ES
        es_doc = incident.to_es_doc()
        
        assert es_doc["severity"] == "HIGH"
        assert "created_at" in es_doc
        assert isinstance(es_doc["created_at"], str) # Must be ISO string
        
        # Deserialize
        restored = Incident.from_es_doc(es_doc)
        
        assert restored.incident_id == incident.incident_id
        assert restored.severity == "HIGH"
        assert restored.status == "OPEN"
        assert restored.title == "Test Incident"
        assert set(restored.affected_systems) == {"siem", "edr"}
        assert set(restored.related_ips) == {"1.2.3.4", "5.6.7.8"}
        assert set(restored.mitre_techniques) == {"T1110", "T1190"}
        assert restored.analyst_notes == "Looks suspicious."
        assert len(restored.timeline) == 1
        assert restored.timeline[0]["event_id"] == "evt-123"
        # Dates should be preserved
        assert restored.created_at == incident.created_at
        
        
    def test_from_es_doc_with_missing_fields_uses_defaults(self):
        doc = {"incident_id": "test-id-123"} # Minimal doc
        
        incident = Incident.from_es_doc(doc)
        
        assert incident.incident_id == "test-id-123"
        assert incident.severity == "LOW"
        assert incident.status == "OPEN"
        assert incident.related_ips == []
        assert incident.timeline == []
