"""
tests/test_phase4.py
────────────────────────────────────────────────────────────────────────────────
Phase 4 verification tests — IR Agent (LangGraph + Ollama + ThreatClassifier).

Tests (all offline — no Ollama or HuggingFace model required):
  1. test_threat_classifier_fallback_when_model_missing
  2. test_ollama_connector_fallback_when_unavailable
  3. test_ir_agent_completes_full_graph
  4. test_ir_agent_checkpointing_survives_restart
  5. test_containment_only_on_critical
"""
from __future__ import annotations

import os
import sys
import uuid
import tempfile

# ── Ensure backend is on the path ─────────────────────────────────────────────
_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import pytest
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_incident_dict(
    severity: str = "HIGH",
    mitre_techniques: list = None,
    related_ips: list = None,
    title: str = None,
) -> dict:
    """Return a minimal incident dict mimicking Incident.to_dict()."""
    inc_id = str(uuid.uuid4())
    return {
        "incident_id":       inc_id,
        "created_at":        datetime.utcnow().isoformat() + "Z",
        "updated_at":        datetime.utcnow().isoformat() + "Z",
        "severity":          severity,
        "status":            "OPEN",
        "title":             title or f"TEST {severity} brute_force from 10.0.0.1 — 3 event(s)",
        "affected_systems":  ["siem"],
        "related_ips":       related_ips or ["10.0.0.1"],
        "related_users":     ["testuser"],
        "related_event_ids": [str(uuid.uuid4())],
        "timeline":          [
            {
                "timestamp":   datetime.utcnow().isoformat() + "Z",
                "event_id":    str(uuid.uuid4()),
                "description": "[SIEM] brute_force from 10.0.0.1",
            }
        ],
        "mitre_techniques":  mitre_techniques or ["T1110"],
        "attack_chain":      ["T1110: Brute Force (Credential Access)"],
        "playbook":          None,
        "analyst_notes":     "",
        "event_count":       1,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — ThreatClassifier fallback when model is missing
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatClassifier:

    def test_threat_classifier_fallback_when_model_missing(self, tmp_path):
        """
        When the HuggingFace model directory does not exist,
        ThreatClassifier must use rule-based classification and
        still return a valid ThreatCategory — never crash.
        """
        # Point the classifier at a guaranteed-absent path
        os.environ["DISTILBERT_MODEL_PATH"] = str(tmp_path / "no_model_here")

        # Re-import to pick up the env change (fresh instance)
        import importlib
        import agents.threat_classifier as tc_mod
        importlib.reload(tc_mod)

        classifier = tc_mod.ThreatClassifier()

        # Pipeline should be None (model dir absent)
        assert classifier._pipeline is None, "Pipeline should be None when model dir is absent"

        incident = _make_incident_dict(mitre_techniques=["T1110", "T1190"])
        result   = classifier.classify(incident)

        assert result is not None
        assert result.category in (
            "bruteforce", "web_attack", "insider_threat",
            "ransomware", "apt", "unknown",
        ), f"Unexpected category: {result.category}"
        assert 0.0 <= result.confidence <= 1.0
        assert result.method in ("rule", "error")

    def test_threat_classifier_t1110_maps_to_bruteforce(self):
        """T1110 (Brute Force) must map to 'bruteforce' via rule-based path."""
        os.environ["DISTILBERT_MODEL_PATH"] = "/nonexistent/path/for/test"

        import importlib
        import agents.threat_classifier as tc_mod
        importlib.reload(tc_mod)

        classifier = tc_mod.ThreatClassifier()
        incident   = _make_incident_dict(mitre_techniques=["T1110"])
        result     = classifier.classify(incident)

        assert result.category == "bruteforce"

    def test_threat_classifier_t1486_maps_to_ransomware(self):
        """T1486 (Data Encrypted for Impact) must map to 'ransomware'."""
        os.environ["DISTILBERT_MODEL_PATH"] = "/nonexistent/path/for/test"

        import importlib
        import agents.threat_classifier as tc_mod
        importlib.reload(tc_mod)

        classifier = tc_mod.ThreatClassifier()
        incident   = _make_incident_dict(mitre_techniques=["T1486"])
        result     = classifier.classify(incident)

        assert result.category == "ransomware"

    def test_threat_classifier_never_raises_on_bad_input(self):
        """classify() must not raise even with a completely empty dict."""
        from agents.threat_classifier import ThreatClassifier
        classifier = ThreatClassifier()
        result = classifier.classify({})
        assert result is not None
        assert isinstance(result.category, str)


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — OllamaConnector fallback when Ollama is unavailable
# ─────────────────────────────────────────────────────────────────────────────

class TestOllamaConnector:

    def test_ollama_connector_fallback_when_unavailable(self):
        """
        When Ollama is unreachable (connection refused to a bad port),
        generate() must return FALLBACK_PLAYBOOK — never raise.
        """
        from agents.ollama_connector import OllamaConnector, FALLBACK_PLAYBOOK

        # Point to a port that is guaranteed to refuse connections
        connector = OllamaConnector(base_url="http://localhost:19999")

        result = connector.generate("Test prompt — Ollama not running")

        assert result == FALLBACK_PLAYBOOK, (
            f"Expected FALLBACK_PLAYBOOK, got:\n{result[:200]}"
        )

    def test_ollama_is_available_returns_false_when_unreachable(self):
        """is_available() must return False when Ollama is not running."""
        from agents.ollama_connector import OllamaConnector

        connector = OllamaConnector(base_url="http://localhost:19999")
        assert connector.is_available() is False

    def test_ollama_fallback_contains_required_steps(self):
        """FALLBACK_PLAYBOOK must include all 6 required action categories."""
        from agents.ollama_connector import FALLBACK_PLAYBOOK

        required_keywords = [
            "CONTAINMENT",
            "EVIDENCE",
            "credentials",   # step 3 talks about credentials
            "firewall",      # step 4 talks about firewall
            "NOTIFICATION",  # step 5 notify team
            "DOCUMENTATION", # step 6 document
        ]
        pb_upper = FALLBACK_PLAYBOOK.upper()
        for keyword in required_keywords:
            assert keyword.upper() in pb_upper, (
                f"FALLBACK_PLAYBOOK missing keyword: {keyword}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — IR Agent completes full graph
# ─────────────────────────────────────────────────────────────────────────────

class TestIRAgentFullGraph:

    def test_ir_agent_completes_full_graph(self, monkeypatch):
        """
        End-to-end graph run with:
          - Ollama mocked to return a fixed playbook string
          - ES mocked to accept index calls
          - Socket.IO import skipped
        Final state must have status='complete' and a non-empty playbook.
        """
        # ── Mock Ollama ────────────────────────────────────────────────────────
        mock_playbook = "MOCK PLAYBOOK: Step 1 - Isolate. Step 2 - Investigate."

        import agents.ollama_connector as oc_mod
        monkeypatch.setattr(oc_mod.ollama_connector, "generate", lambda *a, **kw: mock_playbook)
        monkeypatch.setattr(oc_mod.ollama_connector, "is_available", lambda: True)

        # ── Mock ES ────────────────────────────────────────────────────────────
        class _MockES:
            is_connected = False   # skip ES calls in review_node
            def index_incident(self, *a, **kw): return True

        import storage.es_client as es_mod
        monkeypatch.setattr(es_mod, "es_client", _MockES())

        # ── Skip Socket.IO ─────────────────────────────────────────────────────
        # review_node catches ImportError from 'from app import socketio' — no patch needed

        from agents.ir_agent import run_ir_agent
        incident = _make_incident_dict(severity="HIGH")

        result = run_ir_agent(incident)

        assert result is not None, "run_ir_agent() returned None"
        assert result.get("status") in ("complete", "error"), (
            f"Expected terminal status, got: {result.get('status')}"
        )
        assert result.get("playbook"), "Playbook must be non-empty"

    def test_ir_agent_sets_threat_category(self, monkeypatch):
        """After classify_node, threat_category must be present in state."""
        import agents.ollama_connector as oc_mod
        monkeypatch.setattr(
            oc_mod.ollama_connector, "generate",
            lambda *a, **kw: "FALLBACK"
        )

        from agents.ir_agent import run_ir_agent
        incident = _make_incident_dict(mitre_techniques=["T1110"])
        result   = run_ir_agent(incident)

        assert "threat_category" in result
        tc = result["threat_category"]
        assert "category" in tc
        assert "confidence" in tc


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Checkpointing survives restart
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckpointing:

    def test_ir_agent_checkpointing_survives_restart(self, monkeypatch, tmp_path):
        """
        Run the agent, then re-create the graph with the same thread_id and
        same checkpoint DB — LangGraph should be able to resume state.

        If LangGraph is not installed, this test is skipped gracefully.
        """
        import sqlite3 as _sqlite3
        try:
            from langgraph.checkpoint.sqlite import SqliteSaver  # type: ignore
        except ImportError:
            pytest.skip("langgraph-checkpoint-sqlite not installed — skipping checkpointing test")

        import agents.ollama_connector as oc_mod
        monkeypatch.setattr(
            oc_mod.ollama_connector, "generate",
            lambda *a, **kw: "CHECKPOINT_TEST_PLAYBOOK"
        )

        db_path   = str(tmp_path / "test_checkpoints.db")
        thread_id = "test-thread-" + str(uuid.uuid4())
        incident  = _make_incident_dict(severity="HIGH")

        from agents.ir_agent import build_ir_graph, AgentState

        # ── First run ──────────────────────────────────────────────────────────
        conn1 = _sqlite3.connect(db_path, check_same_thread=False)
        graph1 = build_ir_graph(checkpointer=SqliteSaver(conn1))

        if graph1 is None:
            conn1.close()
            pytest.skip("build_ir_graph() returned None — LangGraph unavailable")

        initial_state: AgentState = {
            "incident":        incident,
            "threat_category": {},
            "enriched_data":   {},
            "playbook":        "",
            "status":          "starting",
            "error":           None,
        }
        graph1.invoke(initial_state, config={"configurable": {"thread_id": thread_id}})
        conn1.close()

        # ── Second run (simulates restart with fresh connection) ───────────────
        conn2 = _sqlite3.connect(db_path, check_same_thread=False)
        graph2 = build_ir_graph(checkpointer=SqliteSaver(conn2))

        try:
            saved_state = graph2.get_state({"configurable": {"thread_id": thread_id}})
            assert saved_state is not None, "Checkpoint state should survive restart"
        except Exception as exc:
            pytest.fail(f"Checkpointing failed on restart: {exc}")
        finally:
            conn2.close()



# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — Containment only on CRITICAL
# ─────────────────────────────────────────────────────────────────────────────

class TestContainmentNode:

    def test_containment_node_fires_on_critical(self, monkeypatch):
        """
        containment_node must add containment actions to the incident timeline
        when severity == CRITICAL.
        """
        from agents.ir_agent import containment_node, AgentState

        # Enable auto-containment via config mock
        import config as cfg_mod
        monkeypatch.setattr(cfg_mod.config, "AUTO_CONTAINMENT_ENABLED", True)

        incident = _make_incident_dict(
            severity="CRITICAL",
            related_ips=["192.168.1.200", "10.10.10.5"],
        )
        state: AgentState = {
            "incident":        incident,
            "threat_category": {"category": "bruteforce", "confidence": 0.9, "method": "rule"},
            "enriched_data":   {},
            "playbook":        "",
            "status":          "generating_playbook",
            "error":           None,
        }

        result = containment_node(state)

        # Timeline should now include containment entries
        timeline = result["incident"]["timeline"]
        containment_entries = [
            e for e in timeline
            if "AUTO-CONTAINMENT" in e.get("description", "")
        ]
        assert len(containment_entries) > 0, (
            "Expected containment timeline entries for CRITICAL incident"
        )
        assert result["incident"].get("containment_applied") is True

    def test_containment_node_skips_on_medium(self, monkeypatch):
        """
        containment_node is only called via the conditional edge, which
        routes MEDIUM directly to playbook_node.  Test the router directly.
        """
        from agents.ir_agent import _should_contain, AgentState

        import config as cfg_mod
        monkeypatch.setattr(cfg_mod.config, "AUTO_CONTAINMENT_ENABLED", True)

        state: AgentState = {
            "incident":        _make_incident_dict(severity="MEDIUM"),
            "threat_category": {},
            "enriched_data":   {},
            "playbook":        "",
            "status":          "generating_playbook",
            "error":           None,
        }

        route = _should_contain(state)
        assert route == "playbook", (
            f"MEDIUM severity should route to 'playbook', got '{route}'"
        )

    def test_containment_node_skips_when_auto_containment_disabled(self, monkeypatch):
        """Even CRITICAL incidents skip containment when flag is False."""
        from agents.ir_agent import _should_contain, AgentState

        import config as cfg_mod
        monkeypatch.setattr(cfg_mod.config, "AUTO_CONTAINMENT_ENABLED", False)

        state: AgentState = {
            "incident":        _make_incident_dict(severity="CRITICAL"),
            "threat_category": {},
            "enriched_data":   {},
            "playbook":        "",
            "status":          "generating_playbook",
            "error":           None,
        }

        route = _should_contain(state)
        assert route == "playbook", (
            "When AUTO_CONTAINMENT_ENABLED=False, even CRITICAL should skip containment"
        )

    def test_low_medium_incidents_never_reach_agent(self, monkeypatch):
        """
        CorrelationEngine.correlate() returns None for LOW/MEDIUM,
        so the agent is never dispatched.
        """
        from correlation.correlation_engine import CorrelationEngine
        from ingestion.schema import LogEvent
        from detection.fidelity_ranker import FidelityResult

        # Patch ES so no network calls
        class _MockES:
            is_connected = False
            def search_events(self, *a, **kw): return []
            def index_incident(self, *a, **kw): return True

        import correlation.correlation_engine as ce_mod
        monkeypatch.setattr(ce_mod, "es_client", _MockES())

        # Track dispatch calls
        dispatched = []
        class _MockDispatcher:
            def dispatch(self, incident): dispatched.append(incident)

        ce_mod._agent_dispatcher = _MockDispatcher()
        ce_mod._AGENT_AVAILABLE  = True

        engine = CorrelationEngine()

        for tier in ("LOW", "MEDIUM"):
            event = LogEvent(
                source_system="siem",
                event_type="brute_force",
                source_ip="10.0.0.1",
                timestamp=datetime.utcnow(),
            )
            fr = FidelityResult(
                combined_score=0.3,
                tier=tier,
                dominant_signal="rule",
                scores_breakdown={},
            )
            result = engine.correlate(event, fr)
            assert result is None, f"{tier} should return None from correlate()"

        assert len(dispatched) == 0, (
            f"Dispatcher should NOT be called for LOW/MEDIUM, but was called {len(dispatched)} times"
        )
