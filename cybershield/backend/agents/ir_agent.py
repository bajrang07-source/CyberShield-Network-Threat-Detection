"""
agents/ir_agent.py
────────────────────────────────────────────────────────────────────────────────
Autonomous Incident Response Agent — LangGraph StateGraph implementation.

Phase 4, Step 3.

State machine:
    START → ingest_node → classify_node → enrich_node
          → [CRITICAL: containment_node] → playbook_node → review_node → END

Design decisions:
  • 100% offline — Ollama at localhost:11434, HuggingFace from /models/.
  • SQLite checkpointer persists graph state across restarts.
  • review_node emits Socket.IO "playbook_ready" via the Flask app's socketio
    (imported lazily; silently skipped if not available in this context).
  • containment_node logs the block action — it does NOT touch the forbidden
    response_engine.py.  The block is recorded in the incident timeline.
  • Every node catches exceptions internally — the graph NEVER crashes.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

import sqlite3

logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_BACKEND_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MITRE_JSON     = os.path.join(_BACKEND_DIR, "data", "mitre_techniques.json")
_BANKING_JSON   = os.path.join(_BACKEND_DIR, "data", "banking_threat_intel.json")
_CHECKPOINT_DB  = os.path.join(_BACKEND_DIR, "data", "agent_checkpoints.db")

# ── Lazy imports (LangGraph is optional — graceful failure) ───────────────────
try:
    from langgraph.graph import StateGraph, START, END                    # type: ignore
    from langgraph.checkpoint.sqlite import SqliteSaver                   # type: ignore
    # langgraph-checkpoint-sqlite 3.x: SqliteSaver(conn) not from_conn_string
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False
    logger.warning(
        "[IRAgent] langgraph not installed — IR agent will run in stub mode. "
        "Install with: pip install langgraph langgraph-checkpoint-sqlite"
    )

from agents.threat_classifier import threat_classifier
from agents.ollama_connector  import ollama_connector, FALLBACK_PLAYBOOK


# ─────────────────────────────────────────────────────────────────────────────
# Agent State
# ─────────────────────────────────────────────────────────────────────────────

class AgentState(TypedDict, total=False):
    """LangGraph state dict passed between nodes."""
    incident:         dict           # raw incident.to_dict()
    threat_category:  dict           # ThreatCategory serialized
    enriched_data:    dict           # MITRE details + banking intel
    playbook:         str            # final playbook text
    status:           str            # current processing stage
    error:            Optional[str]  # last error message, if any


# ─────────────────────────────────────────────────────────────────────────────
# Helper — JSON data loaders
# ─────────────────────────────────────────────────────────────────────────────

def _load_json_safe(path: str) -> Any:
    """Load a JSON file, returning an empty dict on any error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.warning("[IRAgent] Could not load %s: %s", path, exc)
        return {}


def _get_mitre_details(technique_ids: List[str]) -> List[Dict[str, Any]]:
    """Return technique dicts from mitre_techniques.json for the given IDs."""
    data = _load_json_safe(_MITRE_JSON)
    all_techs = data.get("techniques", [])
    id_set = set(technique_ids)
    return [t for t in all_techs if t.get("id") in id_set]


def _get_banking_intel(threat_category: str, technique_ids: List[str]) -> List[Dict[str, Any]]:
    """Return relevant banking threat intel entries."""
    data = _load_json_safe(_BANKING_JSON)
    threats = data.get("banking_threats", [])

    # Match by MITRE overlap or category keyword in name/description
    relevant: List[Dict[str, Any]] = []
    id_set = set(technique_ids)
    category_lower = threat_category.lower()

    for threat in threats:
        mitre_overlap = id_set & set(threat.get("mitre_techniques", []))
        name_match    = category_lower in threat.get("name", "").lower()
        desc_match    = any(
            w in threat.get("description", "").lower()
            for w in category_lower.split("_")
        )
        if mitre_overlap or name_match or desc_match:
            relevant.append(threat)

    return relevant[:3]  # cap at 3 entries to keep prompt manageable


# ─────────────────────────────────────────────────────────────────────────────
# Graph Nodes
# ─────────────────────────────────────────────────────────────────────────────

def ingest_node(state: AgentState) -> AgentState:
    """Validate the incident dict and set initial status."""
    try:
        incident = state.get("incident", {})
        if not incident or not incident.get("incident_id"):
            return {**state, "status": "error", "error": "Invalid or empty incident dict"}
        logger.info(
            "[IRAgent:ingest] Processing incident %s (severity=%s)",
            incident.get("incident_id"), incident.get("severity"),
        )
        return {**state, "status": "classifying", "error": None}
    except Exception as exc:
        logger.error("[IRAgent:ingest] Error: %s", exc)
        return {**state, "status": "error", "error": str(exc)}


def classify_node(state: AgentState) -> AgentState:
    """Classify the incident into a threat category."""
    try:
        incident = state.get("incident", {})
        result   = threat_classifier.classify(incident)
        logger.info(
            "[IRAgent:classify] category=%s confidence=%.2f method=%s",
            result.category, result.confidence, result.method,
        )
        return {
            **state,
            "threat_category": {
                "category":   result.category,
                "confidence": result.confidence,
                "method":     result.method,
            },
            "status": "enriching",
        }
    except Exception as exc:
        logger.error("[IRAgent:classify] Error: %s", exc)
        return {
            **state,
            "threat_category": {"category": "unknown", "confidence": 0.0, "method": "error"},
            "status": "enriching",
            "error": str(exc),
        }


def enrich_node(state: AgentState) -> AgentState:
    """Load MITRE technique details and banking threat intel."""
    try:
        incident         = state.get("incident", {})
        threat_category  = state.get("threat_category", {})
        technique_ids    = incident.get("mitre_techniques", [])
        category_str     = threat_category.get("category", "unknown")

        mitre_details   = _get_mitre_details(technique_ids)
        banking_intel   = _get_banking_intel(category_str, technique_ids)

        enriched = {
            "mitre_details":  mitre_details,
            "banking_intel":  banking_intel,
            "technique_count": len(mitre_details),
            "intel_count":    len(banking_intel),
        }
        logger.info(
            "[IRAgent:enrich] %d MITRE techniques, %d banking intel entries loaded.",
            enriched["technique_count"], enriched["intel_count"],
        )
        return {**state, "enriched_data": enriched, "status": "generating_playbook"}
    except Exception as exc:
        logger.error("[IRAgent:enrich] Error: %s", exc)
        return {
            **state,
            "enriched_data": {"mitre_details": [], "banking_intel": []},
            "status": "generating_playbook",
            "error": str(exc),
        }


def containment_node(state: AgentState) -> AgentState:
    """
    Perform automated containment for CRITICAL incidents.

    NOTE: This node LOGS containment actions and records them in the
    incident timeline. It does NOT touch response_engine.py (forbidden).
    The actual firewall block would be applied by the ops team or an
    existing runbook, triggered by the incident ticket.
    """
    try:
        incident    = state.get("incident", {})
        related_ips = incident.get("related_ips", [])
        inc_id      = incident.get("incident_id", "unknown")

        containment_actions = []
        for ip in related_ips:
            if ip and ip not in ("0.0.0.0", "127.0.0.1"):
                action = {
                    "timestamp":   datetime.utcnow().isoformat() + "Z",
                    "event_id":    f"containment-{inc_id}",
                    "description": f"[AUTO-CONTAINMENT] Block IP {ip} at perimeter firewall (pending ops team action)",
                }
                containment_actions.append(action)
                logger.warning(
                    "[IRAgent:containment] CRITICAL incident %s — containment flag set for IP: %s",
                    inc_id, ip,
                )

        if containment_actions:
            # Append to incident timeline in-state
            updated_incident = dict(incident)
            existing_timeline = list(updated_incident.get("timeline", []))
            existing_timeline.extend(containment_actions)
            updated_incident["timeline"] = existing_timeline
            updated_incident["containment_applied"] = True
            return {**state, "incident": updated_incident, "status": "generating_playbook"}

        return {**state, "status": "generating_playbook"}

    except Exception as exc:
        logger.error("[IRAgent:containment] Error: %s", exc)
        return {**state, "status": "generating_playbook", "error": str(exc)}


def _build_prompt(
    incident: dict,
    threat_category: dict,
    enriched_data: dict,
) -> str:
    """Build the SOC analyst prompt for Ollama."""
    mitre_lines = "\n".join(
        f"  - {t.get('id')}: {t.get('name')} ({t.get('tactic')})"
        for t in enriched_data.get("mitre_details", [])
    ) or "  - No MITRE techniques mapped"

    banking_lines = "\n".join(
        f"  - {b.get('name')}: {b.get('description', '')[:200]}"
        for b in enriched_data.get("banking_intel", [])
    ) or "  - No specific banking threat intel matched"

    attack_chain = "\n".join(
        f"  {i+1}. {step}" for i, step in enumerate(incident.get("attack_chain", []))
    ) or "  - Attack chain not yet mapped"

    affected_systems = ", ".join(incident.get("affected_systems", [])) or "Unknown"
    related_ips      = ", ".join(incident.get("related_ips", []))      or "Unknown"

    return f"""You are a senior banking SOC analyst with expertise in PCI-DSS and RBI cyber security regulations.

INCIDENT DETAILS:
  Title:            {incident.get("title", "Unknown Incident")}
  Severity:         {incident.get("severity", "HIGH")}
  Status:           {incident.get("status", "OPEN")}
  Threat Category:  {threat_category.get("category", "unknown")} (confidence: {threat_category.get("confidence", 0):.0%})
  Affected Systems: {affected_systems}
  Related IPs:      {related_ips}
  Event Count:      {incident.get("event_count", 0)}

ATTACK CHAIN:
{attack_chain}

MITRE ATT&CK TECHNIQUES DETECTED:
{mitre_lines}

RELEVANT BANKING THREAT INTELLIGENCE:
{banking_lines}

Generate a detailed, step-by-step incident response playbook for this specific incident.
Structure your response with these sections:
1. IMMEDIATE CONTAINMENT (actions to take in the next 15 minutes)
2. EVIDENCE COLLECTION (forensic preservation steps)
3. ERADICATION (removing the threat)
4. RECOVERY (restoring systems to normal operation)
5. COMMUNICATION PLAN (who to notify and when)
6. POST-INCIDENT (lessons learned, hardening measures)

Follow PCI-DSS requirements and RBI Cyber Security Framework guidelines.
Be specific and actionable. Use numbered sub-steps within each section.
"""


def playbook_node(state: AgentState) -> AgentState:
    """Generate an IR playbook using Ollama (or fallback)."""
    try:
        incident        = state.get("incident", {})
        threat_category = state.get("threat_category", {})
        enriched_data   = state.get("enriched_data", {})

        prompt  = _build_prompt(incident, threat_category, enriched_data)
        playbook = ollama_connector.generate(prompt)

        logger.info(
            "[IRAgent:playbook] Generated playbook (%d chars) for incident %s",
            len(playbook), incident.get("incident_id"),
        )
        return {**state, "playbook": playbook, "status": "awaiting_analyst"}
    except Exception as exc:
        logger.error("[IRAgent:playbook] Error: %s", exc)
        return {**state, "playbook": FALLBACK_PLAYBOOK, "status": "awaiting_analyst", "error": str(exc)}


def review_node(state: AgentState) -> AgentState:
    """
    Finalise the incident:
      - Set status to PENDING_ANALYST
      - Update Elasticsearch
      - Emit Socket.IO event "playbook_ready"
    """
    try:
        incident   = state.get("incident", {})
        playbook   = state.get("playbook", FALLBACK_PLAYBOOK)
        inc_id     = incident.get("incident_id", "unknown")

        # ── Update ES ──────────────────────────────────────────────────────────
        try:
            from storage.es_client import es_client, INDEX_INCIDENTS  # type: ignore
            if es_client.is_connected:
                updated_doc = dict(incident)
                updated_doc["status"]     = "PENDING_ANALYST"
                updated_doc["playbook"]   = playbook
                updated_doc["updated_at"] = datetime.utcnow().isoformat() + "Z"
                es_client.index_incident(updated_doc)
                logger.info("[IRAgent:review] Updated incident %s in ES.", inc_id)
        except Exception as es_exc:
            logger.warning("[IRAgent:review] ES update failed: %s", es_exc)

        # ── Emit Socket.IO event ───────────────────────────────────────────────
        try:
            from app import socketio  # type: ignore
            preview = (playbook[:300] + "...") if len(playbook) > 300 else playbook
            socketio.emit("playbook_ready", {
                "incident_id":      inc_id,
                "severity":         incident.get("severity"),
                "threat_category":  state.get("threat_category", {}).get("category"),
                "playbook_preview": preview,
            })
            logger.info("[IRAgent:review] Emitted 'playbook_ready' for incident %s.", inc_id)
        except Exception as sio_exc:
            logger.debug("[IRAgent:review] Socket.IO emit skipped: %s", sio_exc)

        return {**state, "status": "complete"}

    except Exception as exc:
        logger.error("[IRAgent:review] Error: %s", exc)
        return {**state, "status": "complete", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Conditional edge — CRITICAL → containment_node first
# ─────────────────────────────────────────────────────────────────────────────

def _should_contain(state: AgentState) -> str:
    """Router after enrich_node.

    Returns "containment" if auto-containment is enabled and severity is
    CRITICAL, else "playbook" to skip containment.
    """
    try:
        from config import config  # type: ignore
        auto_enabled = getattr(config, "AUTO_CONTAINMENT_ENABLED", False)
        severity     = state.get("incident", {}).get("severity", "LOW")
        if auto_enabled and severity == "CRITICAL":
            return "containment"
    except Exception:
        pass
    return "playbook"


# ─────────────────────────────────────────────────────────────────────────────
# Graph factory
# ─────────────────────────────────────────────────────────────────────────────

def build_ir_graph(checkpointer=None):
    """Build and compile the IR LangGraph StateGraph.

    Args:
        checkpointer: Optional LangGraph checkpointer instance.
                      Defaults to SqliteSaver at data/agent_checkpoints.db.

    Returns:
        A compiled LangGraph app, or None if LangGraph is not installed.
    """
    if not _LANGGRAPH_AVAILABLE:
        logger.warning("[IRAgent] LangGraph unavailable — returning None.")
        return None

    graph = StateGraph(AgentState)

    # Register nodes
    graph.add_node("ingest_node",      ingest_node)
    graph.add_node("classify_node",    classify_node)
    graph.add_node("enrich_node",      enrich_node)
    graph.add_node("containment_node", containment_node)
    graph.add_node("playbook_node",    playbook_node)
    graph.add_node("review_node",      review_node)

    # Edges — main path
    graph.add_edge(START,             "ingest_node")
    graph.add_edge("ingest_node",     "classify_node")
    graph.add_edge("classify_node",   "enrich_node")

    # Conditional edge after enrich_node
    graph.add_conditional_edges(
        "enrich_node",
        _should_contain,
        {
            "containment": "containment_node",
            "playbook":    "playbook_node",
        },
    )

    graph.add_edge("containment_node", "playbook_node")
    graph.add_edge("playbook_node",    "review_node")
    graph.add_edge("review_node",      END)

    # Compile with checkpointer
    if checkpointer is None:
        try:
            os.makedirs(os.path.dirname(_CHECKPOINT_DB), exist_ok=True)
            # langgraph-checkpoint-sqlite 3.x API: pass a sqlite3.Connection
            conn = sqlite3.connect(_CHECKPOINT_DB, check_same_thread=False)
            checkpointer = SqliteSaver(conn)
            logger.info("[IRAgent] Using SQLite checkpointer at %s", _CHECKPOINT_DB)
        except Exception as exc:
            logger.warning("[IRAgent] Could not create SQLite checkpointer: %s — running without.", exc)
            checkpointer = None

    return graph.compile(checkpointer=checkpointer)


def run_ir_agent(incident_dict: dict, thread_id: str = None) -> dict:
    """Run the full IR agent graph for a given incident dict.

    Args:
        incident_dict: Serialized Incident (from ``Incident.to_dict()``).
        thread_id:     LangGraph thread ID for checkpointing.
                       Defaults to the incident_id.

    Returns:
        Final AgentState dict, or a stub dict if LangGraph is unavailable.
    """
    if not _LANGGRAPH_AVAILABLE:
        # Stub execution — still generates a playbook via Ollama/fallback
        logger.warning("[IRAgent] Running in stub mode (no graph).")
        playbook = ollama_connector.generate(
            f"Generate incident response playbook for: {incident_dict.get('title', 'Unknown')}"
        )
        return {
            "incident":        incident_dict,
            "threat_category": threat_classifier.classify(incident_dict).__dict__,
            "enriched_data":   {},
            "playbook":        playbook,
            "status":          "complete",
            "error":           "LangGraph not installed",
        }

    graph = build_ir_graph()
    if graph is None:
        return {"status": "error", "error": "Graph build failed", "incident": incident_dict}

    _thread_id = thread_id or incident_dict.get("incident_id", "default")
    config_run = {"configurable": {"thread_id": _thread_id}}

    initial_state: AgentState = {
        "incident":        incident_dict,
        "threat_category": {},
        "enriched_data":   {},
        "playbook":        "",
        "status":          "starting",
        "error":           None,
    }

    try:
        final_state = graph.invoke(initial_state, config=config_run)
        return dict(final_state)
    except Exception as exc:
        logger.error("[IRAgent] Graph execution error: %s", exc)
        return {
            "incident":  incident_dict,
            "playbook":  FALLBACK_PLAYBOOK,
            "status":    "error",
            "error":     str(exc),
        }
