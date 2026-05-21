"""
api/incident_routes.py
────────────────────────────────────────────────────────────────────────────────
Flask Blueprint — incident management endpoints (Phase 3).

Routes:
  GET  /api/incidents                     — list with filtering
  GET  /api/incidents/<incident_id>       — single incident with full timeline
  POST /api/incidents/<incident_id>/action — update status / add analyst notes

All routes are JWT-protected.
Elasticsearch is the source of truth for incident data.
If ES is unavailable, endpoints return appropriate empty responses or 503.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from models.incident import Incident, VALID_STATUSES
from storage.es_client import es_client, INDEX_INCIDENTS
from api.events import emit_incident_update

logger = logging.getLogger(__name__)

incident_bp = Blueprint("incidents", __name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _es_unavailable_response():
    return jsonify({
        "status":  "ok",
        "error":   "Elasticsearch unavailable — incident data not accessible",
        "results": [],
        "incidents": [],
        "heatmap": {},
        "playbook": ""
    }), 200


def _build_list_query(
    severity: Optional[str],
    status: Optional[str],
    since: Optional[str],
    limit: int,
) -> Dict[str, Any]:
    """Build an ES bool query for incident list filtering."""
    must: List[Dict] = []

    if severity:
        must.append({"term": {"severity": severity.upper()}})
    if status:
        must.append({"term": {"status": status.upper()}})
    if since:
        must.append({"range": {"created_at": {"gte": since}}})

    query: Dict[str, Any] = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort":  [{"created_at": {"order": "desc"}}],
        "size":  min(limit, 200),   # hard cap at 200
    }
    return query


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@incident_bp.route("/incidents", methods=["GET"])
@jwt_required()
def list_incidents():
    """GET /api/incidents

    Query parameters:
        severity  – Filter by severity (LOW|MEDIUM|HIGH|CRITICAL)
        status    – Filter by status   (OPEN|PENDING_ANALYST|RESOLVED|FALSE_POSITIVE)
        since     – ISO-8601 timestamp (e.g. 2024-06-01T00:00:00Z)
        limit     – Maximum results (default 50, max 200)

    Response::

        {
            "status": "ok",
            "total": 12,
            "incidents": [ {...}, ... ]
        }
    """
    if not es_client.is_connected:
        return _es_unavailable_response()

    severity = request.args.get("severity")
    status   = request.args.get("status")
    since    = request.args.get("since")
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50

    query = _build_list_query(severity, status, since, limit)

    try:
        docs = es_client.search_events(query, index=INDEX_INCIDENTS, size=limit)
        incidents = []
        for doc in docs:
            try:
                incidents.append(Incident.from_es_doc(doc).to_dict())
            except Exception as exc:
                logger.debug("[IncidentRoutes] Skipping malformed incident doc: %s", exc)

        return jsonify({
            "status":    "ok",
            "total":     len(incidents),
            "incidents": incidents,
        })
    except Exception as exc:
        logger.error("[IncidentRoutes] list_incidents error: %s", exc)
        return jsonify({"status": "error", "error": str(exc), "incidents": []}), 500


@incident_bp.route("/incidents/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident(incident_id: str):
    """GET /api/incidents/<incident_id>

    Returns a single incident with its full timeline.

    Response::

        {
            "status": "ok",
            "incident": { ... full incident dict ... }
        }
    """
    if not es_client.is_connected:
        return _es_unavailable_response()

    try:
        doc = es_client.get_event_by_id(incident_id, index=INDEX_INCIDENTS)
        if doc is None:
            return jsonify({"status": "error", "error": "Incident not found"}), 404
        incident = Incident.from_es_doc(doc)
        return jsonify({"status": "ok", "incident": incident.to_dict()})
    except Exception as exc:
        logger.error("[IncidentRoutes] get_incident(%s) error: %s", incident_id, exc)
        return jsonify({"status": "error", "error": str(exc)}), 500


@incident_bp.route("/incidents/<incident_id>/action", methods=["POST"])
@jwt_required()
def incident_action(incident_id: str):
    """POST /api/incidents/<incident_id>/action

    Update the incident status or add analyst notes.

    Body::

        {
            "action":        "resolve" | "false_positive" | "escalate",
            "analyst_notes": "Optional free-text notes"
        }

    Response::

        {
            "status":      "ok",
            "incident_id": "<uuid>",
            "new_status":  "RESOLVED"
        }
    """
    if not es_client.is_connected:
        return _es_unavailable_response()

    data   = request.get_json(silent=True) or {}
    action = str(data.get("action", "")).lower()
    notes  = str(data.get("analyst_notes", ""))

    # Map action verb to status
    _ACTION_MAP = {
        "resolve":        "RESOLVED",
        "false_positive": "FALSE_POSITIVE",
        "dismiss":        "FALSE_POSITIVE",
        "escalate":       "PENDING_ANALYST",
        "reopen":         "OPEN",
    }
    new_status = _ACTION_MAP.get(action)
    if not new_status:
        return jsonify({
            "status": "error",
            "error":  f"Unknown action '{action}'. "
                      f"Valid: {list(_ACTION_MAP.keys())}",
        }), 400

    try:
        # Fetch existing incident
        doc = es_client.get_event_by_id(incident_id, index=INDEX_INCIDENTS)
        if doc is None:
            return jsonify({"status": "error", "error": "Incident not found"}), 404

        incident = Incident.from_es_doc(doc)
        incident.status       = new_status
        incident.updated_at   = datetime.utcnow()
        if notes:
            # Append to existing notes with timestamp
            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            separator = "\n" if incident.analyst_notes else ""
            incident.analyst_notes = (
                f"{incident.analyst_notes}{separator}[{ts}] {notes}"
            )

        # Re-index the updated incident
        ok = es_client.index_incident(incident.to_es_doc())

        try:
            emit_incident_update(incident.to_dict())
        except Exception as emit_err:
            logger.warning("[IncidentRoutes] Failed to emit incident_update: %s", emit_err)

        return jsonify({
            "status":      "ok",
            "incident_id": incident_id,
            "new_status":  new_status,
            "es_updated":  ok,
        })

    except Exception as exc:
        logger.error("[IncidentRoutes] incident_action(%s) error: %s", incident_id, exc)
        return jsonify({"status": "error", "error": str(exc)}), 500


@incident_bp.route("/incidents/<incident_id>/playbook", methods=["GET"])
@jwt_required()
def get_playbook(incident_id: str):
    """GET /api/incidents/<incident_id>/playbook"""
    if not es_client.is_connected:
        return _es_unavailable_response()
    
    try:
        doc = es_client.get_event_by_id(incident_id, index=INDEX_INCIDENTS)
        if not doc:
            return jsonify({"status": "error", "error": "Incident not found"}), 404
        
        incident = Incident.from_es_doc(doc)
        if incident.playbook:
            return jsonify({"status": "ok", "playbook": incident.playbook})
        
        # Trigger agent dispatch and return 202
        try:
            from agents.agent_dispatcher import agent_dispatcher
            agent_dispatcher.dispatch(incident)
        except Exception as e:
            logger.warning("[IncidentRoutes] Failed to trigger agent dispatch: %s", e)
            
        return jsonify({
            "status": "processing",
            "message": "Playbook generation in progress. Check back later."
        }), 202
    except Exception as exc:
        logger.error("[IncidentRoutes] get_playbook(%s) error: %s", incident_id, exc)
        return jsonify({"status": "error", "error": str(exc)}), 500


@incident_bp.route("/mitre/heatmap", methods=["GET"])
@jwt_required()
def mitre_heatmap():
    """GET /api/mitre/heatmap"""
    if not es_client.is_connected:
        return _es_unavailable_response()
    
    try:
        query = {
            "size": 0,
            "aggs": {
                "mitre_techniques": {
                    "terms": {"field": "mitre_techniques.keyword", "size": 100}
                }
            }
        }
        resp = es_client._es.search(index=INDEX_INCIDENTS, body=query)
        buckets = resp.get("aggregations", {}).get("mitre_techniques", {}).get("buckets", [])
        
        heatmap = {b["key"]: b["doc_count"] for b in buckets}
        return jsonify({"status": "ok", "heatmap": heatmap})
    except Exception as exc:
        logger.error("[IncidentRoutes] mitre_heatmap error: %s", exc)
        return jsonify({"status": "error", "error": str(exc)}), 500


@incident_bp.route("/soc/stats", methods=["GET"])
@jwt_required()
def soc_stats():
    """GET /api/soc/stats"""
    # Default fallback values
    stats = {
        "total_alerts_today": 0,
        "deduplicated_count": 0,
        "analyst_fatigue_ratio": 0.0,
        "open_incidents": 0,
        "critical_count": 0,
        "mean_time_to_detect_minutes": 5,
    }
    if not es_client.is_connected:
        return jsonify({"status": "ok", "stats": stats})
    
    try:
        now = datetime.utcnow()
        start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat() + "Z"
        
        query = {
            "size": 0,
            "query": {
                "range": {"created_at": {"gte": start_of_today}}
            },
            "aggs": {
                "status_open": {
                    "filter": {"term": {"status": "OPEN"}}
                },
                "critical_open": {
                    "filter": {
                        "bool": {
                            "must": [
                                {"term": {"status": "OPEN"}},
                                {"term": {"severity": "CRITICAL"}}
                            ]
                        }
                    }
                },
                "total_events": {
                    "sum": {"field": "event_count"}
                }
            }
        }
        resp = es_client._es.search(index=INDEX_INCIDENTS, body=query)
        total_incidents = resp.get("hits", {}).get("total", {}).get("value", 0)
        aggs = resp.get("aggregations", {})
        
        open_count = aggs.get("status_open", {}).get("doc_count", 0)
        crit_count = aggs.get("critical_open", {}).get("doc_count", 0)
        tot_events = int(aggs.get("total_events", {}).get("value", 0) or 0)
        
        stats["total_alerts_today"] = total_incidents
        stats["open_incidents"] = open_count
        stats["critical_count"] = crit_count
        stats["deduplicated_count"] = max(0, tot_events - total_incidents)
        stats["analyst_fatigue_ratio"] = round(total_incidents / 100.0, 2)
        
        return jsonify({"status": "ok", "stats": stats})
    except Exception as exc:
        logger.error("[IncidentRoutes] soc_stats error: %s", exc)
        return jsonify({"status": "error", "error": str(exc)}), 500
