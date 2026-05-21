"""
api/ingest_routes.py
────────────────────────────────────────────────────────────────────────────────
Flask Blueprint — universal log ingestion endpoints (Phase 1).

Registers four new routes under /api/ingest/* that accept events from
external security sources (SIEM, EDR, Auth, unstructured logs) and:
  1. Normalise them into a canonical LogEvent.
  2. Index them into Elasticsearch (silently skipped if ES is unavailable).
  3. Return a standard JSON response.

These routes are SEPARATE from the existing /api/ingest route in api/ingest.py
(which handles web-traffic telemetry from the reverse-proxy SDK).

Blueprint variable: log_ingest_bp
Registration in app.py:
    from api.ingest_routes import log_ingest_bp
    app.register_blueprint(log_ingest_bp)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from ingestion.auth_ingestor import AuthIngestor
from ingestion.edr_ingestor import EdrIngestor
from ingestion.schema import LogEvent
from ingestion.siem_ingestor import SiemIngestor
from ingestion.unstructured_parser import UnstructuredParser
from storage.es_client import es_client

# Phase 3 — correlation & fidelity
from detection.fidelity_ranker import fidelity_ranker
from correlation.correlation_engine import correlation_engine

logger = logging.getLogger(__name__)

# Blueprint — named log_ingest_bp to avoid collision with existing ingest_bp
log_ingest_bp = Blueprint("log_ingest", __name__, url_prefix="/api/ingest")

# ── Ingestor singletons ───────────────────────────────────────────────────────
_siem_ingestor   = SiemIngestor()
_edr_ingestor    = EdrIngestor()
_auth_ingestor   = AuthIngestor()
_unstructured    = UnstructuredParser()


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _process_events(
    raw_items: List[Any],
    ingestor,
) -> List[Dict[str, Any]]:
    """Normalise, index, score, and (Phase 3) correlate a list of raw items.

    Args:
        raw_items: List of dicts / strings / any supported format.
        ingestor:  An ingestor instance with an ``ingest(raw)`` method.

    Returns:
        List of result dicts, one per item.
    """
    results: List[Dict[str, Any]] = []
    for item in raw_items:
        try:
            event: LogEvent = ingestor.ingest(item)

            # ── Phase 1: index to Elasticsearch ──────────────────────────────
            es_ok = es_client.index_event(event)

            # ── Phase 2: fidelity ranking ─────────────────────────────────────
            fidelity = None
            incident_id = None
            try:
                fidelity = fidelity_ranker.rank({
                    "rule":             0.0,   # rule score not available here
                    "ml_random_forest": 0.5,   # neutral default for external events
                    "pyod":             0.5,
                    "ueba":             0.3,
                    "timeseries":       0.0,
                })
                # Override with event-specific signals if available
                event_type_lower = (event.event_type or "").lower()
                if any(k in event_type_lower for k in
                       ("sql", "xss", "injection", "brute", "exploit",
                        "traversal", "honeypot")):
                    fidelity = fidelity_ranker.rank({
                        "rule":             0.8,
                        "ml_random_forest": 0.7,
                        "pyod":             0.6,
                        "ueba":             0.5,
                        "timeseries":       0.3,
                    })
            except Exception as exc:
                logger.debug("[IngestRoutes] Fidelity ranking skipped: %s", exc)

            # ── Phase 3: incident correlation ─────────────────────────────────
            if fidelity and fidelity.tier in ("HIGH", "CRITICAL"):
                try:
                    incident = correlation_engine.correlate(event, fidelity)
                    if incident:
                        incident_id = incident.incident_id
                        # Emit via Socket.IO if available
                        try:
                            from app import socketio
                            socketio.emit("incident_update", incident.to_dict())
                        except Exception:
                            pass  # Socket.IO unavailable — non-fatal
                except Exception as exc:
                    logger.warning("[IngestRoutes] Correlation skipped: %s", exc)

            results.append({
                "status":        "ok",
                "event_id":      event.event_id,
                "source_system": event.source_system,
                "event_type":    event.event_type,
                "source_ip":     event.source_ip,
                "confidence":    round(fidelity.combined_score, 4) if fidelity else None,
                "fidelity_tier": fidelity.tier if fidelity else None,
                "incident_id":   incident_id,
                "es_indexed":    es_ok,
            })
        except Exception as exc:
            logger.error("[IngestRoutes] Failed to process event: %s", exc)
            results.append({
                "status":      "error",
                "error":       str(exc),
                "event_id":    None,
                "confidence":  None,
                "incident_id": None,
            })
    return results


def _parse_body_as_list() -> List[Any]:
    """Parse request body as a list (handles single obj or JSON array)."""
    body = request.get_json(silent=True, force=True)
    if body is None:
        # Try plain-text fallback (unstructured log lines)
        body = request.get_data(as_text=True) or ""
    if isinstance(body, list):
        return body
    if body:
        return [body]
    return []


def _make_response(results: List[Dict[str, Any]]):
    """Return a uniform JSON response."""
    if not results:
        return jsonify({"status": "error", "error": "Empty request body"}), 400

    if len(results) == 1:
        payload = results[0]
        status_code = 200 if payload.get("status") == "ok" else 500
        return jsonify(payload), status_code

    ok_count = sum(1 for r in results if r.get("status") == "ok")
    return jsonify({
        "status": "ok",
        "total": len(results),
        "ok_count": ok_count,
        "error_count": len(results) - ok_count,
        "events": results,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@log_ingest_bp.route("/siem", methods=["POST"])
@jwt_required()
def ingest_siem():
    """POST /api/ingest/siem

    Accepts a JSON object or array of SIEM events in any supported format
    (dict, CEF string, Syslog string, or free text).

    Requires: Authorization: Bearer <jwt_token>

    Response (single event)::

        {
            "status": "ok",
            "event_id": "<uuid>",
            "source_system": "siem",
            "event_type": "<type>",
            "source_ip": "<ip>",
            "confidence": null,
            "es_indexed": true
        }
    """
    items = _parse_body_as_list()
    results = _process_events(items, _siem_ingestor)
    return _make_response(results)


@log_ingest_bp.route("/edr", methods=["POST"])
@jwt_required()
def ingest_edr():
    """POST /api/ingest/edr

    Accepts a JSON object or array of EDR telemetry events.

    Requires: Authorization: Bearer <jwt_token>
    """
    items = _parse_body_as_list()
    results = _process_events(items, _edr_ingestor)
    return _make_response(results)


@log_ingest_bp.route("/auth", methods=["POST"])
@jwt_required()
def ingest_auth():
    """POST /api/ingest/auth

    Accepts a JSON object or array of authentication events (login, logout,
    MFA failures, account lockouts, etc.).

    Requires: Authorization: Bearer <jwt_token>
    """
    items = _parse_body_as_list()
    results = _process_events(items, _auth_ingestor)
    return _make_response(results)


@log_ingest_bp.route("/logs", methods=["POST"])
@jwt_required()
def ingest_logs():
    """POST /api/ingest/logs

    Accepts raw / unstructured log lines (plain text, JSON object/array,
    or any mixed format).  IPs are extracted via regex; full text is preserved
    in raw_data.

    Requires: Authorization: Bearer <jwt_token>
    """
    items = _parse_body_as_list()
    results = _process_events(items, _unstructured)
    return _make_response(results)
