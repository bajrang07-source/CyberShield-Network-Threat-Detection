"""
CyberShield Universal — Ingest API Blueprint.
POST /api/ingest — accepts telemetry from any SDK or reverse proxy.
"""
import logging
from datetime import datetime

from flask import Blueprint, jsonify, request

from middleware.auth_middleware import require_site_key

logger = logging.getLogger(__name__)

ingest_bp = Blueprint("ingest", __name__, url_prefix="/api")


@ingest_bp.route("/ingest", methods=["POST"])
@require_site_key
def ingest():
    """
    Accept request telemetry from external sites.
    Requires X-CS-API-Key header.

    Body:
    {
        "ip": "1.2.3.4",
        "user_agent": "Mozilla/5.0...",
        "path": "/login",
        "method": "POST",
        "payload": {},
        "headers": {},
        "session_id": "abc123",
        "timestamp": "2024-01-01T00:00:00Z"   # optional
    }

    Response:
    {
        "risk_score": 82.5,
        "attack_type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "action": "block",
        "matched_pattern": "SQLI: ...",
        "ml_score": 0.91
    }
    """
    from app import redis_client
    from services.threat_service import analyze_request
    from flask import g

    data = request.get_json(silent=True) or {}

    # ── Extract fields ────────────────────────────────────────────────────────
    ip = data.get("ip", request.remote_addr or "0.0.0.0")
    user_agent = data.get("user_agent", "")
    path = data.get("path", "/")
    method = data.get("method", "GET").upper()
    payload = data.get("payload", {})
    headers = data.get("headers", {})
    session_id = data.get("session_id", "")

    # Parse optional timestamp
    timestamp = None
    ts_str = data.get("timestamp")
    if ts_str:
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            pass

    # site_id injected by @require_site_key via g.site_id
    site_id = g.site_id

    # ── Validate required fields ───────────────────────────────────────────────
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    # ── Run threat analysis ────────────────────────────────────────────────────
    try:
        result = analyze_request(
            ip=ip,
            method=method,
            path=path,
            user_agent=user_agent,
            payload=payload,
            headers=headers,
            session_id=session_id,
            timestamp=timestamp,
            site_id=site_id,
            redis_client=redis_client,
        )
    except Exception as exc:
        logger.error("[Ingest] Analysis error: %s", exc)
        return jsonify({"error": "Analysis failed", "detail": str(exc)}), 500

    return jsonify({
        "risk_score": round(result.risk_score, 2),
        "attack_type": result.attack_type,
        "severity": result.severity,
        "action": result.action,
        "matched_pattern": result.matched_pattern,
        "ml_score": round(result.ml_score, 4),
        "event_id": result.id,
    })
