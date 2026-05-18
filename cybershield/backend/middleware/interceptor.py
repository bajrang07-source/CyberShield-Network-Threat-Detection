"""
Before-request interceptor — refactored to use threat_service.
The interceptor is now a thin transport adapter that feeds native
Flask traffic into the central ThreatService pipeline.
All detection logic lives in services/threat_service.py.
"""
import logging
import uuid
from datetime import datetime

from flask import request, g, abort, jsonify

logger = logging.getLogger(__name__)


def _get_client_ip() -> str:
    """Resolve real client IP, X-Forwarded-For aware."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _build_payload() -> dict:
    """Safely extract request payload as dict."""
    try:
        if request.is_json:
            return request.get_json(silent=True) or {}
        if request.form:
            return dict(request.form)
        if request.data:
            return {"raw": request.data.decode("utf-8", errors="replace")[:1000]}
        return dict(request.args)
    except Exception:
        return {}


def before_request_hook():
    """
    Main interceptor — registered as @app.before_request.
    Now a thin adapter: extracts request data and delegates
    all detection to services.threat_service.analyze_request().
    """
    from app import redis_client
    from models.db import WhitelistedIP
    from services.threat_service import analyze_request

    path = request.path

    # ── Skip auth, socket.io, and ingest paths ─────────────────────────────────
    SKIP_PREFIXES = ("/api/auth/", "/socket.io/", "/api/ingest")
    if any(path.startswith(p) for p in SKIP_PREFIXES):
        return None

    ip = _get_client_ip()

    # ── Redis block check ──────────────────────────────────────────────────────
    try:
        if redis_client.exists(f"cybershield:blocked:{ip}"):
            return jsonify({"error": "Access denied", "code": "BLOCKED"}), 403
    except Exception:
        pass

    # ── Whitelist check ────────────────────────────────────────────────────────
    try:
        if WhitelistedIP.query.filter_by(ip_address=ip).first():
            logger.debug("[Interceptor] Whitelisted IP: %s — pass through", ip)
            return None
    except Exception:
        pass

    # ── Delegate to threat service ─────────────────────────────────────────────
    method = request.method
    user_agent = request.headers.get("User-Agent", "")
    session_id = request.cookies.get("session", str(uuid.uuid4())[:16])
    payload = _build_payload()

    try:
        result = analyze_request(
            ip=ip,
            method=method,
            path=path,
            user_agent=user_agent,
            payload=payload,
            headers=dict(request.headers),
            session_id=session_id,
            timestamp=datetime.utcnow(),
            site_id=None,           # native traffic has no site_id
            redis_client=redis_client,
        )
        g.threat_result = result

        # Block critical threats
        if result.action == "block":
            abort(403, description='{"error": "Access denied", "code": "BLOCKED"}')

    except Exception as exc:
        logger.error("[Interceptor] ThreatService error: %s", exc)

    return None
