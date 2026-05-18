"""
CyberShield Universal — Reverse Proxy Mode.

Architecture:
    Client → CyberShield (threat analysis) → Origin Server

Usage (standalone Flask app):
    from middleware.proxy import ProxyAnalysisMiddleware
    proxy_app = ProxyAnalysisMiddleware(
        target_origin="https://myapp.com",
        api_key="cs_live_..."
    )
    socketio.run(proxy_app, host="0.0.0.0", port=8080)

Usage in existing app:
    Add route: POST /api/proxy/forward
    Set X-Origin-Host header from client or config.
"""
import logging
import io
from urllib.parse import urlparse, urljoin

import requests as http_requests
from flask import Blueprint, request, Response, jsonify, g
from middleware.auth_middleware import require_site_key

logger = logging.getLogger(__name__)

proxy_bp = Blueprint("proxy", __name__, url_prefix="/proxy")

# Headers that should not be forwarded to origin
HOP_BY_HOP_HEADERS = frozenset([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "x-cs-api-key",          # strip our auth key
    "x-origin-host",         # strip routing header
    "host",                  # will be rewritten
])


def _get_origin(fallback: str = "") -> str:
    """Resolve target origin from X-Origin-Host header or fallback."""
    return request.headers.get("X-Origin-Host", fallback).rstrip("/")


def _filter_headers(headers: dict) -> dict:
    """Remove hop-by-hop and CyberShield-specific headers."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}


@proxy_bp.route("/<path:target_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@require_site_key
def forward(target_path: str):
    """
    Analyze the incoming request, then if safe, forward to origin.

    Request flow:
      1. Authenticate via X-CS-API-Key
      2. Analyze request through threat_service
      3. If action == 'block' → return 403, do NOT forward
      4. If safe → forward to origin server and proxy response back

    Required header: X-Origin-Host: https://myapp.com
    """
    from app import redis_client
    from services.threat_service import analyze_request

    origin = _get_origin()
    if not origin:
        return jsonify({"error": "X-Origin-Host header is required for proxy mode"}), 400

    # ── Validate origin scheme ───────────────────────────────────────────────
    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "Invalid origin scheme. Use http or https."}), 400

    site_id = g.site_id

    # ── Read body ─────────────────────────────────────────────────────────────
    body = request.get_data()
    payload = {}
    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
        elif body:
            payload = {"raw": body.decode("utf-8", errors="replace")[:500]}
    except Exception:
        pass

    # ── Threat analysis ───────────────────────────────────────────────────────
    result = analyze_request(
        ip=request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip(),
        method=request.method,
        path=f"/{target_path}" + (f"?{request.query_string.decode()}" if request.query_string else ""),
        user_agent=request.headers.get("User-Agent", ""),
        payload=payload,
        headers=dict(request.headers),
        session_id=request.cookies.get("session", ""),
        site_id=site_id,
        redis_client=redis_client,
    )

    # ── Block if needed ───────────────────────────────────────────────────────
    if result.action == "block":
        logger.warning("[ProxyMiddleware] Blocked %s → %s/%s (risk=%.1f, type=%s)",
                       result.ip, origin, target_path, result.risk_score, result.attack_type)
        return jsonify({
            "error": "Request blocked by CyberShield",
            "attack_type": result.attack_type,
            "risk_score": round(result.risk_score, 2),
            "severity": result.severity,
        }), 403

    # ── Forward to origin ─────────────────────────────────────────────────────
    target_url = urljoin(origin + "/", target_path)
    if request.query_string:
        target_url += f"?{request.query_string.decode()}"

    forward_headers = _filter_headers(dict(request.headers))
    forward_headers["Host"] = parsed.netloc
    forward_headers["X-Forwarded-For"] = result.ip
    forward_headers["X-CyberShield-Risk"] = str(round(result.risk_score, 2))
    forward_headers["X-CyberShield-Action"] = result.action

    try:
        origin_resp = http_requests.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=body,
            allow_redirects=False,
            timeout=15,
            stream=True,
        )
    except http_requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach origin: {origin}"}), 502
    except http_requests.exceptions.Timeout:
        return jsonify({"error": "Origin server timeout"}), 504
    except Exception as exc:
        logger.error("[ProxyMiddleware] Forward error: %s", exc)
        return jsonify({"error": "Proxy error"}), 502

    # ── Stream response back to client ────────────────────────────────────────
    response_headers = _filter_headers(dict(origin_resp.headers))
    response_headers["X-CyberShield-Risk"] = str(round(result.risk_score, 2))
    response_headers["X-CyberShield-Action"] = result.action

    return Response(
        origin_resp.iter_content(chunk_size=8192),
        status=origin_resp.status_code,
        headers=response_headers,
        content_type=origin_resp.headers.get("Content-Type", "application/octet-stream"),
    )
