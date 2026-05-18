"""
CyberShield WSGI Middleware
============================
PEP 3333-compliant WSGI wrapper that inspects every request
through the CyberShield threat pipeline before forwarding to the app.

Compatible with any WSGI framework: Flask, Django, Falcon, Bottle,
Pyramid, Starlette (sync), etc.

Usage (wrapping any WSGI app):

    from cybershield_wsgi import CyberShieldWSGI

    # Wrap your existing WSGI app
    application = CyberShieldWSGI(
        app=your_wsgi_app,
        api_key='cs_live_your_key_here',
        endpoint='http://localhost:5000',
        mode='block',    # 'block' or 'monitor'
    )

    # For gunicorn: gunicorn mymodule:application
    # For uWSGI:    uwsgi --module mymodule:application

Flask example:
    from flask import Flask
    from cybershield_wsgi import CyberShieldWSGI

    flask_app = Flask(__name__)
    application = CyberShieldWSGI(flask_app, api_key='cs_live_...')
"""
import io
import json
import logging
import time
from urllib.parse import parse_qs, urlparse, urlencode

logger = logging.getLogger("cybershield.wsgi")

try:
    import requests as http_requests
    _requests_available = True
except ImportError:
    _requests_available = False
    logger.warning("[CyberShieldWSGI] 'requests' not installed.")

_BLOCKED_BODY = json.dumps({
    "error":    "Access denied by CyberShield",
    "code":     "BLOCKED",
}).encode("utf-8")


class CyberShieldWSGI:
    """
    WSGI middleware that intercepts every request, analyses it via
    CyberShield's ingest API, and optionally blocks malicious traffic.
    """

    def __init__(self, app, api_key: str, endpoint: str = "http://localhost:5000",
                 mode: str = "block"):
        self.app      = app
        self.api_key  = api_key
        self.endpoint = endpoint.rstrip("/")
        self.mode     = mode
        self.enabled  = bool(api_key and _requests_available)

        logger.info("[CyberShieldWSGI] Protection %s (mode=%s)",
                    "ACTIVE" if self.enabled else "DISABLED", mode)

    def __call__(self, environ, start_response):
        if not self.enabled:
            return self.app(environ, start_response)

        # ── Extract request metadata ──────────────────────────────────────────
        ip     = self._get_ip(environ)
        method = environ.get("REQUEST_METHOD", "GET")
        path   = environ.get("PATH_INFO", "/")
        qs     = environ.get("QUERY_STRING", "")
        full_path = path + (f"?{qs}" if qs else "")
        ua     = environ.get("HTTP_USER_AGENT", "")

        # ── Read body (must be put back for the downstream app) ───────────────
        content_length = int(environ.get("CONTENT_LENGTH") or 0)
        body_bytes = b""
        if content_length > 0:
            try:
                body_bytes = environ["wsgi.input"].read(content_length)
            except Exception:
                pass
        # Replace wsgi.input so downstream app can still read it
        environ["wsgi.input"] = io.BytesIO(body_bytes)

        # ── Extract payload ───────────────────────────────────────────────────
        payload = {}
        try:
            ct = environ.get("CONTENT_TYPE", "")
            if "application/json" in ct and body_bytes:
                payload = json.loads(body_bytes.decode("utf-8", errors="replace"))
            elif "application/x-www-form-urlencoded" in ct and body_bytes:
                payload = {k: v[0] for k, v in parse_qs(body_bytes.decode()).items()}
            if qs:
                payload.update({k: v[0] for k, v in parse_qs(qs).items()})
        except Exception:
            pass

        # ── Headers ───────────────────────────────────────────────────────────
        headers = {
            k[5:].replace("_", "-").title(): v
            for k, v in environ.items()
            if k.startswith("HTTP_")
        }

        # ── Analyse ───────────────────────────────────────────────────────────
        result = self._analyse(ip, method, full_path, ua, payload, headers)
        action = result.get("action", "allow")

        # ── Block if needed ───────────────────────────────────────────────────
        if action == "block" and self.mode == "block":
            start_response("403 Forbidden", [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(_BLOCKED_BODY))),
                ("X-CyberShield-Action", "block"),
                ("X-CyberShield-Risk", str(round(result.get("risk_score", 0), 2))),
            ])
            return [_BLOCKED_BODY]

        # ── Forward to app ────────────────────────────────────────────────────
        def _start_response_with_headers(status, response_headers, exc_info=None):
            response_headers.append(("X-CyberShield-Risk", str(round(result.get("risk_score", 0), 2))))
            response_headers.append(("X-CyberShield-Action", action))
            return start_response(status, response_headers, exc_info)

        return self.app(environ, _start_response_with_headers)

    def _get_ip(self, environ):
        xff = environ.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            return xff.split(",")[0].strip()
        return environ.get("REMOTE_ADDR", "127.0.0.1")

    def _analyse(self, ip, method, path, ua, payload, headers):
        try:
            resp = http_requests.post(
                f"{self.endpoint}/api/ingest",
                json={"ip": ip, "method": method, "path": path,
                      "user_agent": ua, "payload": payload, "headers": headers},
                headers={"X-CS-API-Key": self.api_key},
                timeout=3,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            logger.warning("[CyberShieldWSGI] Analysis failed: %s", exc)
        return {"action": "allow", "risk_score": 0}
