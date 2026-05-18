"""
CyberShield Universal — Standalone Reverse Proxy Runner
=========================================================
Run this to start a local reverse proxy that intercepts all traffic
to your target application, analyses each request through the full
CyberShield detection pipeline, and forwards safe requests.

Architecture:
    Browser / curl / Burp / ZAP / Nikto / custom scripts
           │
           ▼  (this proxy port, e.g. 8080)
    CyberShield Proxy
           │  inspect + score every request
           ▼  (target app port, e.g. 4000)
    Protected Application (FitZone Gym, etc.)

Usage:
    python proxy_runner.py --target http://localhost:4000 --port 8080 --key cs_live_...
    python proxy_runner.py --target http://localhost:4000 --port 8080 --key cs_live_... --mode monitor

Arguments:
    --target   Target application URL (required)
    --port     Port for this proxy to listen on (default: 8080)
    --key      CyberShield site API key  (required)
    --mode     'block' = block threats, 'monitor' = log only (default: block)
    --backend  CyberShield backend URL (default: http://localhost:5000)

Then in your browser, visit http://localhost:8080 instead of http://localhost:4000.
The CyberShield dashboard at http://localhost:3000 will show all intercepted traffic.
"""
import argparse
import logging
import sys
import os
import time
from urllib.parse import urlparse, urljoin

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("cs-proxy")

try:
    import requests as http_requests
    from flask import Flask, request, Response, jsonify
    from flask_cors import CORS
except ImportError:
    logger.error("Missing dependencies. Run: pip install flask flask-cors requests")
    sys.exit(1)

# ── Hop-by-hop headers to strip ───────────────────────────────────────────────
HOP_BY_HOP = frozenset([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
])


def create_proxy_app(target_url: str, api_key: str, backend_url: str, mode: str) -> Flask:
    app   = Flask("CyberShieldProxy")
    CORS(app)

    parsed_target = urlparse(target_url)

    def _analyse(ip, method, path, ua, payload, headers):
        """Send request metadata to CyberShield backend for analysis."""
        try:
            resp = http_requests.post(
                f"{backend_url}/api/ingest",
                json={
                    "ip":         ip,
                    "method":     method,
                    "path":       path,
                    "user_agent": ua,
                    "payload":    payload,
                    "headers":    dict(headers),
                },
                headers={"X-CS-API-Key": api_key},
                timeout=3,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            logger.warning("[Proxy] Analysis failed: %s", exc)
        return {"action": "allow", "risk_score": 0}

    def _filter_headers(headers):
        return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}

    @app.route("/<path:target_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    @app.route("/", defaults={"target_path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    def proxy(target_path):
        ip  = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
        ua  = request.headers.get("User-Agent", "")
        path_with_qs = f"/{target_path}" + (f"?{request.query_string.decode()}" if request.query_string else "")

        # ── Extract payload ───────────────────────────────────────────────────
        body    = request.get_data()
        payload = {}
        try:
            if request.is_json:
                payload = request.get_json(silent=True) or {}
            elif request.form:
                payload = dict(request.form)
            elif body:
                payload = {"raw": body.decode("utf-8", errors="replace")[:500]}
            if request.args:
                payload.update(dict(request.args))
        except Exception:
            pass

        # ── Analyse ───────────────────────────────────────────────────────────
        t_start = time.time()
        result  = _analyse(ip, request.method, path_with_qs, ua, payload, request.headers)
        t_end   = time.time()

        risk   = result.get("risk_score", 0)
        action = result.get("action", "allow")
        atype  = result.get("attack_type", "")

        logger.info("[Proxy] %s %s → risk=%.1f action=%s%s",
                    request.method, path_with_qs, risk, action,
                    f" [{atype}]" if atype else "")

        # ── Block if needed ───────────────────────────────────────────────────
        if action == "block" and mode == "block":
            return jsonify({
                "error":       "Blocked by CyberShield",
                "attack_type": atype,
                "risk_score":  round(risk, 2),
                "severity":    result.get("severity", "CRITICAL"),
            }), 403

        # ── Forward to target ─────────────────────────────────────────────────
        target = urljoin(target_url.rstrip("/") + "/", target_path)
        if request.query_string:
            target += f"?{request.query_string.decode()}"

        fwd_headers = _filter_headers(dict(request.headers))
        fwd_headers["Host"]                  = parsed_target.netloc
        fwd_headers["X-Forwarded-For"]       = ip
        fwd_headers["X-CyberShield-Risk"]    = str(round(risk, 2))
        fwd_headers["X-CyberShield-Action"]  = action

        try:
            origin_resp = http_requests.request(
                method=request.method,
                url=target,
                headers=fwd_headers,
                data=body,
                allow_redirects=False,
                timeout=15,
                stream=True,
            )
        except http_requests.exceptions.ConnectionError:
            return jsonify({"error": f"Cannot reach target: {target_url}"}), 502
        except http_requests.exceptions.Timeout:
            return jsonify({"error": "Target server timeout"}), 504

        resp_headers = _filter_headers(dict(origin_resp.headers))
        resp_headers["X-CyberShield-Risk"]   = str(round(risk, 2))
        resp_headers["X-CyberShield-Action"] = action
        resp_headers["X-Response-Time-Ms"]   = str(round((t_end - t_start) * 1000, 1))

        return Response(
            origin_resp.iter_content(chunk_size=8192),
            status=origin_resp.status_code,
            headers=resp_headers,
            content_type=origin_resp.headers.get("Content-Type", "application/octet-stream"),
        )

    return app


def main():
    parser = argparse.ArgumentParser(description="CyberShield Reverse Proxy")
    parser.add_argument("--target",  required=True,              help="Target app URL (e.g. http://localhost:4000)")
    parser.add_argument("--port",    type=int, default=8080,     help="Proxy listen port (default: 8080)")
    parser.add_argument("--key",     required=True,              help="CyberShield site API key")
    parser.add_argument("--mode",    default="block",            help="'block' or 'monitor' (default: block)")
    parser.add_argument("--backend", default="http://localhost:5000", help="CyberShield backend URL")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  CyberShield Standalone Reverse Proxy")
    logger.info("  Proxy port   : %d", args.port)
    logger.info("  Target app   : %s", args.target)
    logger.info("  Backend      : %s", args.backend)
    logger.info("  Mode         : %s", args.mode)
    logger.info("  Dashboard    : http://localhost:3000")
    logger.info("=" * 60)
    logger.info("Browse to http://localhost:%d instead of %s", args.port, args.target)
    logger.info("All traffic will be intercepted and analyzed in real-time.")

    app = create_proxy_app(args.target, args.key, args.backend, args.mode)
    app.run(host="0.0.0.0", port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
