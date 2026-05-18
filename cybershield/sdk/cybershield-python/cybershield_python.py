"""
CyberShield Universal — Python SDK
Supports Flask, Django, FastAPI, and raw WSGI.

Usage (Flask):
    from cybershield_python import CyberShieldMiddleware
    app.wsgi_app = CyberShieldMiddleware(app.wsgi_app, api_key="cs_live_...", endpoint="http://localhost:5000")

Usage (Django — settings.py):
    MIDDLEWARE = ['cybershield_python.DjangoMiddleware', ...]
    CYBERSHIELD_API_KEY = "cs_live_..."
    CYBERSHIELD_ENDPOINT = "http://localhost:5000"

Usage (FastAPI):
    from cybershield_python import FastAPIMiddleware
    app.add_middleware(FastAPIMiddleware, api_key="cs_live_...")
"""

import hashlib
import json
import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlparse, parse_qs

import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "http://localhost:5000"
DEFAULT_TIMEOUT = 3.0
MAX_QUEUE = 200
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ─── Internal HTTP sender (stdlib only — no extra deps) ───────────────────────

class _Sender:
    def __init__(self, api_key: str, endpoint: str, timeout: float, max_queue: int):
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self._queue: deque = deque(maxlen=max_queue)
        self._lock = threading.Lock()
        self._start_drain_thread()

    def send(self, payload: dict, retries: int = 2) -> Optional[dict]:
        """Send payload synchronously. Returns result dict or None."""
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.endpoint}/api/ingest",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-CS-API-Key": self.api_key,
            },
            method="POST",
        )

        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                logger.warning("[CyberShield] HTTP %s on attempt %d", exc.code, attempt + 1)
                if attempt == retries:
                    break
            except Exception as exc:
                logger.warning("[CyberShield] Send error (attempt %d): %s", attempt + 1, exc)
                if attempt == retries:
                    break
                time.sleep(0.2 * (2 ** attempt))

        # Queue for later
        with self._lock:
            self._queue.append(payload)
        return None

    def _start_drain_thread(self):
        def _drain():
            while True:
                time.sleep(10)
                with self._lock:
                    items = list(self._queue)
                    self._queue.clear()
                for item in items:
                    try:
                        self.send(item, retries=1)
                    except Exception:
                        pass

        t = threading.Thread(target=_drain, daemon=True)
        t.start()


# ─── Shared helpers ───────────────────────────────────────────────────────────

def _extract_ip(environ: dict) -> str:
    forwarded = environ.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return environ.get("REMOTE_ADDR", "0.0.0.0")


def _build_payload_from_environ(environ: dict, body_bytes: bytes = b"") -> dict:
    path = environ.get("PATH_INFO", "/")
    query = environ.get("QUERY_STRING", "")
    full_path = f"{path}?{query}" if query else path
    method = environ.get("REQUEST_METHOD", "GET")
    user_agent = environ.get("HTTP_USER_AGENT", "")

    payload = {}
    content_type = environ.get("CONTENT_TYPE", "")
    if body_bytes:
        try:
            if "application/json" in content_type:
                payload = json.loads(body_bytes.decode("utf-8", errors="replace"))
            else:
                payload = {"raw": body_bytes.decode("utf-8", errors="replace")[:500]}
        except Exception:
            pass

    return {
        "ip": _extract_ip(environ),
        "user_agent": user_agent,
        "path": full_path,
        "method": method,
        "payload": payload,
        "headers": {},
        "session_id": environ.get("HTTP_X_SESSION_ID", ""),
        "timestamp": datetime.utcnow().isoformat(),
    }


# ─── WSGI Middleware (works with Flask, Django, any WSGI app) ─────────────────

class CyberShieldMiddleware:
    """
    Generic WSGI middleware. Wraps any WSGI application.

    Args:
        wsgi_app: The wrapped WSGI application.
        api_key:  CyberShield site API key.
        endpoint: CyberShield server URL.
        mode:     'block' or 'monitor'. In monitor mode, bad requests pass through.
        timeout:  HTTP request timeout in seconds.
    """

    BLOCK_RESPONSE = (
        b'{"error": "Access denied by CyberShield"}',
        "403 Forbidden",
        [("Content-Type", "application/json")],
    )

    def __init__(
        self,
        wsgi_app,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        mode: str = "block",
        timeout: float = DEFAULT_TIMEOUT,
    ):
        if not api_key:
            raise ValueError("[CyberShield] api_key is required")
        self.app = wsgi_app
        self.mode = mode
        self._sender = _Sender(api_key, endpoint, timeout, MAX_QUEUE)

    def __call__(self, environ, start_response):
        # Read body (need to buffer for inspection and then replay)
        body_bytes = b""
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if length > 0:
                body_bytes = environ["wsgi.input"].read(length)
                # Replay for downstream app
                import io
                environ["wsgi.input"] = io.BytesIO(body_bytes)
        except Exception:
            pass

        payload = _build_payload_from_environ(environ, body_bytes)

        result = self._sender.send(payload)

        if result and result.get("action") == "block" and self.mode == "block":
            body, status, headers = self.BLOCK_RESPONSE
            start_response(status, headers)
            return [body]

        return self.app(environ, start_response)


# ─── Django Middleware ────────────────────────────────────────────────────────

class DjangoMiddleware:
    """
    Django middleware. Configure via settings.py:
        CYBERSHIELD_API_KEY = "cs_live_..."
        CYBERSHIELD_ENDPOINT = "http://localhost:5000"
        CYBERSHIELD_MODE = "block"
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self._init_sender()

    def _init_sender(self):
        try:
            from django.conf import settings
            api_key = getattr(settings, "CYBERSHIELD_API_KEY", "")
            endpoint = getattr(settings, "CYBERSHIELD_ENDPOINT", DEFAULT_ENDPOINT)
            mode = getattr(settings, "CYBERSHIELD_MODE", "block")
            timeout = getattr(settings, "CYBERSHIELD_TIMEOUT", DEFAULT_TIMEOUT)
        except ImportError:
            raise RuntimeError("[CyberShield] Django not installed")

        if not api_key:
            raise ValueError("[CyberShield] CYBERSHIELD_API_KEY not set in Django settings")

        self.mode = mode
        self._sender = _Sender(api_key, endpoint, timeout, MAX_QUEUE)

    def __call__(self, request):
        payload = {
            "ip": request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "0.0.0.0")).split(",")[0].strip(),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "path": request.get_full_path(),
            "method": request.method,
            "payload": request.POST.dict() or {},
            "headers": {},
            "session_id": request.session.session_key or "" if hasattr(request, "session") else "",
            "timestamp": datetime.utcnow().isoformat(),
        }

        result = self._sender.send(payload)

        if result and result.get("action") == "block" and self.mode == "block":
            from django.http import JsonResponse
            return JsonResponse({"error": "Access denied by CyberShield"}, status=403)

        response = self.get_response(request)
        return response


# ─── FastAPI / Starlette Middleware ───────────────────────────────────────────

class FastAPIMiddleware:
    """
    Starlette/FastAPI middleware.

    Usage:
        from cybershield_python import FastAPIMiddleware
        app.add_middleware(FastAPIMiddleware, api_key="cs_live_...", endpoint="http://localhost:5000")
    """

    def __init__(self, app, api_key: str, endpoint: str = DEFAULT_ENDPOINT, mode: str = "block", timeout: float = DEFAULT_TIMEOUT):
        self.app = app
        self.mode = mode
        if not api_key:
            raise ValueError("[CyberShield] api_key is required")
        self._sender = _Sender(api_key, endpoint, timeout, MAX_QUEUE)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Read body
        body_chunks = []
        async def receive_wrapper():
            msg = await receive()
            if msg["type"] == "http.request":
                body_chunks.append(msg.get("body", b""))
            return msg

        body_bytes = b""
        # We need to fully consume the body for inspection
        # Use a simple receive wrapper approach
        messages = []

        async def capturing_receive():
            msg = await receive()
            messages.append(msg)
            return msg

        # Build headers dict
        headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}

        # Extract path
        path = scope.get("path", "/")
        query = scope.get("query_string", b"").decode("utf-8")
        full_path = f"{path}?{query}" if query else path

        # Extract IP
        client = scope.get("client")
        ip = client[0] if client else "0.0.0.0"
        forwarded = headers.get("x-forwarded-for", "")
        if forwarded:
            ip = forwarded.split(",")[0].strip()

        payload = {
            "ip": ip,
            "user_agent": headers.get("user-agent", ""),
            "path": full_path,
            "method": scope.get("method", "GET"),
            "payload": {},
            "headers": {},
            "session_id": "",
            "timestamp": datetime.utcnow().isoformat(),
        }

        result = self._sender.send(payload)

        if result and result.get("action") == "block" and self.mode == "block":
            async def blocked_send(message):
                if message["type"] == "http.response.start":
                    await send({
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [[b"content-type", b"application/json"]],
                    })
                elif message["type"] == "http.response.body":
                    await send({
                        "type": "http.response.body",
                        "body": b'{"error":"Access denied by CyberShield"}',
                    })
            await blocked_send({"type": "http.response.start"})
            await blocked_send({"type": "http.response.body"})
            return

        await self.app(scope, receive, send)
