"""
CyberShield Django Middleware
==============================
Drop-in Django middleware that sends every request to CyberShield
for real-time threat analysis and blocks malicious traffic.

Installation:
    1. Copy this file to your Django project
    2. pip install requests
    3. Add to settings.py MIDDLEWARE (before security middleware):

        MIDDLEWARE = [
            'path.to.cybershield_django.CyberShieldMiddleware',
            'django.middleware.security.SecurityMiddleware',
            ...
        ]

    4. Add to settings.py:

        CYBERSHIELD = {
            'API_KEY':  'cs_live_your_key_here',
            'ENDPOINT': 'http://localhost:5000',
            'MODE':     'block',   # 'block' or 'monitor'
        }
"""
import json
import logging
import time

logger = logging.getLogger("cybershield.django")

try:
    import requests as http_requests
    _requests_available = True
except ImportError:
    _requests_available = False
    logger.warning("[CyberShield] 'requests' not installed. Run: pip install requests")


class CyberShieldMiddleware:
    """
    Django middleware for CyberShield threat detection.
    Compatible with Django 2.2+ (new-style middleware).
    """

    def __init__(self, get_response):
        self.get_response = get_response
        from django.conf import settings
        cfg           = getattr(settings, "CYBERSHIELD", {})
        self.api_key  = cfg.get("API_KEY", "")
        self.endpoint = cfg.get("ENDPOINT", "http://localhost:5000").rstrip("/")
        self.mode     = cfg.get("MODE", "block")
        self.enabled  = bool(self.api_key and _requests_available)

        if self.enabled:
            logger.info("[CyberShield] Protection ACTIVE (mode: %s, endpoint: %s)",
                        self.mode, self.endpoint)
        else:
            logger.warning("[CyberShield] Protection DISABLED — check API_KEY and 'requests' install")

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

        ip      = self._get_ip(request)
        method  = request.method
        path    = request.get_full_path()
        ua      = request.META.get("HTTP_USER_AGENT", "")
        payload = self._extract_payload(request)

        t_start = time.time()
        result  = self._analyse(ip, method, path, ua, payload, request.META)
        t_ms    = (time.time() - t_start) * 1000

        action = result.get("action", "allow")

        if action == "block" and self.mode == "block":
            from django.http import JsonResponse
            return JsonResponse({
                "error":       "Access denied by CyberShield",
                "attack_type": result.get("attack_type"),
                "risk_score":  round(result.get("risk_score", 0), 2),
                "severity":    result.get("severity", "CRITICAL"),
            }, status=403)

        response = self.get_response(request)
        return response

    def _get_ip(self, request):
        xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "127.0.0.1")

    def _extract_payload(self, request):
        payload = {}
        try:
            ct = request.content_type or ""
            if "application/json" in ct:
                payload = json.loads(request.body or "{}")
            elif request.POST:
                payload = dict(request.POST)
            if request.GET:
                payload.update(dict(request.GET))
        except Exception:
            pass
        return payload

    def _analyse(self, ip, method, path, ua, payload, meta):
        headers_to_send = {
            k[5:].replace("_", "-").title(): v
            for k, v in meta.items()
            if k.startswith("HTTP_")
        }
        try:
            resp = http_requests.post(
                f"{self.endpoint}/api/ingest",
                json={
                    "ip":         ip,
                    "method":     method,
                    "path":       path,
                    "user_agent": ua,
                    "payload":    payload,
                    "headers":    headers_to_send,
                },
                headers={"X-CS-API-Key": self.api_key},
                timeout=3,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            logger.warning("[CyberShield] Analysis call failed: %s", exc)
        return {"action": "allow", "risk_score": 0}
