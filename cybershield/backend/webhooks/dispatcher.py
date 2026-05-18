"""
CyberShield Universal — Webhook Dispatcher.
Delivers per-site critical alert webhooks with retry + HMAC signing.
"""
import hashlib
import hmac
import json
import logging
import threading
import time
from datetime import datetime

import requests as http_requests

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAYS = [2, 5, 15]   # seconds between retries
TIMEOUT = 8


def _sign_payload(secret: str, body: str) -> str:
    """HMAC-SHA256 signature for webhook payload verification."""
    return hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()


def _send_with_retry(url: str, payload: dict, secret: str = None):
    """Send webhook with exponential-backoff retry."""
    body = json.dumps(payload, default=str)
    headers = {
        "Content-Type": "application/json",
        "X-CyberShield-Event": "threat.critical",
        "X-CyberShield-Version": "2.0",
        "X-CyberShield-Timestamp": datetime.utcnow().isoformat(),
    }
    if secret:
        headers["X-CyberShield-Signature"] = f"sha256={_sign_payload(secret, body)}"

    for attempt, delay in enumerate(RETRY_DELAYS, start=1):
        try:
            resp = http_requests.post(url, data=body, headers=headers, timeout=TIMEOUT)
            if resp.status_code < 500:
                logger.info("[Webhook] Delivered to %s (attempt %d, status %d)", url, attempt, resp.status_code)
                return True
            logger.warning("[Webhook] Server error %d from %s (attempt %d)", resp.status_code, url, attempt)
        except Exception as exc:
            logger.warning("[Webhook] Request error (attempt %d): %s", attempt, exc)

        if attempt < MAX_RETRIES:
            time.sleep(delay)

    logger.error("[Webhook] Failed to deliver to %s after %d attempts", url, MAX_RETRIES)
    return False


def dispatch_webhook(result) -> None:
    """
    Look up the site's webhook config and dispatch asynchronously.
    Called from threat_service for CRITICAL events.
    """
    def _run():
        try:
            from app import app
            with app.app_context():
                from models.db import WebhookConfig, Site

                if not result.site_id:
                    return

                wh = WebhookConfig.query.filter_by(site_id=result.site_id, enabled=True).first()
                if not wh:
                    return

                # Check min severity gate
                severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                if severity_order.get(result.severity, 0) < severity_order.get(wh.min_severity, 2):
                    return

                payload = {
                    "event": "threat.detected",
                    "site_id": result.site_id,
                    "severity": result.severity,
                    "action": result.action,
                    "ip": result.ip,
                    "attack_type": result.attack_type,
                    "risk_score": round(result.risk_score, 2),
                    "matched_pattern": result.matched_pattern,
                    "path": result.path,
                    "method": result.method,
                    "timestamp": result.timestamp.isoformat() if result.timestamp else datetime.utcnow().isoformat(),
                }

                _send_with_retry(wh.url, payload, wh.secret)
        except Exception as exc:
            logger.error("[Webhook] Dispatch thread error: %s", exc)

    threading.Thread(target=_run, daemon=True).start()
