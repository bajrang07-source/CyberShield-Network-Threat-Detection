"""
Response engine — decides how to react to each AttackEvent based on risk score.
Handles blocking, rate-limiting, alerting, geo-lookup, and webhook dispatch.
"""
import json
import logging
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional

import requests as http_requests
from flask import g, abort, jsonify

logger = logging.getLogger(__name__)


def _get_deps():
    """Lazy imports to avoid circular deps."""
    from app import redis_client
    from config import config
    from models.db import db, RequestLog, BlockedIP, Alert
    from api.events import emit_attack, emit_ip_blocked
    return redis_client, config, db, RequestLog, BlockedIP, Alert, emit_attack, emit_ip_blocked


def _severity_label(risk_score: float) -> str:
    from config import config
    if risk_score >= config.CRITICAL_THRESHOLD:
        return "CRITICAL"
    elif risk_score >= config.HIGH_THRESHOLD:
        return "HIGH"
    elif risk_score >= config.MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _insert_request_log(event, db, RequestLog) -> Optional[int]:
    """Insert RequestLog entry and return its ID."""
    try:
        log = RequestLog(
            ip_address=event.ip,
            method=event.method,
            path=event.path,
            user_agent=event.user_agent,
            payload_snippet=event.payload_snippet[:200] if event.payload_snippet else "",
            risk_score=event.risk_score,
            attack_type=event.attack_type,
            is_blocked=(event.severity == "CRITICAL"),
            session_id=event.session_id,
            timestamp=event.timestamp,
        )
        db.session.add(log)
        db.session.flush()  # get ID before commit
        return log.id
    except Exception as exc:
        logger.error("[ResponseEngine] RequestLog insert error: %s", exc)
        return None


def _insert_alert(event, log_id, db, Alert):
    """Insert Alert entry linked to RequestLog."""
    try:
        alert = Alert(
            request_log_id=log_id,
            severity=event.severity,
            attack_type=event.attack_type,
            risk_score=event.risk_score,
            matched_pattern=event.matched_pattern,
            ml_score=event.ml_score,
            timestamp=event.timestamp,
        )
        db.session.add(alert)
    except Exception as exc:
        logger.error("[ResponseEngine] Alert insert error: %s", exc)


def _geo_lookup_async(ip: str, blocked_ip_id: int):
    """Fire-and-forget thread to enrich BlockedIP with geo data."""
    def _lookup():
        try:
            resp = http_requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                from app import app
                with app.app_context():
                    from models.db import db, BlockedIP
                    record = BlockedIP.query.get(blocked_ip_id)
                    if record:
                        record.country = data.get("country", "")
                        record.city = data.get("city", "")
                        record.asn = data.get("as", "")
                        db.session.commit()
        except Exception as exc:
            logger.warning("[GeoLookup] Failed for %s: %s", ip, exc)

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()


def _dispatch_webhook(event, config):
    """POST JSON alert to WEBHOOK_URL if configured."""
    if not config.WEBHOOK_URL:
        return

    def _send():
        try:
            payload = {
                "type": "CRITICAL_ALERT",
                "ip": event.ip,
                "attack_type": event.attack_type,
                "risk_score": event.risk_score,
                "path": event.path,
                "timestamp": event.timestamp.isoformat(),
            }
            http_requests.post(config.WEBHOOK_URL, json=payload, timeout=5)
        except Exception as exc:
            logger.warning("[Webhook] Dispatch failed: %s", exc)

    threading.Thread(target=_send, daemon=True).start()


def handle(event) -> None:
    """
    Main response handler. Called from interceptor for every request.
    Modifies Flask g, may abort with 403/429.
    """
    redis_client, config, db, RequestLog, BlockedIP, Alert, emit_attack, emit_ip_blocked = _get_deps()

    severity = _severity_label(event.risk_score)
    event.severity = severity

    # ── CRITICAL (>= 80) ────────────────────────────────────────────────────────
    if event.risk_score >= config.CRITICAL_THRESHOLD:
        # Block in Redis
        try:
            redis_key = f"cybershield:blocked:{event.ip}"
            redis_client.setex(redis_key, config.BLOCK_DURATION_SECONDS, "1")
        except Exception as exc:
            logger.warning("[ResponseEngine] Redis block failed: %s", exc)

        # Block in DB
        expires_at = datetime.utcnow() + timedelta(seconds=config.BLOCK_DURATION_SECONDS)
        blocked_id = None
        try:
            existing = BlockedIP.query.filter_by(ip_address=event.ip).first()
            if not existing:
                blocked = BlockedIP(
                    ip_address=event.ip,
                    blocked_at=datetime.utcnow(),
                    reason=event.matched_pattern or event.attack_type or "Auto-blocked",
                    attack_type=event.attack_type,
                    expires_at=expires_at,
                )
                db.session.add(blocked)
                db.session.flush()
                blocked_id = blocked.id
                _geo_lookup_async(event.ip, blocked_id)
            else:
                existing.blocked_at = datetime.utcnow()
                existing.expires_at = expires_at
                blocked_id = existing.id
        except Exception as exc:
            logger.error("[ResponseEngine] BlockedIP insert error: %s", exc)

        # Emit events
        try:
            emit_ip_blocked(event.ip, event.matched_pattern or event.attack_type, expires_at)
            emit_attack(event)
        except Exception:
            pass

        # Insert log + alert
        log_id = _insert_request_log(event, db, RequestLog)
        if log_id:
            _insert_alert(event, log_id, db, Alert)
        try:
            db.session.commit()
        except Exception as exc:
            logger.error("[ResponseEngine] DB commit error (CRITICAL): %s", exc)
            db.session.rollback()

        # Webhook
        _dispatch_webhook(event, config)

        abort(403, description=json.dumps({"error": "Access denied", "code": "BLOCKED"}))

    # ── HIGH (>= 60) ────────────────────────────────────────────────────────────
    elif event.risk_score >= config.HIGH_THRESHOLD:
        cap_key = f"cybershield:ratelimit:{event.ip}"
        over_cap = False
        try:
            pipe = redis_client.pipeline()
            pipe.incr(cap_key)
            pipe.expire(cap_key, 60)
            results = pipe.execute()
            over_cap = int(results[0]) > 20  # cap at 20 HIGH requests/min
        except Exception:
            pass

        try:
            emit_attack(event)
        except Exception:
            pass

        log_id = _insert_request_log(event, db, RequestLog)
        if log_id:
            _insert_alert(event, log_id, db, Alert)
        try:
            db.session.commit()
        except Exception as exc:
            logger.error("[ResponseEngine] DB commit error (HIGH): %s", exc)
            db.session.rollback()

        if over_cap:
            response = jsonify({"error": "Too many suspicious requests", "code": "RATE_LIMITED"})
            response.status_code = 429
            response.headers["Retry-After"] = "60"
            abort(response)

    # ── MEDIUM (>= 40) ─────────────────────────────────────────────────────────
    elif event.risk_score >= config.MEDIUM_THRESHOLD:
        try:
            emit_attack(event)
        except Exception:
            pass

        log_id = _insert_request_log(event, db, RequestLog)
        if log_id:
            _insert_alert(event, log_id, db, Alert)
        try:
            db.session.commit()
        except Exception as exc:
            logger.error("[ResponseEngine] DB commit error (MEDIUM): %s", exc)
            db.session.rollback()

    # ── LOW (< 40) ─────────────────────────────────────────────────────────────
    else:
        log_id = _insert_request_log(event, db, RequestLog)
        try:
            db.session.commit()
        except Exception as exc:
            logger.error("[ResponseEngine] DB commit error (LOW): %s", exc)
            db.session.rollback()
