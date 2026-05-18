"""
CyberShield Universal — Central Threat Service.

Single source of truth for all detection orchestration.
Refactored: integrates behavioral engine, emits all new socket events,
and computes real-time stats deltas after each request.

No synthetic events. No timer-based emissions. Everything is traffic-driven.
"""
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List

logger = logging.getLogger(__name__)


# ─── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ThreatResult:
    id: str
    site_id: Optional[str]
    ip: str
    method: str
    path: str
    user_agent: str
    payload_snippet: str
    risk_score: float
    attack_type: Optional[str]
    matched_pattern: str
    ml_score: float
    severity: str
    action: str                      # "allow" | "monitor" | "block"
    timestamp: datetime
    session_id: str
    behavioral_signals: List[str] = field(default_factory=list)
    geo_info: dict = field(default_factory=dict)


# ─── Risk calculator — now includes behavioral score ──────────────────────────

def _calculate_risk(rule_severity: int, ml_score: float, rate_1m: int,
                    behavioral_score: float = 0.0) -> float:
    rule_component       = rule_severity * 10
    ml_component         = ml_score * 40
    freq_component       = min(rate_1m * 2, 20)
    behavioral_component = behavioral_score * 20   # max 20 pts additive
    return min(rule_component + ml_component + freq_component + behavioral_component, 100.0)


def _severity_label(risk_score: float, thresholds: Optional[dict] = None) -> str:
    from config import config
    c = config.CRITICAL_THRESHOLD if not thresholds else thresholds.get("critical", config.CRITICAL_THRESHOLD)
    h = config.HIGH_THRESHOLD     if not thresholds else thresholds.get("high",     config.HIGH_THRESHOLD)
    m = config.MEDIUM_THRESHOLD   if not thresholds else thresholds.get("medium",   config.MEDIUM_THRESHOLD)
    if risk_score >= c: return "CRITICAL"
    elif risk_score >= h: return "HIGH"
    elif risk_score >= m: return "MEDIUM"
    return "LOW"


def _action_for_severity(severity: str) -> str:
    return {"CRITICAL": "block", "HIGH": "monitor", "MEDIUM": "monitor", "LOW": "allow"}.get(severity, "allow")


# ─── Core analysis function ────────────────────────────────────────────────────

def analyze_request(
    ip: str,
    method: str,
    path: str,
    user_agent: str,
    payload: dict,
    headers: dict = None,
    session_id: str = "",
    timestamp: Optional[datetime] = None,
    site_id: Optional[str] = None,
    redis_client=None,
    response_ms: Optional[float] = None,
) -> ThreatResult:
    """
    Full detection pipeline for a single request.
    Steps:
      1.  Build RequestContext
      2.  Feature extraction
      3.  Rule engine
      4.  Behavioral engine  ← NEW
      5.  ML prediction
      6.  Risk score (rule + ML + behavioral)
      7.  Severity + action
      8.  Persist (DB + Redis block)
      9.  Socket.IO emit (request_live, new_attack if threat, stats_delta)
      10. Webhook if CRITICAL
    """
    from detection.feature_extractor import RequestContext, extract_features
    from detection.rule_engine import check_rules
    from detection.behavioral_engine import analyze as behavioral_analyze
    from detection.ml_engine import ml_engine

    if timestamp is None:
        timestamp = datetime.utcnow()
    if not session_id:
        session_id = str(uuid.uuid4())[:16]

    # ── Get redis client ──────────────────────────────────────────────────────
    if redis_client is None:
        try:
            from app import redis_client as _rc
            redis_client = _rc
        except Exception:
            redis_client = _MockRedis()

    # ── Per-site thresholds ───────────────────────────────────────────────────
    thresholds = None
    try:
        if site_id:
            from models.db import SiteRuleConfig
            rc = SiteRuleConfig.query.filter_by(site_id=site_id).first()
            if rc:
                thresholds = {
                    "critical": rc.critical_threshold,
                    "high":     rc.high_threshold,
                    "medium":   rc.medium_threshold,
                }
    except Exception:
        pass

    # ── Step 1: RequestContext ─────────────────────────────────────────────────
    ctx = RequestContext(
        ip=ip, method=method, path=path,
        user_agent=user_agent, payload=payload,
        timestamp=timestamp, session_id=session_id,
    )

    # ── Step 2: Feature extraction ────────────────────────────────────────────
    feature_vector = None
    rate_1m = 1
    try:
        feature_vector = extract_features(ctx, redis_client)
        rate_1m = int(feature_vector[0, 5])
        ctx._rate_1m = rate_1m
    except Exception as exc:
        logger.error("[ThreatService] Feature extraction error: %s", exc)
        ctx._rate_1m = 1

    # ── Step 3: Rule engine ───────────────────────────────────────────────────
    try:
        rule_result = check_rules(ctx)
    except Exception as exc:
        logger.error("[ThreatService] Rule engine error: %s", exc)
        from detection.rule_engine import RuleResult
        rule_result = RuleResult(attack_type=None, severity=0, matched_pattern="")

    # ── Step 4: Behavioral engine (NEW) ───────────────────────────────────────
    behavioral_score  = 0.0
    behavioral_signals: List[str] = []
    try:
        beh_result = behavioral_analyze(ctx, redis_client)
        behavioral_score   = beh_result.score
        behavioral_signals = beh_result.signals
    except Exception as exc:
        logger.error("[ThreatService] Behavioral engine error: %s", exc)

    # ── Step 5: ML prediction ─────────────────────────────────────────────────
    ml_score = 0.5
    if feature_vector is not None:
        try:
            ml_score = ml_engine.predict(feature_vector)
        except Exception as exc:
            logger.error("[ThreatService] ML prediction error: %s", exc)

    # ── Step 6: Risk score ────────────────────────────────────────────────────
    risk_score = _calculate_risk(rule_result.severity, ml_score, rate_1m, behavioral_score)

    # ── Step 7: Severity + action ─────────────────────────────────────────────
    attack_type = rule_result.attack_type
    if not attack_type and ml_score > 0.7:
        attack_type = "ANOMALY"
    if not attack_type and behavioral_signals:
        attack_type = behavioral_signals[0]   # primary behavioral signal

    severity = _severity_label(risk_score, thresholds)
    action   = _action_for_severity(severity)

    # ── Payload snippet ───────────────────────────────────────────────────────
    try:
        snippet = json.dumps(payload, ensure_ascii=False)[:200]
    except Exception:
        snippet = ""

    result = ThreatResult(
        id=str(uuid.uuid4()),
        site_id=site_id,
        ip=ip,
        method=method,
        path=path,
        user_agent=user_agent,
        payload_snippet=snippet,
        risk_score=risk_score,
        attack_type=attack_type,
        matched_pattern=rule_result.matched_pattern,
        ml_score=ml_score,
        severity=severity,
        action=action,
        timestamp=timestamp,
        session_id=session_id,
        behavioral_signals=behavioral_signals,
    )

    # ── Steps 8-10: Persist + emit + webhook ──────────────────────────────────
    try:
        _persist_and_emit(result, redis_client, thresholds, response_ms=response_ms)
    except Exception as exc:
        logger.error("[ThreatService] Persist/emit error: %s", exc)

    return result


# ─── Persist + emit ───────────────────────────────────────────────────────────

def _persist_and_emit(result: ThreatResult, redis_client, thresholds: Optional[dict],
                      response_ms: Optional[float] = None):
    """
    DB persist, Redis block, all Socket.IO emissions, webhook dispatch.
    Every emission is driven by this real request — no timers involved.
    """
    from models.db import db, RequestLog, BlockedIP, Alert
    from api.events import (
        emit_request_live, emit_request_tick_to_room,
        emit_attack_to_room, emit_ip_blocked_to_room,
        emit_req_per_sec, emit_top_ips_update, emit_stats_delta,
    )
    from config import config

    critical_threshold = (
        thresholds.get("critical", config.CRITICAL_THRESHOLD)
        if thresholds else config.CRITICAL_THRESHOLD
    )

    # ── Insert RequestLog ─────────────────────────────────────────────────────
    log_id = None
    try:
        log = RequestLog(
            site_id=result.site_id,
            ip_address=result.ip,
            method=result.method,
            path=result.path,
            user_agent=result.user_agent,
            payload_snippet=(result.payload_snippet or "")[:200],
            risk_score=result.risk_score,
            attack_type=result.attack_type,
            action=result.action,
            is_blocked=(result.action == "block"),
            session_id=result.session_id,
            timestamp=result.timestamp,
        )
        db.session.add(log)
        db.session.flush()
        log_id = log.id
    except Exception as exc:
        logger.error("[ThreatService] RequestLog insert error: %s", exc)

    # ── Insert Alert (medium+ threats) ────────────────────────────────────────
    if log_id and result.risk_score >= 40:
        try:
            alert = Alert(
                request_log_id=log_id,
                severity=result.severity,
                attack_type=result.attack_type,
                risk_score=result.risk_score,
                matched_pattern=result.matched_pattern,
                ml_score=result.ml_score,
                timestamp=result.timestamp,
            )
            db.session.add(alert)
        except Exception as exc:
            logger.error("[ThreatService] Alert insert error: %s", exc)

    # ── Redis block + DB BlockedIP ────────────────────────────────────────────
    if result.risk_score >= critical_threshold:
        try:
            redis_client.setex(
                f"cybershield:blocked:{result.ip}",
                config.BLOCK_DURATION_SECONDS, "1"
            )
        except Exception:
            pass
        try:
            expires_at = result.timestamp + timedelta(seconds=config.BLOCK_DURATION_SECONDS)
            existing = BlockedIP.query.filter_by(
                ip_address=result.ip, site_id=result.site_id
            ).first()
            if not existing:
                blocked = BlockedIP(
                    site_id=result.site_id,
                    ip_address=result.ip,
                    blocked_at=result.timestamp,
                    reason=result.matched_pattern or result.attack_type or "Auto-blocked",
                    attack_type=result.attack_type,
                    expires_at=expires_at,
                )
                db.session.add(blocked)
                db.session.flush()
                _geo_lookup_async(result.ip, blocked.id)
            else:
                existing.blocked_at = result.timestamp
                existing.expires_at = expires_at
        except Exception as exc:
            logger.error("[ThreatService] BlockedIP error: %s", exc)

    try:
        db.session.commit()
    except Exception as exc:
        logger.error("[ThreatService] DB commit error: %s", exc)
        db.session.rollback()

    # ── Socket.IO: request_live — EVERY request ───────────────────────────────
    try:
        emit_request_live(result, response_ms=response_ms)
    except Exception as exc:
        logger.warning("[ThreatService] emit_request_live error: %s", exc)

    # ── Socket.IO: request_tick — for live chart ──────────────────────────────
    try:
        emit_request_tick_to_room(result)
    except Exception as exc:
        logger.warning("[ThreatService] emit_request_tick error: %s", exc)

    # ── Socket.IO: new_attack — only for threats ──────────────────────────────
    try:
        if result.risk_score >= 40:
            emit_attack_to_room(result)
    except Exception as exc:
        logger.warning("[ThreatService] emit_attack error: %s", exc)

    # ── Socket.IO: ip_blocked ─────────────────────────────────────────────────
    try:
        if result.action == "block":
            emit_ip_blocked_to_room(
                result.ip,
                result.matched_pattern or result.attack_type,
                None,
                result.site_id,
            )
    except Exception as exc:
        logger.warning("[ThreatService] emit_ip_blocked error: %s", exc)

    # ── Socket.IO: req_per_sec — rolling 60s window ───────────────────────────
    try:
        rps_key = f"rps:{result.site_id or 'global'}"
        redis_client.incr(rps_key)
        redis_client.expire(rps_key, 60)
        rps_raw = redis_client.get(rps_key)
        rps = float(rps_raw) / 60.0 if rps_raw else 0.0
        emit_req_per_sec(rps, result.site_id)
    except Exception:
        pass

    # ── Socket.IO: top_ips_update — on medium+ threats ────────────────────────
    try:
        if result.risk_score >= 40:
            from detection.behavioral_engine import get_top_suspicious_ips
            top_ips = get_top_suspicious_ips(redis_client, limit=5)
            emit_top_ips_update(top_ips, result.site_id)
    except Exception as exc:
        logger.warning("[ThreatService] top_ips_update error: %s", exc)

    # ── Socket.IO: stats_delta — fresh DB counts after every request ──────────
    try:
        _emit_stats_delta(result, critical_threshold)
    except Exception as exc:
        logger.warning("[ThreatService] stats_delta error: %s", exc)

    # ── Webhook: CRITICAL threats ─────────────────────────────────────────────
    if result.site_id and result.risk_score >= critical_threshold:
        try:
            from webhooks.dispatcher import dispatch_webhook
            dispatch_webhook(result)
        except Exception as exc:
            logger.warning("[ThreatService] Webhook dispatch error: %s", exc)


def _emit_stats_delta(result: ThreatResult, critical_threshold: float):
    """
    Compute fresh aggregate stats from DB and emit via socket.
    Called after every persisted request — no polling, no timer.
    """
    from api.events import emit_stats_delta
    from models.db import RequestLog, BlockedIP
    from datetime import datetime, timedelta

    try:
        since = datetime.utcnow() - timedelta(hours=24)
        base_q = RequestLog.query
        if result.site_id:
            base_q = base_q.filter(RequestLog.site_id == result.site_id)

        total   = base_q.filter(RequestLog.timestamp >= since).count()
        attacks = base_q.filter(
            RequestLog.timestamp >= since,
            RequestLog.risk_score >= 40
        ).count()

        blocked_q = BlockedIP.query
        if result.site_id:
            blocked_q = blocked_q.filter(BlockedIP.site_id == result.site_id)
        blocked = blocked_q.filter(
            (BlockedIP.expires_at > datetime.utcnow()) | (BlockedIP.is_permanent == True)
        ).count()

        emit_stats_delta({
            "total_requests":   total,
            "attacks_detected": attacks,
            "blocked_ips":      blocked,
            "timestamp":        datetime.utcnow().isoformat(),
        }, result.site_id)
    except Exception as exc:
        logger.warning("[ThreatService] _emit_stats_delta error: %s", exc)


def _geo_lookup_async(ip: str, blocked_ip_id: int):
    """Fire-and-forget geo enrichment."""
    import threading
    import requests as http_requests

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
                        record.city    = data.get("city", "")
                        record.asn     = data.get("as", "")
                        db.session.commit()
        except Exception as exc:
            logger.warning("[GeoLookup] Failed for %s: %s", ip, exc)

    threading.Thread(target=_lookup, daemon=True).start()


class _MockRedis:
    """Fallback when Redis is unavailable."""
    def ping(self): return True
    def exists(self, *a): return 0
    def setex(self, *a, **kw): pass
    def set(self, *a, **kw): pass
    def get(self, *a): return None
    def incr(self, *a): return 1
    def expire(self, *a): return True
    def delete(self, *a): pass
    def sadd(self, *a): return 1
    def scard(self, *a): return 0
    def keys(self, *a): return []
    def pipeline(self): return self
    def execute(self): return [1, True, 1, True]
    def __enter__(self): return self
    def __exit__(self, *a): pass
