"""
CyberShield REST API — Dashboard Blueprint (Phase 4).
All routes (except /api/auth/login) require JWT.
"""
import csv
import io
import json
import logging
from datetime import datetime, timedelta
from typing import List

from flask import Blueprint, jsonify, request, abort, g
from flask_jwt_extended import jwt_required, get_jwt_identity

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api")


def _get_deps():
    from models.db import db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings
    from config import config
    return db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/stats
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/stats", methods=["GET"])
@jwt_required()
def get_stats():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    since = datetime.utcnow() - timedelta(hours=24)

    total = RequestLog.query.filter(RequestLog.timestamp >= since).count()
    attacks = RequestLog.query.filter(
        RequestLog.timestamp >= since, RequestLog.risk_score >= 40
    ).count()
    blocked = BlockedIP.query.filter(
        (BlockedIP.expires_at > datetime.utcnow()) | (BlockedIP.is_permanent == True)
    ).count()

    avg_risk = db.session.query(
        db.func.avg(RequestLog.risk_score)
    ).filter(RequestLog.timestamp >= since).scalar() or 0.0

    critical = RequestLog.query.filter(
        RequestLog.timestamp >= since, RequestLog.risk_score >= config.CRITICAL_THRESHOLD
    ).count()
    high = RequestLog.query.filter(
        RequestLog.timestamp >= since,
        RequestLog.risk_score >= config.HIGH_THRESHOLD,
        RequestLog.risk_score < config.CRITICAL_THRESHOLD,
    ).count()
    medium = RequestLog.query.filter(
        RequestLog.timestamp >= since,
        RequestLog.risk_score >= config.MEDIUM_THRESHOLD,
        RequestLog.risk_score < config.HIGH_THRESHOLD,
    ).count()

    # Top attack types
    from sqlalchemy import func
    top_types = (
        db.session.query(RequestLog.attack_type, func.count(RequestLog.id).label("count"))
        .filter(RequestLog.timestamp >= since, RequestLog.attack_type != None)
        .group_by(RequestLog.attack_type)
        .order_by(func.count(RequestLog.id).desc())
        .limit(5)
        .all()
    )

    # Requests per hour (last 24h)
    from sqlalchemy import extract
    hours_data = []
    for h in range(23, -1, -1):
        hour_start = datetime.utcnow() - timedelta(hours=h + 1)
        hour_end = datetime.utcnow() - timedelta(hours=h)
        cnt = RequestLog.query.filter(
            RequestLog.timestamp >= hour_start,
            RequestLog.timestamp < hour_end,
        ).count()
        hours_data.append({
            "hour": hour_start.strftime("%Y-%m-%dT%H:00:00"),
            "count": cnt,
        })

    return jsonify({
        "total_requests": total,
        "attacks_detected": attacks,
        "blocked_ips": blocked,
        "avg_risk_score": round(float(avg_risk), 2),
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "top_attack_types": [{"type": t, "count": c} for t, c in top_types],
        "requests_per_hour": hours_data,
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/attacks
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/attacks", methods=["GET"])
@jwt_required()
def get_attacks():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()

    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    attack_type = request.args.get("attack_type")
    min_severity = request.args.get("min_severity", type=int)
    ip_filter = request.args.get("ip")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    q = RequestLog.query.filter(RequestLog.risk_score >= 40)

    if attack_type:
        q = q.filter(RequestLog.attack_type == attack_type)
    if min_severity is not None:
        q = q.filter(RequestLog.risk_score >= min_severity)
    if ip_filter:
        q = q.filter(RequestLog.ip_address == ip_filter)
    if start_date:
        try:
            q = q.filter(RequestLog.timestamp >= datetime.fromisoformat(start_date))
        except Exception:
            pass
    if end_date:
        try:
            q = q.filter(RequestLog.timestamp <= datetime.fromisoformat(end_date))
        except Exception:
            pass

    q = q.order_by(RequestLog.timestamp.desc())
    paginated = q.paginate(page=page, per_page=per_page, error_out=False)

    items = []
    for log in paginated.items:
        item = log.to_dict()
        if log.alert:
            item["ml_score"] = log.alert.ml_score
            item["matched_pattern"] = log.alert.matched_pattern
        else:
            item["ml_score"] = None
            item["matched_pattern"] = None
        items.append(item)

    return jsonify({
        "items": items,
        "total": paginated.total,
        "page": page,
        "pages": paginated.pages,
        "per_page": per_page,
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/attacks/<id>
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/attacks/<int:attack_id>", methods=["GET"])
@jwt_required()
def get_attack_detail(attack_id):
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()

    log = RequestLog.query.get_or_404(attack_id)
    detail = log.to_dict()

    if log.alert:
        detail["alert"] = log.alert.to_dict()

    # Last 10 requests from same IP in last 10 minutes
    since = datetime.utcnow() - timedelta(minutes=10)
    timeline_logs = (
        RequestLog.query
        .filter(RequestLog.ip_address == log.ip_address, RequestLog.timestamp >= since)
        .order_by(RequestLog.timestamp.desc())
        .limit(10)
        .all()
    )
    detail["timeline"] = [
        {"timestamp": t.timestamp.isoformat(), "path": t.path, "method": t.method, "risk_score": t.risk_score}
        for t in timeline_logs
    ]

    return jsonify(detail)


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/blocked-ips
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/blocked-ips", methods=["GET"])
@jwt_required()
def get_blocked_ips():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()

    records = BlockedIP.query.filter(
        (BlockedIP.expires_at > datetime.utcnow()) | (BlockedIP.is_permanent == True)
    ).order_by(BlockedIP.blocked_at.desc()).all()

    return jsonify([r.to_dict() for r in records])


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/blocked-ips/unblock
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/blocked-ips/unblock", methods=["POST"])
@jwt_required()
def unblock_ip():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    from app import redis_client

    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400

    # Remove Redis key
    try:
        redis_client.delete(f"cybershield:blocked:{ip}")
    except Exception:
        pass

    # Soft-delete: set expires_at = now
    record = BlockedIP.query.filter_by(ip_address=ip).first()
    if record:
        record.expires_at = datetime.utcnow()
        record.is_permanent = False
        db.session.commit()

    return jsonify({"success": True, "ip": ip})


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/blocked-ips/block
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/blocked-ips/block", methods=["POST"])
@jwt_required()
def block_ip_manual():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    from app import redis_client

    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Manual block")
    duration_hours = int(data.get("duration_hours", 24))

    if not ip:
        return jsonify({"error": "IP required"}), 400

    is_permanent = duration_hours == 0
    expires_at = None if is_permanent else datetime.utcnow() + timedelta(hours=duration_hours)

    # Redis
    try:
        if is_permanent:
            redis_client.set(f"cybershield:blocked:{ip}", "1")
        else:
            redis_client.setex(f"cybershield:blocked:{ip}", duration_hours * 3600, "1")
    except Exception:
        pass

    # DB upsert
    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        existing.reason = reason
        existing.blocked_at = datetime.utcnow()
        existing.expires_at = expires_at
        existing.is_permanent = is_permanent
    else:
        blocked = BlockedIP(
            ip_address=ip,
            reason=reason,
            blocked_at=datetime.utcnow(),
            expires_at=expires_at,
            is_permanent=is_permanent,
        )
        db.session.add(blocked)

    db.session.commit()
    return jsonify({"success": True, "ip": ip, "permanent": is_permanent})


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/traffic-timeline
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/traffic-timeline", methods=["GET"])
@jwt_required()
def traffic_timeline():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()

    minutes = min(int(request.args.get("minutes", 60)), 1440)
    since = datetime.utcnow() - timedelta(minutes=minutes)

    logs = RequestLog.query.filter(RequestLog.timestamp >= since).all()

    # Bucket by minute
    buckets = {}
    for log in logs:
        minute_key = log.timestamp.strftime("%Y-%m-%dT%H:%M:00")
        if minute_key not in buckets:
            buckets[minute_key] = {"total": 0, "attacks": 0, "blocked": 0}
        buckets[minute_key]["total"] += 1
        if log.risk_score >= 40:
            buckets[minute_key]["attacks"] += 1
        if log.is_blocked:
            buckets[minute_key]["blocked"] += 1

    result = [{"minute": k, **v} for k, v in sorted(buckets.items())]
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/threat-breakdown
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/threat-breakdown", methods=["GET"])
@jwt_required()
def threat_breakdown():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    from sqlalchemy import func

    since = datetime.utcnow() - timedelta(hours=24)

    # By type
    type_counts = (
        db.session.query(RequestLog.attack_type, func.count(RequestLog.id))
        .filter(RequestLog.timestamp >= since, RequestLog.risk_score >= 40)
        .group_by(RequestLog.attack_type)
        .all()
    )
    total_attacks = sum(c for _, c in type_counts) or 1
    by_type = [
        {"type": t or "UNKNOWN", "count": c, "percentage": round(c / total_attacks * 100, 1)}
        for t, c in type_counts
    ]

    # By hour (last 24h, separated by type)
    attack_types_tracked = ["SQL_INJECTION", "XSS", "BRUTE_FORCE", "ANOMALY"]
    by_hour = []
    for h in range(23, -1, -1):
        hour_start = datetime.utcnow() - timedelta(hours=h + 1)
        hour_end = datetime.utcnow() - timedelta(hours=h)
        row = {"hour": hour_start.strftime("%Y-%m-%dT%H:00:00")}
        for atype in attack_types_tracked:
            cnt = RequestLog.query.filter(
                RequestLog.timestamp >= hour_start,
                RequestLog.timestamp < hour_end,
                RequestLog.attack_type == atype,
            ).count()
            row[atype.lower()] = cnt
        by_hour.append(row)

    # Top IPs
    top_ips_q = (
        db.session.query(
            RequestLog.ip_address,
            func.count(RequestLog.id).label("count"),
            func.max(RequestLog.timestamp).label("last_seen"),
        )
        .filter(RequestLog.timestamp >= since, RequestLog.risk_score >= 40)
        .group_by(RequestLog.ip_address)
        .order_by(func.count(RequestLog.id).desc())
        .limit(10)
        .all()
    )

    top_ips = []
    for ip, count, last_seen in top_ips_q:
        blocked = BlockedIP.query.filter_by(ip_address=ip).first()
        top_ips.append({
            "ip": ip,
            "count": count,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "country": blocked.country if blocked else None,
        })

    return jsonify({"by_type": by_type, "by_hour": by_hour, "top_ips": top_ips})


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/settings
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/settings", methods=["GET"])
@jwt_required()
def get_settings():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    rows = Settings.query.all()
    return jsonify({r.key: r.value for r in rows})


# ─────────────────────────────────────────────────────────────────────────────
# PUT /api/settings
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_SETTING_KEYS = {
    "CRITICAL_THRESHOLD", "HIGH_THRESHOLD", "MEDIUM_THRESHOLD",
    "ML_WEIGHT", "BRUTE_FORCE_RATE_LIMIT", "BLOCK_DURATION_SECONDS",
    "WEBHOOK_URL", "ENABLE_ML", "ENABLE_RULES_SQLI", "ENABLE_RULES_XSS",
    "ENABLE_RULES_PATH_TRAVERSAL", "ENABLE_RULES_BRUTE_FORCE",
    "ENABLE_RULES_CMD_INJECTION", "ENABLE_HONEYPOT",
}

@dashboard_bp.route("/settings", methods=["PUT"])
@jwt_required()
def update_settings():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()

    data = request.get_json(silent=True) or {}
    updated = {}

    for key, value in data.items():
        if key not in ALLOWED_SETTING_KEYS:
            continue
        existing = Settings.query.filter_by(key=key).first()
        if existing:
            existing.value = str(value)
            existing.updated_at = datetime.utcnow()
        else:
            db.session.add(Settings(key=key, value=str(value)))

        # Update in-memory config
        try:
            setattr(config, key, type(getattr(config, key))(value))
        except Exception:
            pass

        updated[key] = value

    db.session.commit()
    return jsonify({"success": True, "updated": updated})


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/simulate-attack
# ─────────────────────────────────────────────────────────────────────────────
SIMULATION_PAYLOADS = {
    "SQL_INJECTION": {
        "path": "/api/search",
        "payload": {"q": "' OR 1=1 UNION SELECT * FROM users--"},
        "method": "POST",
    },
    "XSS": {
        "path": "/api/comment",
        "payload": {"comment": "<script>alert('XSS')</script>"},
        "method": "POST",
    },
    "BRUTE_FORCE": {
        "path": "/api/auth/login",
        "payload": {"username": "admin", "password": "test123"},
        "method": "POST",
        "_rate_1m": 15,
    },
    "PATH_TRAVERSAL": {
        "path": "/api/files?name=../../etc/passwd",
        "payload": {},
        "method": "GET",
    },
    "CLEAN": {
        "path": "/api/products",
        "payload": {"page": 1, "limit": 20},
        "method": "GET",
    },
}

@dashboard_bp.route("/simulate-attack", methods=["POST"])
@jwt_required()
def simulate_attack():
    from detection.feature_extractor import RequestContext, extract_features
    from detection.rule_engine import check_rules
    from detection.ml_engine import ml_engine
    from app import redis_client
    from config import config

    data = request.get_json(silent=True) or {}
    attack_type = data.get("attack_type", "CLEAN")

    sim = SIMULATION_PAYLOADS.get(attack_type, SIMULATION_PAYLOADS["CLEAN"])

    ctx = RequestContext(
        ip="192.168.99.99",
        method=sim["method"],
        path=sim["path"],
        user_agent="CyberShield-Simulator/1.0",
        payload=sim["payload"],
        timestamp=datetime.utcnow(),
        session_id="simulate-session",
    )
    ctx._rate_1m = sim.get("_rate_1m", 1)

    # Features
    try:
        feature_vector = extract_features(ctx, redis_client)
        fv_list = feature_vector[0].tolist()
    except Exception:
        feature_vector = None
        fv_list = []

    # Rules
    rule_result = check_rules(ctx)

    # ML
    ml_score = 0.5
    if feature_vector is not None:
        ml_score = ml_engine.predict(feature_vector)

    # Risk score
    rule_component = rule_result.severity * 10
    ml_component = ml_score * 40
    freq_component = min(ctx._rate_1m * 2, 20)
    risk_score = min(rule_component + ml_component + freq_component, 100.0)

    # Severity
    if risk_score >= config.CRITICAL_THRESHOLD:
        severity = "CRITICAL"
    elif risk_score >= config.HIGH_THRESHOLD:
        severity = "HIGH"
    elif risk_score >= config.MEDIUM_THRESHOLD:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return jsonify({
        "risk_score": round(risk_score, 2),
        "attack_type": rule_result.attack_type or attack_type,
        "matched_pattern": rule_result.matched_pattern,
        "ml_score": round(float(ml_score), 4),
        "severity": severity,
        "rule_result": {
            "attack_type": rule_result.attack_type,
            "severity": rule_result.severity,
            "matched_pattern": rule_result.matched_pattern,
        },
        "feature_vector": fv_list,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Whitelist endpoints
# ─────────────────────────────────────────────────────────────────────────────
@dashboard_bp.route("/whitelist", methods=["GET"])
@jwt_required()
def get_whitelist():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    records = WhitelistedIP.query.all()
    return jsonify([r.to_dict() for r in records])


@dashboard_bp.route("/whitelist", methods=["POST"])
@jwt_required()
def add_to_whitelist():
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    note = data.get("note", "")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    existing = WhitelistedIP.query.filter_by(ip_address=ip).first()
    if existing:
        return jsonify({"error": "IP already whitelisted"}), 409

    entry = WhitelistedIP(ip_address=ip, note=note)
    db.session.add(entry)
    db.session.commit()
    return jsonify(entry.to_dict()), 201


@dashboard_bp.route("/whitelist/<ip>", methods=["DELETE"])
@jwt_required()
def remove_from_whitelist(ip):
    db, RequestLog, BlockedIP, Alert, WhitelistedIP, Settings, config = _get_deps()
    record = WhitelistedIP.query.filter_by(ip_address=ip).first()
    if not record:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(record)
    db.session.commit()
    return jsonify({"success": True, "ip": ip})
