"""
CyberShield Universal — Site Management API.
CRUD for Organizations, Sites, and API Keys.
All routes require JWT (admin dashboard access).
"""
import logging
import os
import secrets
import string

import bcrypt
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

logger = logging.getLogger(__name__)

sites_bp = Blueprint("sites", __name__, url_prefix="/api")


def _get_db():
    from models.db import db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig
    return db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig


def _generate_api_key() -> str:
    """Generate a secure API key: cs_live_<48 random alphanumeric chars>."""
    alphabet = string.ascii_letters + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(48))
    return f"cs_live_{suffix}"


def _hash_key(raw_key: str) -> str:
    return bcrypt.hashpw(raw_key.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Organization endpoints
# ─────────────────────────────────────────────────────────────────────────────

@sites_bp.route("/organizations", methods=["GET"])
@jwt_required()
def list_organizations():
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    orgs = Organization.query.order_by(Organization.created_at.desc()).all()
    return jsonify([o.to_dict() for o in orgs])


@sites_bp.route("/organizations", methods=["POST"])
@jwt_required()
def create_organization():
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    org = Organization(name=name)
    db.session.add(org)
    db.session.commit()
    return jsonify(org.to_dict()), 201


# ─────────────────────────────────────────────────────────────────────────────
# Site endpoints
# ─────────────────────────────────────────────────────────────────────────────

@sites_bp.route("/sites", methods=["GET"])
@jwt_required()
def list_sites():
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    sites = Site.query.order_by(Site.created_at.desc()).all()
    result = []
    for site in sites:
        d = site.to_dict()
        d["request_count"] = len(site.request_logs)
        d["has_webhook"] = site.webhook_config is not None and site.webhook_config.enabled
        result.append(d)
    return jsonify(result)


@sites_bp.route("/sites/<site_id>", methods=["GET"])
@jwt_required()
def get_site(site_id):
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    site = Site.query.get_or_404(site_id)
    d = site.to_dict()
    d["api_keys"] = [k.to_dict() for k in site.api_keys if k.is_active]
    d["webhook"] = site.webhook_config.to_dict() if site.webhook_config else None
    d["rule_config"] = site.rule_config.to_dict() if site.rule_config else None
    return jsonify(d)


@sites_bp.route("/sites", methods=["POST"])
@jwt_required()
def create_site():
    """
    Create a new site and generate its first API key.
    Returns the plaintext key ONCE — never stored.
    """
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    origin_url = data.get("origin_url", "").strip()
    org_id = data.get("organization_id")

    if not name or not origin_url:
        return jsonify({"error": "name and origin_url are required"}), 400

    # Auto-create an org if none provided
    if not org_id:
        org = Organization(name=f"{name} Org")
        db.session.add(org)
        db.session.flush()
        org_id = org.id
    else:
        if not Organization.query.get(org_id):
            return jsonify({"error": "organization not found"}), 404

    # Create site
    site = Site(organization_id=org_id, name=name, origin_url=origin_url)
    db.session.add(site)
    db.session.flush()

    # Generate first API key
    raw_key = _generate_api_key()
    prefix = raw_key[:16]
    hashed = _hash_key(raw_key)

    api_key = ApiKey(
        site_id=site.id,
        key_prefix=prefix,
        hashed_key=hashed,
        label="Default",
    )
    db.session.add(api_key)

    # Create default rule config
    rule_config = SiteRuleConfig(site_id=site.id)
    db.session.add(rule_config)

    db.session.commit()

    return jsonify({
        "site": site.to_dict(),
        "api_key": raw_key,           # plaintext — shown ONCE
        "api_key_id": api_key.id,
        "warning": "Store this API key securely. It will NOT be shown again.",
    }), 201


@sites_bp.route("/sites/<site_id>", methods=["PATCH"])
@jwt_required()
def update_site(site_id):
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    site = Site.query.get_or_404(site_id)
    data = request.get_json(silent=True) or {}

    if "name" in data:
        site.name = data["name"].strip()
    if "origin_url" in data:
        site.origin_url = data["origin_url"].strip()
    if "status" in data and data["status"] in ("active", "suspended"):
        site.status = data["status"]

    db.session.commit()
    return jsonify(site.to_dict())


@sites_bp.route("/sites/<site_id>", methods=["DELETE"])
@jwt_required()
def delete_site(site_id):
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    site = Site.query.get_or_404(site_id)
    db.session.delete(site)
    db.session.commit()
    return jsonify({"success": True, "site_id": site_id})


# ─────────────────────────────────────────────────────────────────────────────
# API Key endpoints
# ─────────────────────────────────────────────────────────────────────────────

@sites_bp.route("/sites/<site_id>/keys", methods=["POST"])
@jwt_required()
def rotate_api_key(site_id):
    """Rotate (add new, deactivate old) API key for a site."""
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    site = Site.query.get_or_404(site_id)
    data = request.get_json(silent=True) or {}
    label = data.get("label", "Rotated Key")

    # Deactivate existing keys
    for k in site.api_keys:
        k.is_active = False

    raw_key = _generate_api_key()
    prefix = raw_key[:16]
    hashed = _hash_key(raw_key)

    new_key = ApiKey(
        site_id=site.id,
        key_prefix=prefix,
        hashed_key=hashed,
        label=label,
    )
    db.session.add(new_key)
    db.session.commit()

    return jsonify({
        "api_key": raw_key,
        "api_key_id": new_key.id,
        "warning": "Store this API key securely. It will NOT be shown again.",
    }), 201


@sites_bp.route("/sites/<site_id>/keys/<int:key_id>", methods=["DELETE"])
@jwt_required()
def revoke_api_key(site_id, key_id):
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    key = ApiKey.query.filter_by(id=key_id, site_id=site_id).first_or_404()
    key.is_active = False
    db.session.commit()
    return jsonify({"success": True, "key_id": key_id})


# ─────────────────────────────────────────────────────────────────────────────
# Webhook configuration
# ─────────────────────────────────────────────────────────────────────────────

@sites_bp.route("/sites/<site_id>/webhook", methods=["PUT"])
@jwt_required()
def upsert_webhook(site_id):
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    site = Site.query.get_or_404(site_id)
    data = request.get_json(silent=True) or {}

    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    wh = site.webhook_config
    if wh:
        wh.url = url
        wh.enabled = data.get("enabled", wh.enabled)
        wh.min_severity = data.get("min_severity", wh.min_severity)
        wh.secret = data.get("secret", wh.secret)
    else:
        wh = WebhookConfig(
            site_id=site.id,
            url=url,
            enabled=data.get("enabled", True),
            min_severity=data.get("min_severity", "HIGH"),
            secret=data.get("secret"),
        )
        db.session.add(wh)

    db.session.commit()
    return jsonify(wh.to_dict())


@sites_bp.route("/sites/<site_id>/webhook", methods=["DELETE"])
@jwt_required()
def delete_webhook(site_id):
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    site = Site.query.get_or_404(site_id)
    if site.webhook_config:
        db.session.delete(site.webhook_config)
        db.session.commit()
    return jsonify({"success": True})


# ─────────────────────────────────────────────────────────────────────────────
# Rule config per site
# ─────────────────────────────────────────────────────────────────────────────

@sites_bp.route("/sites/<site_id>/rules", methods=["PUT"])
@jwt_required()
def update_site_rules(site_id):
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    site = Site.query.get_or_404(site_id)
    data = request.get_json(silent=True) or {}

    rc = site.rule_config
    if not rc:
        rc = SiteRuleConfig(site_id=site.id)
        db.session.add(rc)

    for field in ("enable_xss", "enable_sqli", "enable_path_traversal",
                  "enable_bruteforce", "enable_cmd_injection"):
        if field in data:
            setattr(rc, field, bool(data[field]))
    for field in ("critical_threshold", "high_threshold", "medium_threshold"):
        if field in data:
            setattr(rc, field, float(data[field]))

    db.session.commit()
    return jsonify(rc.to_dict())


# ─────────────────────────────────────────────────────────────────────────────
# Per-site stats (scoped, no data leakage)
# ─────────────────────────────────────────────────────────────────────────────

@sites_bp.route("/sites/<site_id>/stats", methods=["GET"])
@jwt_required()
def site_stats(site_id):
    from datetime import timedelta
    db, Organization, Site, ApiKey, WebhookConfig, SiteRuleConfig = _get_db()
    from models.db import RequestLog, BlockedIP
    from sqlalchemy import func

    Site.query.get_or_404(site_id)  # 404 guard
    since_hours = int(request.args.get("hours", 24))
    from datetime import datetime
    since = datetime.utcnow() - timedelta(hours=since_hours)

    total = RequestLog.query.filter(RequestLog.site_id == site_id, RequestLog.timestamp >= since).count()
    attacks = RequestLog.query.filter(
        RequestLog.site_id == site_id,
        RequestLog.timestamp >= since,
        RequestLog.risk_score >= 40
    ).count()
    blocked = BlockedIP.query.filter(
        BlockedIP.site_id == site_id,
        (BlockedIP.expires_at > datetime.utcnow()) | (BlockedIP.is_permanent == True)
    ).count()

    top_types = (
        db.session.query(RequestLog.attack_type, func.count(RequestLog.id).label("count"))
        .filter(RequestLog.site_id == site_id, RequestLog.timestamp >= since, RequestLog.attack_type != None)
        .group_by(RequestLog.attack_type)
        .order_by(func.count(RequestLog.id).desc())
        .limit(5)
        .all()
    )

    return jsonify({
        "site_id": site_id,
        "total_requests": total,
        "attacks_detected": attacks,
        "blocked_ips": blocked,
        "top_attack_types": [{"type": t, "count": c} for t, c in top_types],
    })
