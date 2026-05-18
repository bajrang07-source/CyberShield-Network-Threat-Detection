"""
API Key authentication middleware for CyberShield Universal.
Reads X-CS-API-Key header, resolves tenant (site_id), attaches to Flask g.
"""
import logging
from datetime import datetime
from functools import wraps

import bcrypt
from flask import request, g, jsonify

logger = logging.getLogger(__name__)


def _find_site_for_key(raw_key: str):
    """
    Look up the site for the given plaintext API key.
    Returns (ApiKey record, Site record) or (None, None).
    """
    from models.db import ApiKey, Site

    if not raw_key or not raw_key.startswith("cs_live_"):
        return None, None

    # Derive the prefix (first 16 chars) to narrow the search
    prefix = raw_key[:16]
    candidates = ApiKey.query.filter_by(key_prefix=prefix, is_active=True).all()

    for api_key_record in candidates:
        try:
            if bcrypt.checkpw(raw_key.encode("utf-8"), api_key_record.hashed_key.encode("utf-8")):
                site = Site.query.get(api_key_record.site_id)
                if site and site.status == "active":
                    return api_key_record, site
        except Exception as exc:
            logger.warning("[AuthMiddleware] bcrypt check error: %s", exc)

    return None, None


def authenticate_site_key():
    """
    Callable middleware: reads X-CS-API-Key, resolves tenant.
    Sets g.site_id, g.site, g.api_key_record on success.
    Returns a 401/403 JSON response on failure, None on success.

    Status codes:
      401 — key missing or malformed (doesn't start with cs_live_)
      403 — key valid format but not found / inactive / site suspended
    """
    raw_key = request.headers.get("X-CS-API-Key", "").strip()
    if not raw_key:
        return jsonify({"error": "Missing X-CS-API-Key header", "code": "AUTH_REQUIRED"}), 401

    # Malformed key format → 401 (not a valid CyberShield key at all)
    if not raw_key.startswith("cs_live_"):
        return jsonify({"error": "Invalid API key format", "code": "AUTH_REQUIRED"}), 401

    api_key_record, site = _find_site_for_key(raw_key)
    if not api_key_record or not site:
        return jsonify({"error": "Invalid or inactive API key", "code": "AUTH_FAILED"}), 403

    # Attach to request context
    g.site_id = site.id
    g.site = site
    g.api_key_record = api_key_record

    # Update last_used_at asynchronously-ish (best-effort)
    try:
        from models.db import db
        api_key_record.last_used_at = datetime.utcnow()
        db.session.commit()
    except Exception:
        pass

    return None  # success


def require_site_key(f):
    """
    Decorator version of authenticate_site_key for routes that require it.
    Usage:
        @app.route('/api/ingest', methods=['POST'])
        @require_site_key
        def ingest(): ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        result = authenticate_site_key()
        if result is not None:
            return result
        return f(*args, **kwargs)
    return decorated
