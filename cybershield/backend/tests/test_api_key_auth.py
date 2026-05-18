"""
Tests for API key authentication middleware.
"""
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def app():
    from flask import Flask
    from models.db import db as _db

    application = Flask(__name__)
    application.config['TESTING'] = True
    application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    application.config['SECRET_KEY'] = 'test'
    application.config['JWT_SECRET_KEY'] = 'test-jwt'

    _db.init_app(application)
    with application.app_context():
        _db.create_all()
        yield application
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def _setup_site_with_key(db):
    """Create a test site with a valid API key. Returns (site, raw_key)."""
    import bcrypt
    from models.db import Organization, Site, ApiKey

    org = Organization(name='Test Org')
    db.session.add(org)
    db.session.flush()

    site = Site(organization_id=org.id, name='Test Site', origin_url='https://test.com')
    db.session.add(site)
    db.session.flush()

    raw_key = 'cs_live_testkey12345678901234567890123456789012345678'
    hashed = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=4)).decode()

    key = ApiKey(
        site_id=site.id,
        key_prefix=raw_key[:16],
        hashed_key=hashed,
        label='Test',
        is_active=True,
    )
    db.session.add(key)
    db.session.commit()
    return site, raw_key


# ── Test: Missing API key returns 401 ─────────────────────────────────────────

def test_missing_api_key_returns_401(app):
    from models.db import db
    with app.app_context():
        with app.test_request_context('/api/ingest', method='POST'):
            from middleware.auth_middleware import authenticate_site_key
            result = authenticate_site_key()
            assert result is not None
            response, status = result
            assert status == 401


# ── Test: Invalid API key returns 403 ─────────────────────────────────────────

def test_invalid_api_key_returns_403(app):
    from models.db import db
    with app.app_context():
        with app.test_request_context(
            '/api/ingest',
            method='POST',
            headers={'X-CS-API-Key': 'cs_live_invalidkey000000000000000000000000000000000000'},
        ):
            from middleware.auth_middleware import authenticate_site_key
            result = authenticate_site_key()
            assert result is not None
            response, status = result
            assert status == 403


# ── Test: Wrong prefix format returns 401 ────────────────────────────────────

def test_wrong_key_format_returns_401(app):
    from models.db import db
    with app.app_context():
        with app.test_request_context(
            '/api/ingest',
            method='POST',
            headers={'X-CS-API-Key': 'invalid_format_key'},
        ):
            from middleware.auth_middleware import authenticate_site_key
            result = authenticate_site_key()
            assert result is not None
            response, status = result
            assert status == 401


# ── Test: Valid API key resolves site ─────────────────────────────────────────

def test_valid_api_key_resolves_site(app):
    from flask import g
    from models.db import db
    with app.app_context():
        site, raw_key = _setup_site_with_key(db)

        with app.test_request_context(
            '/api/ingest',
            method='POST',
            headers={'X-CS-API-Key': raw_key},
        ):
            with app.test_request_context(
                headers={'X-CS-API-Key': raw_key}
            ):
                from middleware.auth_middleware import authenticate_site_key
                result = authenticate_site_key()
                # Should return None (success) and set g.site_id
                assert result is None
                assert g.site_id == site.id


# ── Test: Inactive key is rejected ────────────────────────────────────────────

def test_inactive_api_key_rejected(app):
    from models.db import db, ApiKey
    import bcrypt
    with app.app_context():
        site, raw_key = _setup_site_with_key(db)

        # Deactivate the key
        key = ApiKey.query.filter_by(site_id=site.id).first()
        key.is_active = False
        db.session.commit()

        with app.test_request_context(
            headers={'X-CS-API-Key': raw_key}
        ):
            from middleware.auth_middleware import authenticate_site_key
            result = authenticate_site_key()
            assert result is not None
            response, status = result
            assert status == 403


# ── Test: Suspended site is rejected ─────────────────────────────────────────

def test_suspended_site_rejected(app):
    from models.db import db, Site
    with app.app_context():
        site, raw_key = _setup_site_with_key(db)

        # Suspend the site
        s = Site.query.get(site.id)
        s.status = 'suspended'
        db.session.commit()

        with app.test_request_context(
            headers={'X-CS-API-Key': raw_key}
        ):
            from middleware.auth_middleware import authenticate_site_key
            result = authenticate_site_key()
            assert result is not None
            _, status = result
            assert status == 403
