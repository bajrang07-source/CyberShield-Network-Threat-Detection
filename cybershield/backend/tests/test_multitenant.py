"""
Tests for multi-tenant data isolation.
Verifies that site_id scoping prevents cross-tenant data leakage.
"""
import pytest
from datetime import datetime, timedelta


@pytest.fixture
def app():
    """Create a test Flask app with in-memory SQLite."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

    from flask import Flask
    from models.db import db as _db

    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'test-secret'
    app.config['JWT_SECRET_KEY'] = 'test-jwt-secret'

    _db.init_app(app)
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture
def db(app):
    from models.db import db as _db
    with app.app_context():
        yield _db


def _create_org_and_site(db, name='TestOrg', site_name='TestSite', url='https://test.com'):
    from models.db import Organization, Site
    org = Organization(name=name)
    db.session.add(org)
    db.session.flush()
    site = Site(organization_id=org.id, name=site_name, origin_url=url)
    db.session.add(site)
    db.session.flush()
    return org, site


# ── Test: Organization creation ───────────────────────────────────────────────

def test_create_organization(db):
    from models.db import Organization
    org = Organization(name='Acme Corp')
    db.session.add(org)
    db.session.commit()

    fetched = Organization.query.first()
    assert fetched is not None
    assert fetched.name == 'Acme Corp'
    assert fetched.created_at is not None


# ── Test: Site scoped to org ──────────────────────────────────────────────────

def test_site_belongs_to_org(db):
    from models.db import Organization, Site
    org, site = _create_org_and_site(db)
    db.session.commit()

    fetched = Site.query.get(site.id)
    assert fetched.organization_id == org.id
    assert fetched.origin_url == 'https://test.com'
    assert fetched.status == 'active'


# ── Test: RequestLog site_id scoping ─────────────────────────────────────────

def test_request_log_site_isolation(db):
    from models.db import RequestLog
    _, site_a = _create_org_and_site(db, 'OrgA', 'SiteA', 'https://a.com')
    _, site_b = _create_org_and_site(db, 'OrgB', 'SiteB', 'https://b.com')
    db.session.commit()

    # Insert logs for site A
    for i in range(3):
        log = RequestLog(
            site_id=site_a.id,
            ip_address=f'10.0.0.{i}',
            method='GET',
            path='/api/test',
            risk_score=10.0,
        )
        db.session.add(log)

    # Insert log for site B
    log_b = RequestLog(
        site_id=site_b.id,
        ip_address='192.168.1.1',
        method='POST',
        path='/api/login',
        risk_score=90.0,
    )
    db.session.add(log_b)
    db.session.commit()

    # Site A can only see its own logs
    site_a_logs = RequestLog.query.filter_by(site_id=site_a.id).all()
    assert len(site_a_logs) == 3
    for log in site_a_logs:
        assert log.site_id == site_a.id

    # Site B can only see its own logs
    site_b_logs = RequestLog.query.filter_by(site_id=site_b.id).all()
    assert len(site_b_logs) == 1
    assert site_b_logs[0].ip_address == '192.168.1.1'

    # Verify no data leakage: site A logs not visible to site B query
    for log in site_b_logs:
        assert log.site_id != site_a.id


# ── Test: BlockedIP site_id scoping ──────────────────────────────────────────

def test_blocked_ip_site_isolation(db):
    from models.db import BlockedIP
    _, site_a = _create_org_and_site(db, 'OrgA', 'SiteA', 'https://a.com')
    _, site_b = _create_org_and_site(db, 'OrgB', 'SiteB', 'https://b.com')
    db.session.commit()

    blocked_a = BlockedIP(
        site_id=site_a.id,
        ip_address='1.2.3.4',
        reason='SQL Injection',
        expires_at=datetime.utcnow() + timedelta(hours=24),
    )
    blocked_b = BlockedIP(
        site_id=site_b.id,
        ip_address='5.6.7.8',
        reason='XSS',
        expires_at=datetime.utcnow() + timedelta(hours=24),
    )
    db.session.add_all([blocked_a, blocked_b])
    db.session.commit()

    site_a_blocked = BlockedIP.query.filter_by(site_id=site_a.id).all()
    assert len(site_a_blocked) == 1
    assert site_a_blocked[0].ip_address == '1.2.3.4'

    site_b_blocked = BlockedIP.query.filter_by(site_id=site_b.id).all()
    assert len(site_b_blocked) == 1
    assert site_b_blocked[0].ip_address == '5.6.7.8'


# ── Test: API key belongs to correct site ─────────────────────────────────────

def test_api_key_site_binding(db):
    import bcrypt
    from models.db import ApiKey
    _, site = _create_org_and_site(db)
    db.session.commit()

    raw_key = 'cs_live_testkey123456789'
    hashed = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt(rounds=4)).decode()

    key = ApiKey(
        site_id=site.id,
        key_prefix=raw_key[:16],
        hashed_key=hashed,
        label='Test',
    )
    db.session.add(key)
    db.session.commit()

    fetched = ApiKey.query.filter_by(site_id=site.id).first()
    assert fetched is not None
    assert bcrypt.checkpw(raw_key.encode(), fetched.hashed_key.encode())


# ── Test: SiteRuleConfig isolation ────────────────────────────────────────────

def test_site_rule_config_isolation(db):
    from models.db import SiteRuleConfig
    _, site_a = _create_org_and_site(db, 'OrgA', 'SiteA', 'https://a.com')
    _, site_b = _create_org_and_site(db, 'OrgB', 'SiteB', 'https://b.com')
    db.session.commit()

    rc_a = SiteRuleConfig(site_id=site_a.id, enable_xss=False, critical_threshold=70.0)
    rc_b = SiteRuleConfig(site_id=site_b.id, enable_sqli=False, critical_threshold=85.0)
    db.session.add_all([rc_a, rc_b])
    db.session.commit()

    config_a = SiteRuleConfig.query.filter_by(site_id=site_a.id).first()
    config_b = SiteRuleConfig.query.filter_by(site_id=site_b.id).first()

    # Each site has its own config
    assert config_a.enable_xss is False
    assert config_a.critical_threshold == 70.0

    assert config_b.enable_sqli is False
    assert config_b.critical_threshold == 85.0

    # No cross-contamination
    assert config_a.site_id != config_b.site_id
