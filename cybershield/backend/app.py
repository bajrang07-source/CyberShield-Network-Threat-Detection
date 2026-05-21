"""
CyberShield Universal — Flask application entry point.
Extended for multi-tenant support with Socket.IO rooms.
"""
import logging
import os
from datetime import datetime

import redis as redis_lib
from flask import Flask, jsonify, request, g
from flask_jwt_extended import JWTManager, create_access_token
from flask_socketio import SocketIO, join_room, leave_room

from config import config
from models.db import db

# ── App & extension setup ──────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
jwt = JWTManager(app)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# ── Redis client ───────────────────────────────────────────────────────────────
try:
    redis_client = redis_lib.StrictRedis.from_url(config.REDIS_URL, decode_responses=True)
    redis_client.ping()
    logging.info("[App] Redis connected at %s", config.REDIS_URL)
except Exception as exc:
    logging.warning("[App] Redis unavailable: %s — using mock.", exc)

    class _MockRedis:
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

    redis_client = _MockRedis()

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# ── Interceptor registration ───────────────────────────────────────────────────
from middleware.interceptor import before_request_hook

@app.before_request
def _interceptor():
    return before_request_hook()


# ── Honeypot routes ─────────────────────────────────────────────────────────────
HONEYPOT_PATHS = ["/admin", "/wp-login.php", "/phpmyadmin", "/.env", "/xmlrpc.php", "/.git/config"]

def handle_honeypot(path: str):
    html = f"""<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL {path} was not found on this server.</p></body>
</html>"""
    return html, 404, {"Content-Type": "text/html"}

for _hp in HONEYPOT_PATHS:
    def _make_view(p):
        def _view():
            return handle_honeypot(p)
        _view.__name__ = f"honeypot_{p.replace('/', '_').replace('.', '_')}"
        return _view
    app.add_url_rule(_hp, view_func=_make_view(_hp), methods=["GET", "POST", "PUT", "DELETE"])


# ── Auth endpoint ──────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if username == config.ADMIN_USER and password == config.ADMIN_PASS:
        token = create_access_token(identity=username)
        return jsonify({"access_token": token, "token_type": "bearer"})
    return jsonify({"error": "Invalid credentials"}), 401


# ── Health endpoint ────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    from detection.ml_engine import ml_engine

    redis_ok = False
    try:
        redis_client.ping()
        redis_ok = True
    except Exception:
        pass

    return jsonify({
        "status": "ok",
        "model_loaded": ml_engine.is_loaded,
        "redis_connected": redis_ok,
        "timestamp": datetime.utcnow().isoformat(),
    })


# ── Stats broadcaster REMOVED ────────────────────────────────────────────────
# Stats are now emitted exclusively by threat_service._emit_stats_delta()
# after each real request is processed. Zero traffic = zero socket emissions.
# See: services/threat_service.py → _emit_stats_delta()


# ── Blueprint registration ─────────────────────────────────────────────────────
from api.dashboard import dashboard_bp
from api.ingest import ingest_bp
from api.ingest_routes import log_ingest_bp      # Phase 1 — universal log ingestion
from api.incident_routes import incident_bp       # Phase 3 — incident management
from api.sites import sites_bp
from middleware.proxy import proxy_bp

app.register_blueprint(dashboard_bp)
app.register_blueprint(ingest_bp)
app.register_blueprint(log_ingest_bp)             # Phase 1
app.register_blueprint(incident_bp, url_prefix="/api")
app.register_blueprint(sites_bp)
app.register_blueprint(proxy_bp)


# ── SocketIO events ────────────────────────────────────────────────────────────
_connected_clients: int = 0

@socketio.on("connect")
def on_connect():
    global _connected_clients
    _connected_clients += 1
    logging.info("[SocketIO] Client connected: %s (total: %d)", request.sid, _connected_clients)
    try:
        from api.events import emit_connection_count
        emit_connection_count(_connected_clients)
    except Exception:
        pass


@socketio.on("disconnect")
def on_disconnect():
    global _connected_clients
    _connected_clients = max(0, _connected_clients - 1)
    logging.info("[SocketIO] Client disconnected: %s (total: %d)", request.sid, _connected_clients)
    try:
        from api.events import emit_connection_count
        emit_connection_count(_connected_clients)
    except Exception:
        pass


@socketio.on("join_site")
def on_join_site(data):
    """Client joins a site-specific room to receive scoped events."""
    site_id = data.get("site_id") if isinstance(data, dict) else None
    if site_id:
        room = f"site:{site_id}"
        join_room(room)
        logging.info("[SocketIO] %s joined room %s", request.sid, room)
        socketio.emit("room_joined", {"room": room, "site_id": site_id}, room=request.sid)


@socketio.on("leave_site")
def on_leave_site(data):
    """Client leaves a site-specific room."""
    site_id = data.get("site_id") if isinstance(data, dict) else None
    if site_id:
        room = f"site:{site_id}"
        leave_room(room)
        logging.info("[SocketIO] %s left room %s", request.sid, room)


# ── Startup ────────────────────────────────────────────────────────────────────
def create_app():
    with app.app_context():
        db.create_all()
        logging.info("[App] Database tables created/verified.")
    logging.info("[App] Stats broadcaster removed — stats emitted per real request.")
    return app


if __name__ == "__main__":
    create_app()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
