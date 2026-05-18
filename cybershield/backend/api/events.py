"""
SocketIO event emitters for CyberShield Universal.
All emitters are room-aware and only fire on real traffic events.
No timer-based or synthetic emissions of any kind.
"""
from datetime import datetime
from typing import Optional, List


def _get_socketio():
    from app import socketio
    return socketio


def _room_for_site(site_id: Optional[str]) -> Optional[str]:
    return f"site:{site_id}" if site_id else None


def _emit(socketio, event: str, payload: dict, site_id: Optional[str] = None):
    """Emit to site room (if set) AND global namespace."""
    room = _room_for_site(site_id)
    if room:
        socketio.emit(event, payload, room=room, namespace="/")
    socketio.emit(event, payload, namespace="/")


# ─── Preserved: global emitters (backward compat) ─────────────────────────────

def emit_attack(event) -> None:
    emit_attack_to_room(event, site_id=getattr(event, "site_id", None))


def emit_ip_blocked(ip: str, reason: str, expires_at) -> None:
    emit_ip_blocked_to_room(ip, reason, expires_at, None)


def emit_request_tick(event) -> None:
    emit_request_tick_to_room(event)


def emit_stats_update(stats_dict: dict) -> None:
    """Emit stats_update — called only after a real request is processed."""
    socketio = _get_socketio()
    socketio.emit("stats_update", stats_dict, namespace="/")


# ─── Room-aware: attack event ─────────────────────────────────────────────────

def emit_attack_to_room(result, site_id: Optional[str] = None) -> None:
    socketio = _get_socketio()
    sid = site_id or getattr(result, "site_id", None)
    payload = {
        "id":              result.id,
        "ip":              result.ip,
        "method":          result.method,
        "path":            result.path,
        "user_agent":      result.user_agent,
        "payload_snippet": result.payload_snippet,
        "risk_score":      result.risk_score,
        "attack_type":     result.attack_type,
        "matched_pattern": result.matched_pattern,
        "ml_score":        result.ml_score,
        "severity":        result.severity,
        "action":          getattr(result, "action", None),
        "site_id":         sid,
        "timestamp":       result.timestamp.isoformat() if result.timestamp else datetime.utcnow().isoformat(),
        "session_id":      result.session_id,
        "geo_info":        getattr(result, "geo_info", {}),
        "behavioral_signals": getattr(result, "behavioral_signals", []),
    }
    _emit(socketio, "new_attack", payload, sid)


# ─── Room-aware: IP blocked ───────────────────────────────────────────────────

def emit_ip_blocked_to_room(ip: str, reason: str, expires_at, site_id: Optional[str] = None) -> None:
    socketio = _get_socketio()
    payload = {
        "ip":         ip,
        "reason":     reason,
        "site_id":    site_id,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "timestamp":  datetime.utcnow().isoformat(),
    }
    _emit(socketio, "ip_blocked", payload, site_id)


# ─── Room-aware: request tick (chart) ────────────────────────────────────────

def emit_request_tick_to_room(result, site_id: Optional[str] = None) -> None:
    socketio = _get_socketio()
    sid = site_id or getattr(result, "site_id", None)
    payload = {
        "ip":         result.ip,
        "path":       result.path,
        "method":     getattr(result, "method", "GET"),
        "risk_score": result.risk_score,
        "site_id":    sid,
        "timestamp":  result.timestamp.isoformat() if result.timestamp else datetime.utcnow().isoformat(),
        "is_attack":  result.risk_score >= 40,
    }
    _emit(socketio, "request_tick", payload, sid)


# ─── NEW: Live request feed (ALL requests, not just attacks) ──────────────────

def emit_request_live(result, response_ms: Optional[float] = None) -> None:
    """
    Emitted for EVERY request processed by the pipeline.
    Powers the raw 'Live Request Feed' panel on the dashboard.
    """
    socketio = _get_socketio()
    sid = getattr(result, "site_id", None)
    payload = {
        "id":           result.id,
        "ip":           result.ip,
        "method":       result.method,
        "path":         result.path,
        "user_agent":   result.user_agent,
        "risk_score":   result.risk_score,
        "attack_type":  result.attack_type,
        "severity":     result.severity,
        "action":       result.action,
        "site_id":      sid,
        "timestamp":    result.timestamp.isoformat() if result.timestamp else datetime.utcnow().isoformat(),
        "response_ms":  response_ms,
        "is_attack":    result.risk_score >= 40,
        "behavioral_signals": getattr(result, "behavioral_signals", []),
    }
    _emit(socketio, "request_live", payload, sid)


# ─── NEW: Requests-per-second gauge ──────────────────────────────────────────

def emit_req_per_sec(rps: float, site_id: Optional[str] = None) -> None:
    """Rolling req/sec — emitted after every request, computed from Redis counter."""
    socketio = _get_socketio()
    payload = {
        "rps":      round(rps, 2),
        "site_id":  site_id,
        "timestamp": datetime.utcnow().isoformat(),
    }
    _emit(socketio, "req_per_sec", payload, site_id)


# ─── NEW: Top suspicious IPs update ──────────────────────────────────────────

def emit_top_ips_update(top_ips: list, site_id: Optional[str] = None) -> None:
    """
    Emitted after any MEDIUM+ threat detection.
    top_ips: list of { ip, burst_count, scan_count, login_fail_count, behavioral_score }
    """
    socketio = _get_socketio()
    payload = {
        "top_ips":   top_ips,
        "site_id":   site_id,
        "timestamp": datetime.utcnow().isoformat(),
    }
    _emit(socketio, "top_ips_update", payload, site_id)


# ─── NEW: Stats delta (traffic-driven, replaces timer broadcaster) ───────────

def emit_stats_delta(stats_dict: dict, site_id: Optional[str] = None) -> None:
    """
    Emitted immediately after each request is persisted to DB.
    Contains fresh aggregate counts — no polling, no timer.
    Replaces the 5-second background broadcaster entirely.
    """
    socketio = _get_socketio()
    payload = {**stats_dict, "site_id": site_id, "timestamp": datetime.utcnow().isoformat()}
    _emit(socketio, "stats_update", payload, site_id)


# ─── NEW: Connection count ────────────────────────────────────────────────────

def emit_connection_count(count: int) -> None:
    socketio = _get_socketio()
    socketio.emit("connection_count", {"count": count}, namespace="/")
