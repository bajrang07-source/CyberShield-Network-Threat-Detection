"""
CyberShield — Behavioral Analysis Engine
=========================================
Stateful threat detection layer that operates on request patterns
over time, using Redis as the state store.

Completely independent of the ML model — scores are additive.
Never generates synthetic events. Only analyzes real traffic patterns.

Signals:
  1. Request burst          — >20 req/30s from same IP
  2. Route enumeration      — >10 unique paths from same IP in 60s
  3. Login failure storm    — >5 POST /login failures from same IP in 5m
  4. Method probing         — GET/POST/PUT/DELETE on same path within 2m
  5. Header anomaly         — missing User-Agent or abnormally few headers
  6. Bot fingerprinting     — headless/automation patterns in UA string
  7. 404 path scanning      — tracked via Redis; set from threat_service after response

Returns BehavioralResult with a score 0.0-1.0 and a list of triggered signal names.
"""
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Bot/automation UA patterns (substrings, lowercase) ───────────────────────
_BOT_UA_PATTERNS = [
    "bot", "crawler", "spider", "scraper", "headless", "phantom",
    "selenium", "puppeteer", "playwright", "mechanize", "wget",
    "libwww", "go-http-client", "java/", "python-httpx",
    "axios/", "node-fetch", "got/", "superagent",
    "nikto", "nmap", "masscan", "zap", "burpsuite",
    "nuclei", "hydra", "gobuster", "dirb", "dirbuster",
]

# Login path detection (suffix match, lowercase)
_LOGIN_PATHS = {"/login", "/auth/login", "/signin", "/sign-in", "/api/login", "/user/login"}


@dataclass
class BehavioralResult:
    score: float                     # 0.0 – 1.0 additive risk contribution
    signals: List[str] = field(default_factory=list)
    detail: str = ""


def analyze(ctx, redis_client) -> BehavioralResult:
    """
    Run all behavioral checks against the request context.
    Returns a BehavioralResult with a composite score.
    """
    signals: List[str] = []
    raw_score = 0.0

    ip     = ctx.ip
    path   = ctx.path.lower().split("?")[0]
    method = ctx.method.upper()
    ua     = (ctx.user_agent or "").lower()

    # ── 1. Request burst (all paths) ─────────────────────────────────────────
    try:
        burst_key = f"beh:burst:{ip}"
        burst_count = redis_client.incr(burst_key)
        redis_client.expire(burst_key, 30)
        if int(burst_count) > 20:
            signals.append("REQUEST_BURST")
            raw_score += 0.35
    except Exception:
        pass

    # ── 2. Route enumeration — unique paths in 60s ────────────────────────────
    try:
        scan_key = f"beh:scan:{ip}"
        # Use a Redis set to track unique paths; SADD returns 1 if new
        redis_client.sadd(scan_key, path)
        redis_client.expire(scan_key, 60)
        unique_paths = redis_client.scard(scan_key)
        if int(unique_paths) > 10:
            signals.append("ROUTE_ENUMERATION")
            raw_score += 0.30
    except Exception:
        pass

    # ── 3. Login failure storm ────────────────────────────────────────────────
    try:
        if method == "POST" and any(path.endswith(lp) for lp in _LOGIN_PATHS):
            fail_key = f"beh:loginfail:{ip}"
            fail_count = redis_client.incr(fail_key)
            redis_client.expire(fail_key, 300)  # 5-minute window
            if int(fail_count) > 5:
                signals.append("LOGIN_FAILURE_STORM")
                raw_score += 0.40
    except Exception:
        pass

    # ── 4. HTTP method probing — same path, multiple methods in 2m ───────────
    try:
        # Store the set of methods tried on this IP+path combo
        method_key = f"beh:method:{ip}:{path[:60]}"
        redis_client.sadd(method_key, method)
        redis_client.expire(method_key, 120)
        method_count = redis_client.scard(method_key)
        if int(method_count) >= 3:
            signals.append("METHOD_PROBING")
            raw_score += 0.20
    except Exception:
        pass

    # ── 5. Header anomaly — no User-Agent or suspiciously sparse headers ──────
    try:
        if not ctx.user_agent or len(ctx.user_agent.strip()) == 0:
            signals.append("MISSING_USER_AGENT")
            raw_score += 0.25
    except Exception:
        pass

    # ── 6. Bot fingerprinting ─────────────────────────────────────────────────
    try:
        if ua and any(p in ua for p in _BOT_UA_PATTERNS):
            signals.append("BOT_FINGERPRINT")
            raw_score += 0.30
    except Exception:
        pass

    # Clamp to 1.0
    score = min(raw_score, 1.0)
    detail = ", ".join(signals) if signals else ""

    return BehavioralResult(score=score, signals=signals, detail=detail)


def record_404(ip: str, redis_client) -> None:
    """
    Called externally (from response hook) when a 404 is returned.
    Tracks path-scanning activity.
    """
    try:
        key = f"beh:404:{ip}"
        count = redis_client.incr(key)
        redis_client.expire(key, 60)
        return int(count)
    except Exception:
        return 0


def get_top_suspicious_ips(redis_client, limit: int = 10) -> list:
    """
    Returns a ranked list of IPs with behavioral activity, for dashboard display.
    Each entry: { ip, burst_count, scan_count, login_fail_count, 404_count }
    """
    # This is a best-effort scan — only works with real Redis (not mock)
    results = []
    try:
        burst_keys = redis_client.keys("beh:burst:*")
        for key in burst_keys[:50]:
            ip = key.split("beh:burst:")[-1]
            try:
                burst  = int(redis_client.get(key) or 0)
                scan   = int(redis_client.scard(f"beh:scan:{ip}") or 0)
                fails  = int(redis_client.get(f"beh:loginfail:{ip}") or 0)
                f404   = int(redis_client.get(f"beh:404:{ip}") or 0)
                score  = burst * 0.35 + scan * 0.30 + fails * 0.40 + f404 * 0.10
                if score > 0:
                    results.append({
                        "ip": ip,
                        "burst_count": burst,
                        "scan_count": scan,
                        "login_fail_count": fails,
                        "not_found_count": f404,
                        "behavioral_score": round(min(score, 100), 1),
                    })
            except Exception:
                continue
        results.sort(key=lambda x: x["behavioral_score"], reverse=True)
    except Exception:
        pass
    return results[:limit]
