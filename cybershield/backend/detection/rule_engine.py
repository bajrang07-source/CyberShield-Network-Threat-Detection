"""
Rule-based detection engine for CyberShield.
Returns structured RuleResult with attack_type, severity, and matched_pattern.
"""
import re
from dataclasses import dataclass
from typing import Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config


@dataclass
class RuleResult:
    attack_type: Optional[str]     # None if clean
    severity: int                  # 0-10
    matched_pattern: str           # description of what matched


# ── Compiled regex patterns ────────────────────────────────────────────────────

SQLI_PATTERNS = re.compile(
    r"('|\b)OR\s+['\w]+\s*=\s*['\w]+|UNION[\s\S]*?SELECT|DROP\s+TABLE|--\s*$|;\s*SELECT|"
    r"SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(|INSERT\s+INTO|exec\s*\(|xp_cmdshell",
    re.IGNORECASE | re.MULTILINE,
)

XSS_PATTERNS = re.compile(
    r"<script[\s\S]*?>|onerror\s*=|javascript:|on\w+\s*=\s*.*?[\"']|<iframe|<svg[\s\S]*?on\w+",
    re.IGNORECASE | re.DOTALL,
)

PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./){2,}|%2e%2e%2f|etc/passwd|etc/shadow|/proc/self",
    re.IGNORECASE,
)

CMD_INJECTION_PATTERNS = re.compile(
    r";\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|nc)\b|"
    r"&&\s*\w+|`\w+`|\|\s*(ls|cat|rm|wget|curl|bash|sh)\b",
    re.IGNORECASE,
)

# Honeypot paths (exact or prefix match)
HONEYPOT_PATHS = {
    "/admin", "/wp-login.php", "/phpmyadmin", "/.env",
    "/xmlrpc.php", "/.git/config",
}


def _text_from_context(ctx) -> str:
    """Flatten request context to searchable string."""
    import json
    try:
        payload_str = json.dumps(ctx.payload, ensure_ascii=False)
    except Exception:
        payload_str = str(ctx.payload)
    return f"{ctx.path} {payload_str}"


def check_rules(ctx) -> RuleResult:
    """
    Evaluate all rule categories against the RequestContext.
    Returns the first matching RuleResult (highest-priority first).
    """
    path_lower = ctx.path.lower().split("?")[0]

    # 1. Honeypot paths — instant, highest severity
    if path_lower in HONEYPOT_PATHS or any(path_lower.startswith(h) for h in HONEYPOT_PATHS):
        return RuleResult(
            attack_type="HONEYPOT_TRAP",
            severity=10,
            matched_pattern=f"Honeypot path accessed: {ctx.path}",
        )

    full_text = _text_from_context(ctx)

    # 2. Command Injection (severity 10)
    m = CMD_INJECTION_PATTERNS.search(full_text)
    if m:
        return RuleResult(
            attack_type="COMMAND_INJECTION",
            severity=10,
            matched_pattern=f"CMD_INJECTION: {m.group(0)[:80]}",
        )

    # 3. SQL Injection (severity 9)
    m = SQLI_PATTERNS.search(full_text)
    if m:
        return RuleResult(
            attack_type="SQL_INJECTION",
            severity=9,
            matched_pattern=f"SQLI: {m.group(0)[:80]}",
        )

    # 4. XSS (severity 8)
    m = XSS_PATTERNS.search(full_text)
    if m:
        return RuleResult(
            attack_type="XSS",
            severity=8,
            matched_pattern=f"XSS: {m.group(0)[:80]}",
        )

    # 5. Path Traversal (severity 7)
    m = PATH_TRAVERSAL_PATTERNS.search(full_text)
    if m:
        return RuleResult(
            attack_type="PATH_TRAVERSAL",
            severity=7,
            matched_pattern=f"PATH_TRAVERSAL: {m.group(0)[:80]}",
        )

    # 6. Brute Force — path ends with /login AND high request rate
    try:
        rate_1m = getattr(ctx, "_rate_1m", 0)
    except Exception:
        rate_1m = 0

    if path_lower.endswith("/login") and rate_1m > config.BRUTE_FORCE_RATE_LIMIT:
        return RuleResult(
            attack_type="BRUTE_FORCE",
            severity=6,
            matched_pattern=f"BRUTE_FORCE: {rate_1m} req/min on {ctx.path}",
        )

    # Clean
    return RuleResult(attack_type=None, severity=0, matched_pattern="")
