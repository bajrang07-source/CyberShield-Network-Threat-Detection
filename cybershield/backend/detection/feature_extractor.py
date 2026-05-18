"""
Feature extraction for CyberShield detection pipeline.
Converts a raw HTTP request into an 11-element feature vector.
"""
import math
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import numpy as np

# Special characters to count
SPECIAL_CHARS = set("'\";<>/\\()==--")

# Known bad user agent substrings (lowercase)
BAD_UA_PATTERNS = {"curl", "sqlmap", "nikto", "scrapy", "masscan", "nmap", "python-requests/2.2"}

# SQL keywords (lowercase)
SQL_KEYWORDS = {"select", "union", "insert", "drop", "delete", "update", "exec", "sleep", "benchmark", "or 1=1"}

# XSS patterns
XSS_PATTERNS = re.compile(r"<script|onerror\s*=|javascript:|on\w+\s*=|<iframe|<svg", re.IGNORECASE)

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = re.compile(r"\.\./|%2e%2e%2f|etc/passwd|etc/shadow", re.IGNORECASE)


@dataclass
class RequestContext:
    ip: str
    method: str
    path: str
    user_agent: str
    payload: dict
    timestamp: datetime
    session_id: str = ""


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _payload_as_string(payload: dict) -> str:
    try:
        return json.dumps(payload, ensure_ascii=False).lower()
    except Exception:
        return str(payload).lower()


def extract_features(ctx: RequestContext, redis_client) -> np.ndarray:
    """
    Extract the 11 detection features from a RequestContext.
    Returns np.array shape (1, 11).

    Features (in order):
      0  payload_length
      1  num_special_chars
      2  has_sql_keywords
      3  has_xss_patterns
      4  has_path_traversal
      5  request_rate_1m
      6  request_rate_5m
      7  is_known_bad_ua
      8  entropy_payload
      9  num_query_params
      10 method_is_post
    """
    payload_str = _payload_as_string(ctx.payload)
    full_text = (ctx.path + " " + payload_str).lower()

    # 0. payload_length
    payload_length = len(payload_str)

    # 1. num_special_chars
    num_special_chars = sum(1 for c in payload_str if c in SPECIAL_CHARS)

    # 2. has_sql_keywords
    has_sql_keywords = int(any(kw in full_text for kw in SQL_KEYWORDS))

    # 3. has_xss_patterns
    has_xss_patterns = int(bool(XSS_PATTERNS.search(full_text)))

    # 4. has_path_traversal
    has_path_traversal = int(bool(PATH_TRAVERSAL_PATTERNS.search(ctx.path + " " + full_text)))

    # 5 & 6. request_rate_1m and request_rate_5m — Redis INCR pipeline
    rate_1m_key = f"rate:{ctx.ip}:1m"
    rate_5m_key = f"rate:{ctx.ip}:5m"

    request_rate_1m = 1
    request_rate_5m = 1

    try:
        pipe = redis_client.pipeline()
        pipe.incr(rate_1m_key)
        pipe.expire(rate_1m_key, 60)
        pipe.incr(rate_5m_key)
        pipe.expire(rate_5m_key, 300)
        results = pipe.execute()
        request_rate_1m = int(results[0]) if results[0] else 1
        request_rate_5m = int(results[2]) if results[2] else 1
    except Exception:
        pass  # Redis unavailable — fallback to defaults

    # 7. is_known_bad_ua
    ua_lower = (ctx.user_agent or "").lower()
    is_known_bad_ua = int(any(pattern in ua_lower for pattern in BAD_UA_PATTERNS))

    # 8. entropy_payload
    entropy_payload = _shannon_entropy(payload_str) if payload_str else 0.0

    # 9. num_query_params
    from urllib.parse import urlparse, parse_qs
    try:
        parsed = urlparse(ctx.path)
        num_query_params = len(parse_qs(parsed.query))
    except Exception:
        num_query_params = 0

    # 10. method_is_post
    method_is_post = int(ctx.method.upper() == "POST")

    features = np.array([[
        payload_length,
        num_special_chars,
        has_sql_keywords,
        has_xss_patterns,
        has_path_traversal,
        request_rate_1m,
        request_rate_5m,
        is_known_bad_ua,
        entropy_payload,
        num_query_params,
        method_is_post,
    ]], dtype=float)

    return features
