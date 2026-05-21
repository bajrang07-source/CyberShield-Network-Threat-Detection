"""
ingestion/log_normalizer.py
────────────────────────────────────────────────────────────────────────────────
LogNormalizer — converts raw input in any format into a canonical LogEvent.

Supported formats
  • dict / JSON-like mapping
  • CEF string  (starts with "CEF:")
  • Syslog string  (RFC-3164 <priority>... or RFC-5424 <priority>version ...)
  • Free-text / unstructured  (fallback)

No Flask, no SQLAlchemy, no other CyberShield module is imported here.
All functions are pure so they can be unit-tested in isolation.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from ingestion.schema import LogEvent

# ── IP extraction regex (shared) ─────────────────────────────────────────────
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# ── Flexible field-name aliases → canonical LogEvent field ───────────────────
_IP_ALIASES = frozenset({
    "src_ip", "sourceip", "source_ip", "ip", "client_ip",
    "remote_addr", "ipaddr", "ip_address", "host", "src",
})
_USER_ALIASES = frozenset({
    "user_id", "userid", "user", "username", "account",
    "subject_id", "actor", "uid",
})
_EVENT_TYPE_ALIASES = frozenset({
    "event_type", "eventtype", "type", "category", "event_name",
    "name", "event_id",
})
_ACTION_ALIASES = frozenset({
    "action", "act", "disposition", "outcome", "result", "verdict",
})
_TIMESTAMP_ALIASES = frozenset({
    "timestamp", "ts", "time", "datetime", "@timestamp",
    "event_time", "created_at",
})


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_first_ip(text: str) -> str:
    """Return the first IPv4 address found in *text*, else '0.0.0.0'."""
    m = _IP_RE.search(text)
    return m.group(0) if m else "0.0.0.0"


def _resolve_alias(data: Dict[str, Any], aliases: frozenset) -> Optional[str]:
    """Case-insensitive key lookup across a set of aliases."""
    lowered = {k.lower(): v for k, v in data.items()}
    for alias in aliases:
        val = lowered.get(alias.lower())
        if val is not None:
            return str(val)
    return None


def _parse_timestamp(raw: Optional[str]) -> datetime:
    """Best-effort timestamp parser; returns utcnow() on failure."""
    if not raw:
        return datetime.utcnow()
    # Strip trailing Z for fromisoformat compat (Python < 3.11)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            return datetime.strptime(raw.rstrip("Z"), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(raw.rstrip("Z"))
    except Exception:
        return datetime.utcnow()


# ─────────────────────────────────────────────────────────────────────────────
# Format-specific parsers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_dict(
    data: Dict[str, Any],
    source_system: str,
) -> LogEvent:
    """Map a flat or nested dictionary to a LogEvent."""
    source_ip = _resolve_alias(data, _IP_ALIASES) or "0.0.0.0"
    user_id = _resolve_alias(data, _USER_ALIASES)
    event_type = _resolve_alias(data, _EVENT_TYPE_ALIASES) or "generic"
    action = _resolve_alias(data, _ACTION_ALIASES) or "none"
    ts_raw = _resolve_alias(data, _TIMESTAMP_ALIASES)
    timestamp = _parse_timestamp(ts_raw)

    # Collect remaining fields as payload (exclude already-mapped keys)
    mapped_keys = (_IP_ALIASES | _USER_ALIASES | _EVENT_TYPE_ALIASES
                   | _ACTION_ALIASES | _TIMESTAMP_ALIASES)
    payload = {k: v for k, v in data.items() if k.lower() not in mapped_keys}

    return LogEvent(
        source_system=source_system,
        source_ip=source_ip,
        user_id=user_id,
        event_type=event_type,
        action=action,
        timestamp=timestamp,
        payload=payload,
        raw_data=str(data),
    )


def _parse_cef_header(header: str) -> Tuple[str, str, str, str, str, str, str]:
    """Parse the pipe-delimited CEF header into its 7 components.

    CEF:Version|Device Vendor|Device Product|Device Version|
        Device Event Class ID|Name|Severity
    """
    parts = header.split("|", 6)
    while len(parts) < 7:
        parts.append("")
    return tuple(parts)  # type: ignore[return-value]


def _parse_cef_extension(ext: str) -> Dict[str, str]:
    """Parse 'key=value key2=value2 ...' CEF extension string.

    Handles values containing spaces by using lookahead for the next key=.
    """
    result: Dict[str, str] = {}
    # Split on 'word=' boundary
    tokens = re.split(r"(\w+)=", ext)
    # tokens: ['', 'key1', 'val1 ', 'key2', 'val2', ...]
    i = 1
    while i < len(tokens) - 1:
        key = tokens[i].strip()
        val = tokens[i + 1].strip()
        result[key] = val
        i += 2
    return result


def _normalize_cef(raw: str, source_system: str) -> LogEvent:
    """Parse a CEF-formatted event string."""
    # Strip the 'CEF:' prefix
    body = raw[4:] if raw.upper().startswith("CEF:") else raw

    # Split header from extension
    if " " in body:
        # Extension follows after the 7th pipe segment
        parts = body.split("|", 7)
        if len(parts) == 8:
            header = "|".join(parts[:7])
            ext_str = parts[7]
        else:
            header = body
            ext_str = ""
    else:
        header = body
        ext_str = ""

    (version, vendor, product, dev_version, class_id,
     name, severity) = _parse_cef_header(header)
    extension = _parse_cef_extension(ext_str)

    source_ip = (extension.get("src") or extension.get("sourceAddress")
                 or extension.get("dvc") or "0.0.0.0")
    user_id = (extension.get("suser") or extension.get("duser")
               or extension.get("suid") or None)
    ts_epoch = extension.get("rt") or extension.get("start")
    timestamp = (datetime.utcfromtimestamp(int(ts_epoch) / 1000)
                 if ts_epoch and ts_epoch.isdigit()
                 else datetime.utcnow())

    payload = {
        "cef_version": version,
        "vendor": vendor,
        "product": product,
        "dev_version": dev_version,
        "class_id": class_id,
        "severity": severity,
        **extension,
    }

    return LogEvent(
        source_system=source_system,
        source_ip=source_ip,
        user_id=user_id,
        event_type=name or "cef_event",
        action=extension.get("act", "none"),
        timestamp=timestamp,
        payload=payload,
        raw_data=raw,
    )


# RFC-3164:  <priority>Mon DD HH:MM:SS hostname message
_SYSLOG_3164 = re.compile(
    r"^<(\d+)>(\w{3}\s+\d+\s[\d:]+)\s+(\S+)\s+(.*)$", re.DOTALL
)
# RFC-5424:  <priority>version timestamp hostname app proc-id msgid message
_SYSLOG_5424 = re.compile(
    r"^<(\d+)>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$",
    re.DOTALL,
)


def _normalize_syslog(raw: str, source_system: str) -> LogEvent:
    """Parse RFC-3164 or RFC-5424 syslog messages."""
    m5424 = _SYSLOG_5424.match(raw)
    if m5424:
        priority, version, timestamp_str, hostname, app, proc_id, msgid, msg = m5424.groups()
        timestamp = _parse_timestamp(timestamp_str)
        source_ip = _extract_first_ip(hostname) if _IP_RE.match(hostname) else _extract_first_ip(msg)
        return LogEvent(
            source_system=source_system,
            source_ip=source_ip,
            event_type=f"syslog_{app}",
            action="none",
            timestamp=timestamp,
            payload={
                "priority": priority,
                "version": version,
                "hostname": hostname,
                "app": app,
                "proc_id": proc_id,
                "msgid": msgid,
                "message": msg,
            },
            raw_data=raw,
        )

    m3164 = _SYSLOG_3164.match(raw)
    if m3164:
        priority, timestamp_str, hostname, msg = m3164.groups()
        timestamp = _parse_timestamp(timestamp_str)
        source_ip = _extract_first_ip(hostname) if _IP_RE.match(hostname) else _extract_first_ip(msg)
        return LogEvent(
            source_system=source_system,
            source_ip=source_ip,
            event_type="syslog_message",
            action="none",
            timestamp=timestamp,
            payload={
                "priority": priority,
                "hostname": hostname,
                "message": msg,
            },
            raw_data=raw,
        )

    # Could not match any syslog format — treat as unstructured
    return _normalize_unstructured(raw, source_system)


def _normalize_unstructured(raw: str, source_system: str) -> LogEvent:
    """Last-resort parser: capture the full string and attempt IP extraction."""
    source_ip = _extract_first_ip(raw)
    return LogEvent(
        source_system=source_system,
        source_ip=source_ip,
        event_type="unstructured",
        action="none",
        timestamp=datetime.utcnow(),
        payload={},
        raw_data=raw,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class LogNormalizer:
    """Format-agnostic normalizer.

    Usage::

        normalizer = LogNormalizer()
        event = normalizer.normalize(raw_input, "siem")
    """

    def normalize(self, raw_input: Any, source_system: str) -> LogEvent:
        """Convert *raw_input* (any format) into a canonical :class:`LogEvent`.

        Args:
            raw_input:     dict, str (CEF/Syslog/free-text), or any object
                           that has a meaningful ``__str__`` representation.
            source_system: One of the SOURCE_SYSTEMS strings.  Used verbatim.

        Returns:
            A fully populated :class:`LogEvent`.
        """
        # ── dict / mapping ────────────────────────────────────────────────────
        if isinstance(raw_input, dict):
            return _normalize_dict(raw_input, source_system)

        # ── string-based formats ──────────────────────────────────────────────
        if not isinstance(raw_input, str):
            raw_input = str(raw_input)

        stripped = raw_input.strip()

        if stripped.upper().startswith("CEF:"):
            return _normalize_cef(stripped, source_system)

        if stripped.startswith("<"):
            return _normalize_syslog(stripped, source_system)

        return _normalize_unstructured(stripped, source_system)
