"""
ingestion/schema.py
────────────────────────────────────────────────────────────────────────────────
LogEvent — canonical dataclass for every security event ingested into
CyberShield regardless of its source system.

No dependencies on any other CyberShield module.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

# ── Valid source systems ──────────────────────────────────────────────────────
SOURCE_SYSTEMS = frozenset({"web_traffic", "siem", "edr", "auth", "system_log"})


@dataclass
class LogEvent:
    """Universal security event record.

    Attributes:
        event_id      – UUID4 string, auto-generated when not supplied.
        timestamp     – UTC datetime of the event (defaults to now).
        source_system – Origin system tag.  One of SOURCE_SYSTEMS.
        source_ip     – IPv4/v6 address of the originating host.
        user_id       – Optional authenticated user identifier.
        event_type    – Semantic category (e.g. "authentication_failure",
                        "malware_detected", "cef_event", "unstructured").
        action        – Disposition taken (e.g. "allow", "block", "quarantine").
        payload       – Structured key/value data extracted from the raw event.
        raw_data      – Original unparsed string (always preserved verbatim).
    """

    # ── Required-ish fields (all have safe defaults) ──────────────────────────
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_system: str = "system_log"
    source_ip: str = "0.0.0.0"

    # ── Optional fields ───────────────────────────────────────────────────────
    user_id: Optional[str] = None
    event_type: str = "generic"
    action: str = "none"
    payload: Dict[str, Any] = field(default_factory=dict)
    raw_data: str = ""

    # ─────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "source_system": self.source_system,
            "source_ip": self.source_ip,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "action": self.action,
            "payload": self.payload,
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEvent":
        """Deserialize from a dictionary (inverse of to_dict).

        Unknown keys are silently ignored so that forward-compatible payloads
        don't cause crashes.
        """
        ts = data.get("timestamp")
        if isinstance(ts, str):
            # Accept ISO-8601 with or without trailing 'Z'
            ts = datetime.fromisoformat(ts.rstrip("Z"))
        elif not isinstance(ts, datetime):
            ts = datetime.utcnow()

        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            timestamp=ts,
            source_system=data.get("source_system", "system_log"),
            source_ip=data.get("source_ip", "0.0.0.0"),
            user_id=data.get("user_id"),
            event_type=data.get("event_type", "generic"),
            action=data.get("action", "none"),
            payload=data.get("payload", {}),
            raw_data=data.get("raw_data", ""),
        )
