"""
ingestion/auth_ingestor.py
────────────────────────────────────────────────────────────────────────────────
AuthIngestor — thin routing wrapper for authentication-sourced events.

Accepts the raw payload from an identity provider, directory service, or
application login system (dict, CEF, Syslog, or free text) and produces a
normalised LogEvent tagged source_system="auth".
"""
from __future__ import annotations

from ingestion.log_normalizer import LogNormalizer
from ingestion.schema import LogEvent

_normalizer = LogNormalizer()


class AuthIngestor:
    """Ingest raw authentication events into canonical LogEvents."""

    SOURCE_SYSTEM = "auth"

    def ingest(self, raw_data) -> LogEvent:
        """Normalise *raw_data* and return a :class:`LogEvent`.

        Args:
            raw_data: dict, CEF string, Syslog string, or free text.

        Returns:
            A :class:`LogEvent` with ``source_system="auth"``.
        """
        return _normalizer.normalize(raw_data, self.SOURCE_SYSTEM)
