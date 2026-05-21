"""
ingestion/siem_ingestor.py
────────────────────────────────────────────────────────────────────────────────
SiemIngestor — thin routing wrapper for SIEM-sourced events.

Accepts the raw payload from a SIEM platform (dict, CEF, Syslog, or free text)
and produces a normalised LogEvent tagged source_system="siem".
"""
from __future__ import annotations

from ingestion.log_normalizer import LogNormalizer
from ingestion.schema import LogEvent

_normalizer = LogNormalizer()


class SiemIngestor:
    """Ingest raw SIEM events into canonical LogEvents."""

    SOURCE_SYSTEM = "siem"

    def ingest(self, raw_data) -> LogEvent:
        """Normalise *raw_data* and return a :class:`LogEvent`.

        Args:
            raw_data: dict, CEF string, Syslog string, or free text.

        Returns:
            A :class:`LogEvent` with ``source_system="siem"``.
        """
        return _normalizer.normalize(raw_data, self.SOURCE_SYSTEM)
