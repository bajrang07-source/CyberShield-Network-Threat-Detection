"""
ingestion/edr_ingestor.py
────────────────────────────────────────────────────────────────────────────────
EdrIngestor — thin routing wrapper for EDR-sourced events.

Accepts the raw telemetry from an Endpoint Detection and Response agent
(dict, CEF, Syslog, or free text) and produces a normalised LogEvent tagged
source_system="edr".
"""
from __future__ import annotations

from ingestion.log_normalizer import LogNormalizer
from ingestion.schema import LogEvent

_normalizer = LogNormalizer()


class EdrIngestor:
    """Ingest raw EDR events into canonical LogEvents."""

    SOURCE_SYSTEM = "edr"

    def ingest(self, raw_data) -> LogEvent:
        """Normalise *raw_data* and return a :class:`LogEvent`.

        Args:
            raw_data: dict, CEF string, Syslog string, or free text.

        Returns:
            A :class:`LogEvent` with ``source_system="edr"``.
        """
        return _normalizer.normalize(raw_data, self.SOURCE_SYSTEM)
