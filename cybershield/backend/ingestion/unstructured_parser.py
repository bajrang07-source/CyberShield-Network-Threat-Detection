"""
ingestion/unstructured_parser.py
────────────────────────────────────────────────────────────────────────────────
UnstructuredParser — thin routing wrapper for arbitrary / free-text log lines.

Accepts raw strings or dicts from system logs, application logs, or any other
source that does not conform to a structured format.  Produces a normalised
LogEvent tagged source_system="system_log".

The LogNormalizer will automatically fall through to its unstructured handler
for string input that is not CEF or Syslog.
"""
from __future__ import annotations

from ingestion.log_normalizer import LogNormalizer
from ingestion.schema import LogEvent

_normalizer = LogNormalizer()


class UnstructuredParser:
    """Ingest unstructured / free-text log lines into canonical LogEvents."""

    SOURCE_SYSTEM = "system_log"

    def ingest(self, raw_data) -> LogEvent:
        """Normalise *raw_data* and return a :class:`LogEvent`.

        Args:
            raw_data: Any string, dict, or object.  String inputs are treated
                      as free-text; the normalizer will extract IPs if present
                      and set event_type="unstructured".

        Returns:
            A :class:`LogEvent` with ``source_system="system_log"``.
        """
        return _normalizer.normalize(raw_data, self.SOURCE_SYSTEM)
