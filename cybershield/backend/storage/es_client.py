"""
storage/es_client.py
────────────────────────────────────────────────────────────────────────────────
Elasticsearch storage backend — ADDITIONAL to SQLite, never a replacement.

All public methods are wrapped in try/except.  If Elasticsearch is unavailable
the methods return a safe sentinel value (False / [] / None) and log a warning.
The application NEVER crashes due to ES errors.

Usage::

    from storage.es_client import es_client      # singleton

    ok = es_client.index_event(log_event)
    results = es_client.search_events({"query": {"match_all": {}}})
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Index name constants ──────────────────────────────────────────────────────
INDEX_EVENTS    = "cybershield-events"
INDEX_INCIDENTS = "cybershield-incidents"

# ── Lazy ES import so the app boots even if elasticsearch-py is not installed ─
try:
    from elasticsearch import Elasticsearch, NotFoundError  # type: ignore
    _ES_AVAILABLE = True
except ImportError:
    Elasticsearch = None          # type: ignore[assignment,misc]
    NotFoundError = Exception     # type: ignore[assignment,misc]
    _ES_AVAILABLE = False
    logger.warning(
        "[ESClient] 'elasticsearch' package not installed. "
        "All ES calls will be silently skipped.  "
        "Install with: pip install elasticsearch"
    )


class ElasticsearchClient:
    """Thin wrapper around the official elasticsearch-py client.

    Connection is attempted once at instantiation.  Any subsequent call that
    finds ``self._es`` is None returns a safe sentinel without raising.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 9200,
        scheme: str = "http",
    ) -> None:
        self._es = None
        if not _ES_AVAILABLE:
            return

        try:
            client = Elasticsearch(
                [{"host": host, "port": port, "scheme": scheme}],
                request_timeout=5,
                max_retries=1,
                retry_on_timeout=False,
            )
            # Verify connectivity
            if client.ping():
                self._es = client
                logger.info(
                    "[ESClient] Connected to Elasticsearch at %s://%s:%d",
                    scheme, host, port,
                )
            else:
                logger.warning(
                    "[ESClient] Ping failed — Elasticsearch unreachable at "
                    "%s://%s:%d.  Continuing without ES.",
                    scheme, host, port,
                )
        except Exception as exc:
            logger.warning(
                "[ESClient] Could not connect to Elasticsearch: %s. "
                "Continuing without ES.",
                exc,
            )

    # ── Public interface ──────────────────────────────────────────────────────

    def index_event(self, log_event) -> bool:
        """Index a :class:`~ingestion.schema.LogEvent` into Elasticsearch.

        Args:
            log_event: A LogEvent instance.  Must expose a ``.to_dict()``
                       method and an ``event_id`` attribute.

        Returns:
            True on success, False if ES is unavailable or the call failed.
        """
        if self._es is None:
            return False
        try:
            doc = log_event.to_dict()
            self._es.index(
                index=INDEX_EVENTS,
                id=log_event.event_id,
                document=doc,
            )
            return True
        except Exception as exc:
            logger.warning("[ESClient] index_event failed: %s", exc)
            return False

    def index_incident(self, incident: Dict[str, Any]) -> bool:
        """Index a raw incident dict (e.g. from threat_service) into ES.

        Args:
            incident: Dictionary that MUST contain an ``"id"`` key used as the
                      document ID.

        Returns:
            True on success, False otherwise.
        """
        if self._es is None:
            return False
        try:
            doc_id = str(incident.get("id", ""))
            self._es.index(
                index=INDEX_INCIDENTS,
                id=doc_id or None,
                document=incident,
            )
            return True
        except Exception as exc:
            logger.warning("[ESClient] index_incident failed: %s", exc)
            return False

    def search_events(
        self,
        query: Dict[str, Any],
        index: str = INDEX_EVENTS,
        size: int = 100,
    ) -> List[Dict[str, Any]]:
        """Execute a DSL query and return a list of source documents.

        Args:
            query: Elasticsearch DSL query body (e.g. ``{"query": {...}}``).
            index: Target index name.  Defaults to ``cybershield-events``.
            size:  Maximum number of hits to return.

        Returns:
            List of ``_source`` dicts.  Empty list on any error.
        """
        if self._es is None:
            return []
        try:
            resp = self._es.search(index=index, body=query, size=size)
            hits = resp.get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception as exc:
            logger.warning("[ESClient] search_events failed: %s", exc)
            return []

    def get_event_by_id(
        self,
        event_id: str,
        index: str = INDEX_EVENTS,
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single document by its ID.

        Args:
            event_id: The Elasticsearch document ``_id``.
            index:    Target index.

        Returns:
            The ``_source`` dict if found, ``None`` otherwise.
        """
        if self._es is None:
            return None
        try:
            doc = self._es.get(index=index, id=event_id)
            return doc.get("_source")
        except NotFoundError:
            return None
        except Exception as exc:
            logger.warning("[ESClient] get_event_by_id failed: %s", exc)
            return None

    @property
    def is_connected(self) -> bool:
        """True if a live ES connection is available."""
        return self._es is not None


# ── Module-level singleton ─────────────────────────────────────────────────────
es_client = ElasticsearchClient()
