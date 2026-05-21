"""
correlation/correlation_engine.py
────────────────────────────────────────────────────────────────────────────────
CorrelationEngine — groups related LogEvents into Incidents (Phase 3).

Design decisions:
  • Elasticsearch is the backend for finding related events and open incidents.
  • If ES is unavailable, find_related() returns [] and correlate() still creates
    a minimal incident from the triggering event — never crashes, never drops data.
  • Only HIGH/CRITICAL fidelity events trigger incident creation.
  • An existing OPEN incident for the same IP or user is reused (merged).
  • All ES calls inherit the try/except pattern from storage/es_client.py.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from models.incident import Incident
from correlation.mitre_mapper import mitre_mapper
from storage.es_client import es_client, INDEX_EVENTS, INDEX_INCIDENTS
from ingestion.schema import LogEvent

logger = logging.getLogger(__name__)

# ── Phase 4 — lazy import of IR agent dispatcher ──────────────────────────────
# Wrapped in try/except so the correlation engine boots even if Phase 4
# dependencies (langgraph, transformers) are not yet installed.
try:
    from agents.agent_dispatcher import agent_dispatcher as _agent_dispatcher
    _AGENT_AVAILABLE = True
except Exception as _agent_import_err:  # noqa: BLE001
    _agent_dispatcher = None  # type: ignore[assignment]
    _AGENT_AVAILABLE  = False
    logger.info(
        "[CorrelationEngine] Phase 4 IR agent not available: %s — "
        "continuing without autonomous response.",
        _agent_import_err,
    )

# ── Tier ordering for severity comparison ────────────────────────────────────
_TIER_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class CorrelationEngine:
    """Groups correlated security events into structured Incident records.

    Usage::

        engine = CorrelationEngine()
        incident = engine.correlate(log_event, fidelity_result)
        # incident is None for LOW/MEDIUM events
    """

    # ── Event retrieval ───────────────────────────────────────────────────────

    def find_related(
        self,
        log_event: LogEvent,
        window_hours: int = 24,
    ) -> List[LogEvent]:
        """Query Elasticsearch for events related to *log_event*.

        Searches for events sharing:
          • same source_ip in the last *window_hours*
          • same user_id  in the last 48 h
          • same event_type (attack type) in the last 1 h, any source_system

        Returns:
            List of :class:`~ingestion.schema.LogEvent` objects reconstructed
            from ES _source documents.  Returns [] if ES is unavailable.
        """
        related: List[LogEvent] = []
        now_iso = datetime.utcnow().isoformat() + "Z"

        # ── Query 1: same source_ip in window ─────────────────────────────────
        if log_event.source_ip and log_event.source_ip != "0.0.0.0":
            since_ip = (datetime.utcnow() - timedelta(hours=window_hours)).isoformat() + "Z"
            ip_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term":  {"source_ip": log_event.source_ip}},
                            {"range": {"timestamp": {"gte": since_ip, "lte": now_iso}}},
                        ],
                        "must_not": [
                            {"term": {"event_id": log_event.event_id}}
                        ],
                    }
                }
            }
            docs = es_client.search_events(ip_query, index=INDEX_EVENTS, size=50)
            related.extend(self._docs_to_events(docs))

        # ── Query 2: same user_id in 48 h ─────────────────────────────────────
        if log_event.user_id:
            since_user = (datetime.utcnow() - timedelta(hours=48)).isoformat() + "Z"
            user_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term":  {"user_id": log_event.user_id}},
                            {"range": {"timestamp": {"gte": since_user, "lte": now_iso}}},
                        ],
                        "must_not": [
                            {"term": {"event_id": log_event.event_id}}
                        ],
                    }
                }
            }
            docs = es_client.search_events(user_query, index=INDEX_EVENTS, size=50)
            related.extend(self._docs_to_events(docs))

        # ── Query 3: same event_type in last 1 h ──────────────────────────────
        if log_event.event_type and log_event.event_type not in ("generic", "unstructured"):
            since_type = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
            type_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term":  {"event_type": log_event.event_type}},
                            {"range": {"timestamp": {"gte": since_type, "lte": now_iso}}},
                        ],
                        "must_not": [
                            {"term": {"event_id": log_event.event_id}}
                        ],
                    }
                }
            }
            docs = es_client.search_events(type_query, index=INDEX_EVENTS, size=20)
            related.extend(self._docs_to_events(docs))

        # Deduplicate by event_id
        seen_ids: set = {log_event.event_id}
        unique: List[LogEvent] = []
        for ev in related:
            if ev.event_id not in seen_ids:
                seen_ids.add(ev.event_id)
                unique.append(ev)

        return unique

    def _docs_to_events(self, docs: List[Dict[str, Any]]) -> List[LogEvent]:
        """Convert ES _source dicts to LogEvent objects, skipping bad docs."""
        events: List[LogEvent] = []
        for doc in docs:
            try:
                events.append(LogEvent.from_dict(doc))
            except Exception as exc:
                logger.debug("[CorrelationEngine] Skipping malformed ES doc: %s", exc)
        return events

    # ── Existing incident lookup ──────────────────────────────────────────────

    def _find_open_incident(self, log_event: LogEvent) -> Optional[Incident]:
        """Query ES for an OPEN incident matching the same IP or user."""
        queries = []
        if log_event.source_ip and log_event.source_ip != "0.0.0.0":
            queries.append({"term": {"related_ips": log_event.source_ip}})
        if log_event.user_id:
            queries.append({"term": {"related_users": log_event.user_id}})

        if not queries:
            return None

        try:
            q = {
                "query": {
                    "bool": {
                        "must":   [{"term": {"status": "OPEN"}}],
                        "should": queries,
                        "minimum_should_match": 1,
                    }
                },
                "sort": [{"created_at": {"order": "desc"}}],
            }
            docs = es_client.search_events(q, index=INDEX_INCIDENTS, size=1)
            if docs:
                return Incident.from_es_doc(docs[0])
        except Exception as exc:
            logger.debug("[CorrelationEngine] _find_open_incident error: %s", exc)
        return None

    # ── Main correlate method ─────────────────────────────────────────────────

    def correlate(
        self,
        log_event: LogEvent,
        fidelity_result,          # FidelityResult from Phase 2
    ) -> Optional[Incident]:
        """Correlate *log_event* into an Incident.

        Only HIGH or CRITICAL fidelity events create / update incidents.

        Args:
            log_event:      Canonical :class:`~ingestion.schema.LogEvent`.
            fidelity_result: :class:`~detection.fidelity_ranker.FidelityResult`
                             from the ensemble ranker.

        Returns:
            The created or updated :class:`~models.incident.Incident`, or
            ``None`` if the event does not warrant an incident.
        """
        tier = getattr(fidelity_result, "tier", "LOW")
        if tier not in ("HIGH", "CRITICAL"):
            return None

        try:
            # ── Step 1: Find related events ───────────────────────────────────
            related_events = self.find_related(log_event)
            all_events = [log_event] + related_events

            # ── Step 2: Check for existing open incident ──────────────────────
            incident = self._find_open_incident(log_event)
            is_new   = incident is None

            if is_new:
                incident = Incident(severity=tier)
            else:
                incident.upgrade_severity(tier)

            # ── Step 3: Build / update timeline ──────────────────────────────
            # Sort events by timestamp
            def _ts_key(ev):
                ts = getattr(ev, "timestamp", None)
                return ts if isinstance(ts, datetime) else datetime.utcnow()

            all_events_sorted = sorted(all_events, key=_ts_key)

            for ev in all_events_sorted:
                description = self._describe_event(ev)
                if ev.event_id not in incident.related_event_ids:
                    incident.add_event(
                        event_id=ev.event_id,
                        description=description,
                        timestamp=ev.timestamp if isinstance(ev.timestamp, datetime)
                                  else datetime.utcnow(),
                    )

            # ── Step 4: Merge IPs, users, systems, MITRE ─────────────────────
            for ev in all_events:
                incident.merge_ip(ev.source_ip)
                incident.merge_user(str(ev.user_id) if ev.user_id else "")
                incident.merge_system(ev.source_system)

                # MITRE mapping per event
                techniques = mitre_mapper.map_from_event(ev)
                incident.add_mitre(techniques)

            # ── Step 5: Generate / update title ──────────────────────────────
            attack_type = (
                log_event.event_type
                or (related_events[0].event_type if related_events else "UNKNOWN")
            )
            n_events = len(incident.related_event_ids)
            ip_display = log_event.source_ip or "unknown"
            incident.title = (
                f"{attack_type.upper()} from {ip_display} — {n_events} event(s)"
            )

            # ── Step 6: Build attack chain (ordered technique names) ──────────
            incident.attack_chain = self._build_attack_chain(
                incident.mitre_techniques
            )

            # ── Step 7: Index to Elasticsearch ───────────────────────────────
            try:
                es_client.index_incident(incident.to_es_doc())
            except Exception as exc:
                logger.warning("[CorrelationEngine] ES index_incident failed: %s", exc)

            logger.info(
                "[CorrelationEngine] %s incident %s — %d events, tier=%s",
                "Created" if is_new else "Updated",
                incident.incident_id, n_events, tier,
            )

            # ── Phase 4: non-blocking IR agent dispatch ───────────────────────
            # Only HIGH/CRITICAL reach here (gate is at the top of correlate()).
            # The dispatch() call is fire-and-forget; any error is swallowed so
            # it can NEVER affect the correlation return value.
            if _AGENT_AVAILABLE and _agent_dispatcher is not None:
                try:
                    _agent_dispatcher.dispatch(incident)
                except Exception as _disp_exc:  # noqa: BLE001
                    logger.warning(
                        "[CorrelationEngine] Agent dispatch failed for %s: %s",
                        incident.incident_id, _disp_exc,
                    )

            return incident

        except Exception as exc:
            logger.error("[CorrelationEngine] correlate() error: %s", exc)
            return None

    # ── Private helpers ───────────────────────────────────────────────────────

    def _describe_event(self, ev: LogEvent) -> str:
        """Generate a one-line description for a timeline entry."""
        parts = [
            f"[{ev.source_system.upper()}]",
            ev.event_type or "event",
            f"from {ev.source_ip}",
        ]
        if ev.user_id:
            parts.append(f"(user: {ev.user_id})")
        if ev.action and ev.action != "none":
            parts.append(f"→ {ev.action}")
        return " ".join(parts)

    def _build_attack_chain(self, technique_ids: List[str]) -> List[str]:
        """Return human-readable attack-chain descriptions sorted by tactic."""
        chain: List[str] = []
        for tid in technique_ids:
            tech = mitre_mapper.get_technique(tid)
            if tech:
                chain.append(f"{tid}: {tech.get('name', '')} ({tech.get('tactic', '')})")
            else:
                chain.append(tid)
        return chain


# Module-level singleton
correlation_engine = CorrelationEngine()
