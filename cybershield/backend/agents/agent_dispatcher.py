"""
agents/agent_dispatcher.py
────────────────────────────────────────────────────────────────────────────────
AgentDispatcher — thread-pool wrapper around the IR agent.

Phase 4, Step 4.

Design:
  • Max 3 concurrent agent executions (thread pool).
  • dispatch() is non-blocking — it submits to the pool and returns immediately.
  • On completion, the incident playbook is updated in Elasticsearch.
  • All errors are logged; none propagate to the caller.
  • Safe to import even when LangGraph / Ollama are absent.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Thread pool ───────────────────────────────────────────────────────────────
_POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix="ir_agent")


class AgentDispatcher:
    """Non-blocking dispatcher that runs the IR agent in a background thread.

    Usage::

        from agents.agent_dispatcher import agent_dispatcher
        from models.incident import Incident

        incident: Incident = ...
        agent_dispatcher.dispatch(incident)   # returns immediately
    """

    # ── Public interface ──────────────────────────────────────────────────────

    def dispatch(self, incident) -> Optional[Future]:
        """Submit an IR-agent run for *incident* to the thread pool.

        Args:
            incident: An :class:`~models.incident.Incident` instance.

        Returns:
            A :class:`concurrent.futures.Future` (the caller may ignore it),
            or ``None`` if submission fails.
        """
        try:
            inc_dict = incident.to_dict()
            inc_id   = inc_dict.get("incident_id", "unknown")
            severity = inc_dict.get("severity", "UNKNOWN")

            logger.info(
                "[AgentDispatcher] Dispatching IR agent for incident %s (severity=%s)",
                inc_id, severity,
            )

            future = _POOL.submit(self._run_agent, inc_dict)
            future.add_done_callback(lambda f: self._on_complete(f, inc_id))
            return future

        except Exception as exc:
            logger.error("[AgentDispatcher] dispatch() failed: %s", exc)
            return None

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _run_agent(incident_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the IR agent graph (runs inside a thread)."""
        from agents.ir_agent import run_ir_agent  # local import to avoid circular deps
        inc_id = incident_dict.get("incident_id", "unknown")
        logger.info("[AgentDispatcher] IR agent thread started for %s", inc_id)
        result = run_ir_agent(incident_dict)
        logger.info(
            "[AgentDispatcher] IR agent finished for %s — status=%s",
            inc_id, result.get("status"),
        )
        return result

    @staticmethod
    def _on_complete(future: Future, inc_id: str) -> None:
        """Callback executed when the agent future resolves."""
        try:
            if future.exception():
                logger.error(
                    "[AgentDispatcher] Agent future raised exception for %s: %s",
                    inc_id, future.exception(),
                )
                return

            result   = future.result()
            playbook = result.get("playbook", "")
            status   = result.get("status", "unknown")

            if not playbook:
                logger.warning("[AgentDispatcher] No playbook in result for %s", inc_id)
                return

            # ── Persist playbook back to Elasticsearch ────────────────────────
            try:
                from storage.es_client import es_client, INDEX_INCIDENTS  # type: ignore
                if es_client.is_connected:
                    doc = {
                        "incident_id": inc_id,
                        "playbook":    playbook,
                        "status":      "PENDING_ANALYST",
                        "updated_at":  datetime.utcnow().isoformat() + "Z",
                    }
                    # Use update via index (upsert pattern)
                    es_client.index_incident(doc)
                    logger.info(
                        "[AgentDispatcher] Playbook persisted to ES for incident %s", inc_id
                    )
            except Exception as es_exc:
                logger.warning(
                    "[AgentDispatcher] ES persistence failed for %s: %s", inc_id, es_exc
                )

        except Exception as exc:
            logger.error("[AgentDispatcher] _on_complete() error for %s: %s", inc_id, exc)


# ── Module-level singleton ─────────────────────────────────────────────────────
agent_dispatcher = AgentDispatcher()
