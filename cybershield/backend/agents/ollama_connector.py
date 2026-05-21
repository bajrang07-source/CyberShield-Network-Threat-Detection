"""
agents/ollama_connector.py
────────────────────────────────────────────────────────────────────────────────
OllamaConnector — HTTP client for a locally running Ollama instance.

Phase 4, Step 2.

Design:
  • 100% offline — all LLM inference goes to http://localhost:11434.
  • If Ollama is unreachable (timeout, connection refused) the connector
    returns FALLBACK_PLAYBOOK instead of raising.
  • is_available() can be called before generate() to check Ollama health.
  • Never raises — callers can always rely on a string return value.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

import requests  # already in requirements.txt

logger = logging.getLogger(__name__)

# ── Hardcoded fallback playbook ───────────────────────────────────────────────
FALLBACK_PLAYBOOK = """\
Ollama unavailable. Manual incident response playbook:

1. CONTAINMENT — Isolate affected system(s) from network immediately.
   - Block source IP at perimeter firewall and WAF.
   - Terminate active sessions of compromised user accounts.

2. EVIDENCE PRESERVATION — Do not power off systems.
   - Capture volatile memory dump (RAM) from affected hosts.
   - Preserve system logs, SIEM events, and network captures.
   - Create forensic disk image before any remediation.

3. CREDENTIAL RESET — Assume credentials are compromised.
   - Force password reset for all affected user accounts.
   - Revoke and rotate API keys, service account passwords.
   - Invalidate all active session tokens.

4. FIREWALL REVIEW — Tighten network access controls.
   - Audit firewall rules for the source IP and IP range.
   - Review and block any newly discovered malicious IP ranges.
   - Enable geo-blocking for high-risk jurisdictions if applicable.

5. STAKEHOLDER NOTIFICATION — Follow escalation matrix.
   - Notify CISO and Security Operations Manager immediately.
   - Escalate to senior management for CRITICAL severity incidents.
   - Prepare regulatory notification (RBI/SEBI) if customer data is involved.

6. TIMELINE DOCUMENTATION — Create an incident timeline record.
   - Document first detection timestamp, affected systems, and actions taken.
   - Record all decisions and approvals in the incident management system.
   - Schedule post-incident review within 5 business days.
"""


class OllamaConnector:
    """Thin HTTP client for a locally running Ollama server.

    Usage::

        connector = OllamaConnector()
        if connector.is_available():
            playbook = connector.generate("Your SOC prompt here")
        else:
            playbook = FALLBACK_PLAYBOOK
    """

    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        self.base_url = base_url.rstrip("/")

    # ── Public interface ──────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Check whether Ollama is reachable.

        Returns:
            True if the /api/tags endpoint responds within 3 seconds.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/api/tags",
                timeout=3,
            )
            return resp.status_code == 200
        except Exception as exc:
            logger.debug("[OllamaConnector] is_available() → False: %s", exc)
            return False

    def generate(
        self,
        prompt: str,
        model: str = "mistral",
    ) -> str:
        """Send a generation request to Ollama.

        Args:
            prompt: The full text prompt to send to the model.
            model:  Ollama model tag (default: "mistral").

        Returns:
            The generated text string, or :data:`FALLBACK_PLAYBOOK` if
            Ollama is unreachable, times out, or returns an error.
        """
        payload = {
            "model":  model,
            "prompt": prompt,
            "stream": False,
        }
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            result = data.get("response", "").strip()
            if not result:
                logger.warning("[OllamaConnector] Empty response from Ollama.")
                return FALLBACK_PLAYBOOK
            logger.info(
                "[OllamaConnector] Generated %d chars via model=%s.", len(result), model
            )
            return result
        except requests.exceptions.Timeout:
            logger.warning(
                "[OllamaConnector] Ollama generate() timed out (120s) — returning fallback."
            )
            return FALLBACK_PLAYBOOK
        except requests.exceptions.ConnectionError:
            logger.warning(
                "[OllamaConnector] Ollama unreachable at %s — returning fallback.", self.base_url
            )
            return FALLBACK_PLAYBOOK
        except Exception as exc:
            logger.warning("[OllamaConnector] generate() error: %s — returning fallback.", exc)
            return FALLBACK_PLAYBOOK

    def list_models(self) -> list:
        """Return available model tags from Ollama (best-effort)."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            resp.raise_for_status()
            return [m.get("name") for m in resp.json().get("models", [])]
        except Exception:
            return []


# ── Module-level singleton ─────────────────────────────────────────────────────
ollama_connector = OllamaConnector()
