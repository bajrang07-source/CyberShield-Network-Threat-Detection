"""
correlation/mitre_mapper.py
────────────────────────────────────────────────────────────────────────────────
MitreMapper — rule-based MITRE ATT&CK technique tagger (Phase 3).

Loads technique definitions from data/mitre_techniques.json.
Maps LogEvent fields (event_type, payload keywords, source_system) to
ATT&CK technique IDs using keyword matching.

No Flask, no SQLAlchemy, no existing CyberShield modules (pure logic).
Returns [] on any error — never crashes.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_MITRE_JSON_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "mitre_techniques.json",
)

# ── Hardcoded fast-path rules (supplement keyword matching) ───────────────────
# Format: (set_of_trigger_strings, list_of_technique_ids)
_FAST_RULES: List[tuple] = [
    # Web attacks → Exploit Public-Facing Application
    ({"sql_injection", "sqli"},                                ["T1190"]),
    ({"xss", "cross_site_scripting"},                         ["T1190", "T1059"]),
    ({"cmd_injection", "command_injection", "command_exec"},  ["T1059"]),
    ({"path_traversal", "directory_traversal"},               ["T1190", "T1083"]),
    ({"honeypot_trap", "honeypot"},                           ["T1190"]),
    # Auth attacks
    ({"brute_force", "login_fail", "authentication_failure",
      "login_failure_storm"},                                  ["T1110"]),
    ({"privilege_escalation", "valid_account"},               ["T1078"]),
    # Endpoint / EDR
    ({"powershell", "ps1", "invoke-expression", "iex"},       ["T1059.001"]),
    ({"process_injection", "dll_injection"},                  ["T1055"]),
    # Network / scanning
    ({"scanner", "port_scan", "route_enumeration"},           ["T1046", "T1083"]),
    ({"request_burst", "dos", "ddos"},                        ["T1499"]),
    # Lateral movement
    ({"lateral_movement", "remote_service", "rdp"},           ["T1021"]),
    ({"ssh_lateral", "ssh"},                                  ["T1021.004"]),
    # Exfil / impact
    ({"exfil", "data_leak", "exfiltration"},                  ["T1041"]),
    ({"ransomware", "encrypt"},                               ["T1486"]),
    ({"credential_dump", "mimikatz"},                         ["T1003"]),
]


class MitreMapper:
    """Rule-based MITRE ATT&CK technique mapper.

    Usage::

        mapper = MitreMapper()
        techniques = mapper.map_from_event(log_event)
        # e.g. ["T1190", "T1059"]
    """

    def __init__(self, json_path: str = _MITRE_JSON_PATH) -> None:
        self._techniques: List[Dict[str, Any]] = []
        self._keyword_index: Dict[str, List[str]] = {}   # keyword → [technique_ids]
        self._load(json_path)

    def _load(self, path: str) -> None:
        """Load and index the MITRE JSON catalogue."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            techniques = data.get("techniques", [])
            self._techniques = techniques

            # Build inverted keyword index
            for tech in techniques:
                tid = tech.get("id", "")
                for kw in tech.get("keywords", []):
                    kw_lower = kw.lower().strip()
                    if kw_lower:
                        self._keyword_index.setdefault(kw_lower, [])
                        if tid not in self._keyword_index[kw_lower]:
                            self._keyword_index[kw_lower].append(tid)

            logger.info(
                "[MitreMapper] Loaded %d techniques with %d keywords from %s",
                len(self._techniques), len(self._keyword_index), path,
            )
        except FileNotFoundError:
            logger.warning("[MitreMapper] Techniques file not found: %s", path)
        except Exception as exc:
            logger.warning("[MitreMapper] Failed to load techniques: %s", exc)

    # ── Public API ────────────────────────────────────────────────────────────

    def map_from_event(self, log_event) -> List[str]:
        """Map a LogEvent to a deduplicated list of MITRE technique IDs.

        Strategy:
          1. Collect searchable text from event_type, action, source_system,
             and payload values.
          2. Apply hardcoded fast-path rules (highest precedence).
          3. Apply keyword index from the JSON catalogue.
          4. Deduplicate and return sorted list.

        Returns:
            List of technique IDs (e.g. ["T1110", "T1190"]).
            Returns [] if no match or on any error.
        """
        try:
            # ── Build searchable text set ─────────────────────────────────────
            tokens: List[str] = []

            event_type    = str(getattr(log_event, "event_type", "") or "").lower()
            action        = str(getattr(log_event, "action",     "") or "").lower()
            source_system = str(getattr(log_event, "source_system", "") or "").lower()
            raw_data      = str(getattr(log_event, "raw_data",   "") or "").lower()

            tokens.append(event_type)
            tokens.append(action)
            tokens.append(source_system)

            payload = getattr(log_event, "payload", {}) or {}
            if isinstance(payload, dict):
                for v in payload.values():
                    tokens.append(str(v).lower())

            # Include raw_data (truncated to avoid performance issues)
            tokens.append(raw_data[:500])

            search_text = " ".join(tokens)

            # ── Fast-path rules ───────────────────────────────────────────────
            found: List[str] = []
            for trigger_set, technique_ids in _FAST_RULES:
                for trigger in trigger_set:
                    if trigger in search_text:
                        for tid in technique_ids:
                            if tid not in found:
                                found.append(tid)
                        break  # matched this rule — no need to check other triggers

            # ── Keyword index lookup ──────────────────────────────────────────
            for kw, tids in self._keyword_index.items():
                if kw in search_text:
                    for tid in tids:
                        if tid not in found:
                            found.append(tid)

            return sorted(set(found))

        except Exception as exc:
            logger.warning("[MitreMapper] map_from_event error: %s", exc)
            return []

    def get_technique(self, technique_id: str) -> Dict[str, Any]:
        """Return the full technique definition for a given ID, or {}."""
        for tech in self._techniques:
            if tech.get("id") == technique_id:
                return tech
        return {}

    @property
    def technique_count(self) -> int:
        return len(self._techniques)


# Module-level singleton
mitre_mapper = MitreMapper()
