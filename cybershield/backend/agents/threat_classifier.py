"""
agents/threat_classifier.py
────────────────────────────────────────────────────────────────────────────────
ThreatClassifier — categorises incidents using a local HuggingFace model,
with a rule-based fallback when the model is absent.

Phase 4, Step 1.

Design:
  • Attempts to load a text-classification pipeline from /models/distilbert-cybersec/
    with TRANSFORMERS_OFFLINE=1 respect (no external downloads).
  • If the model directory does not exist or transformers is not installed,
    silently falls back to MITRE-technique-based rule classification.
  • classify() NEVER raises — it always returns a ThreatCategory.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── HuggingFace model path ────────────────────────────────────────────────────
_MODEL_PATH = os.getenv("DISTILBERT_MODEL_PATH", "/models/distilbert-cybersec")

# ── Valid threat categories ───────────────────────────────────────────────────
CATEGORY_WEB_ATTACK     = "web_attack"
CATEGORY_INSIDER_THREAT = "insider_threat"
CATEGORY_RANSOMWARE     = "ransomware"
CATEGORY_APT            = "apt"
CATEGORY_BRUTEFORCE     = "bruteforce"
CATEGORY_UNKNOWN        = "unknown"

# ── MITRE technique → category mapping (rule-based fallback) ─────────────────
_MITRE_TO_CATEGORY: Dict[str, str] = {
    # Brute-force family
    "T1110":     CATEGORY_BRUTEFORCE,
    "T1110.001": CATEGORY_BRUTEFORCE,
    "T1110.003": CATEGORY_BRUTEFORCE,
    # Command & Scripting → web attack
    "T1059":     CATEGORY_WEB_ATTACK,
    "T1059.001": CATEGORY_WEB_ATTACK,
    "T1059.003": CATEGORY_WEB_ATTACK,
    "T1059.006": CATEGORY_WEB_ATTACK,
    # Ransomware / impact
    "T1486":     CATEGORY_RANSOMWARE,
    # Web application exploitation
    "T1190":     CATEGORY_WEB_ATTACK,
    "T1083":     CATEGORY_WEB_ATTACK,
    # Insider / valid account abuse
    "T1078":     CATEGORY_INSIDER_THREAT,
    "T1078.001": CATEGORY_INSIDER_THREAT,
    "T1098":     CATEGORY_INSIDER_THREAT,
    "T1136":     CATEGORY_INSIDER_THREAT,
    # Data exfiltration (often insider / APT)
    "T1041":     CATEGORY_APT,
    "T1567":     CATEGORY_APT,
    # Lateral movement → APT
    "T1021":     CATEGORY_APT,
    "T1021.001": CATEGORY_APT,
    "T1021.004": CATEGORY_APT,
    # Process injection → APT
    "T1055":     CATEGORY_APT,
    # Credential dumping → APT
    "T1003":     CATEGORY_APT,
    # Default — remaining techniques → APT
}


@dataclass
class ThreatCategory:
    """Output of ThreatClassifier.classify()."""
    category:   str           # one of the CATEGORY_* constants above
    confidence: float         # 0.0 – 1.0
    method:     str = "rule"  # "model" or "rule"


class ThreatClassifier:
    """Classifies incidents into threat categories.

    Tries to load a local HuggingFace text-classification model.
    Falls back to a MITRE-technique-based rule engine if the model
    is unavailable or transformers is not installed.

    Usage::

        classifier = ThreatClassifier()
        incident_dict = incident.to_dict()
        result = classifier.classify(incident_dict)
        print(result.category, result.confidence)
    """

    def __init__(self) -> None:
        self._pipeline = None
        self._load_model()

    # ── Model loading ─────────────────────────────────────────────────────────

    def _load_model(self) -> None:
        """Attempt to load the local HuggingFace pipeline (best-effort)."""
        if not os.path.isdir(_MODEL_PATH):
            logger.warning(
                "[ThreatClassifier] Model dir not found: %s — using rule-based fallback.",
                _MODEL_PATH,
            )
            return

        try:
            # Respect offline mode — prevent accidental network calls
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            from transformers import pipeline as hf_pipeline  # type: ignore
            self._pipeline = hf_pipeline(
                "text-classification",
                model=_MODEL_PATH,
                device=-1,           # CPU only
                truncation=True,
                max_length=512,
            )
            logger.info("[ThreatClassifier] HuggingFace model loaded from %s.", _MODEL_PATH)
        except Exception as exc:
            logger.warning(
                "[ThreatClassifier] Failed to load HuggingFace model: %s — using rule-based fallback.",
                exc,
            )
            self._pipeline = None

    # ── Public interface ──────────────────────────────────────────────────────

    def classify(self, incident: Dict[str, Any]) -> ThreatCategory:
        """Classify an incident dict into a ThreatCategory.

        Args:
            incident: Dictionary (e.g. from ``Incident.to_dict()``).

        Returns:
            :class:`ThreatCategory` — never raises.
        """
        try:
            if self._pipeline is not None:
                return self._classify_with_model(incident)
            return self._classify_with_rules(incident)
        except Exception as exc:
            logger.error("[ThreatClassifier] classify() error: %s", exc)
            return ThreatCategory(category=CATEGORY_UNKNOWN, confidence=0.0, method="error")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _classify_with_model(self, incident: Dict[str, Any]) -> ThreatCategory:
        """Use the HuggingFace pipeline for classification."""
        text = self._build_text(incident)
        result = self._pipeline(text)[0]  # [{label: ..., score: ...}]
        # Map model label to our category constants (best-effort)
        label = result.get("label", "").lower()
        category = self._normalise_label(label)
        confidence = float(result.get("score", 0.5))
        return ThreatCategory(category=category, confidence=confidence, method="model")

    def _classify_with_rules(self, incident: Dict[str, Any]) -> ThreatCategory:
        """Rule-based fallback using MITRE techniques from the incident."""
        techniques: List[str] = incident.get("mitre_techniques", [])
        # Walk technique list; pick the first category match by priority
        for tech in techniques:
            category = _MITRE_TO_CATEGORY.get(tech)
            if category:
                return ThreatCategory(
                    category=category,
                    confidence=0.75,
                    method="rule",
                )

        # Fall back to title/event-type heuristics
        title = (incident.get("title", "") or "").lower()
        attack_chain = " ".join(incident.get("attack_chain", [])).lower()
        combined = title + " " + attack_chain

        if any(w in combined for w in ("brute", "password", "spray", "credential")):
            return ThreatCategory(category=CATEGORY_BRUTEFORCE, confidence=0.6, method="rule")
        if any(w in combined for w in ("ransom", "encrypt", "locked")):
            return ThreatCategory(category=CATEGORY_RANSOMWARE, confidence=0.6, method="rule")
        if any(w in combined for w in ("sql", "xss", "injection", "traversal", "exploit")):
            return ThreatCategory(category=CATEGORY_WEB_ATTACK, confidence=0.6, method="rule")
        if any(w in combined for w in ("insider", "exfil", "leak", "data_transfer")):
            return ThreatCategory(category=CATEGORY_INSIDER_THREAT, confidence=0.6, method="rule")

        return ThreatCategory(category=CATEGORY_APT, confidence=0.4, method="rule")

    @staticmethod
    def _build_text(incident: Dict[str, Any]) -> str:
        """Construct the text string fed to the HuggingFace model."""
        title       = incident.get("title", "")
        timeline    = incident.get("timeline", [])[:3]
        descriptions = [t.get("description", "") for t in timeline]
        return f"{title}. " + " ".join(descriptions)

    @staticmethod
    def _normalise_label(label: str) -> str:
        """Map HuggingFace label to our known category constants."""
        label_map = {
            "web_attack":     CATEGORY_WEB_ATTACK,
            "insider_threat": CATEGORY_INSIDER_THREAT,
            "ransomware":     CATEGORY_RANSOMWARE,
            "apt":            CATEGORY_APT,
            "bruteforce":     CATEGORY_BRUTEFORCE,
            "brute_force":    CATEGORY_BRUTEFORCE,
        }
        # Try direct match first, then partial
        if label in label_map:
            return label_map[label]
        for key, val in label_map.items():
            if key in label:
                return val
        return CATEGORY_APT  # default to APT if label is unrecognised


# ── Module-level singleton ─────────────────────────────────────────────────────
threat_classifier = ThreatClassifier()
