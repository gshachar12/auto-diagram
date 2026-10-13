"""
PANGEA - Grounder stage.

Implements the LLM Grounder component of the PANGEA pipeline, per PANGEA_SPEC:

    Network Traffic Description ─┐
                                  ├─> Step Extractor  ─> Steps[] + actors[] (roles only)
    (text only, no PCAP access)  ┘
                                        │
    Reduced PCAP + Fingerprint_index ──┤
                                        ▼
                                Evidence Matcher ─> resolved actors + grounded Steps
                                        │
                                        ▼
                              Matching JSON (final Grounder output)

See legacy_grounder.py for the top-level (LLM) Grounder class that wires these together.
"""

from .legacy_grounder import Grounder
from .steps_extractor import StepExtractor
from .evidence_matcher import EvidenceMatcher
from .models import (
    Actor,
    Step,
    ExpectedIndicators,
    Grounding,
    GroundingStatus,
    MatchingResult,
)

__all__ = [
    "Grounder",
    "StepExtractor",
    "EvidenceMatcher",
    "Actor",
    "Step",
    "ExpectedIndicators",
    "Grounding",
    "GroundingStatus",
    "MatchingResult",
]
