"""
PAnGEA — Grounder shared models.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


@dataclass
class Actor:
    actor_id: str
    role: str
    description_ref: str = ""
    # --- populated by Evidence Matcher, never by Step Extractor (R2-style
    # separation: Step Extractor sees text only, has no evidence basis to
    # assign an IP) ---
    resolved_endpoints: list[str] = field(default_factory=list)
    resolution_basis: Optional[str] = None
    # NOTE: deliberately no numeric confidence field. A heuristic-derived
    # score isn't indicative of anything until it's been checked against
    # labeled ground truth (see Evaluator design) -- adding one now would
    # look more rigorous than it actually is. resolution_basis still
    # carries a textual rationale for auditability; that's not a
    # substitute for a real calibrated score, just a different thing.


@dataclass
class ExpectedIndicators:
    protocol: Optional[str] = None
    port: Optional[int] = None
    flags: Optional[list[str]] = None
    direction: Optional[str] = None            # e.g. "attacker->victim", in actor_id terms
    volume_pattern: Optional[str] = None        # e.g. "high", "burst", "steady", "low"
    cardinality_pattern: Optional[str] = None   # e.g. "one-to-many", "many-to-one", "one-to-one"
    indicator_description: Optional[str] = None
    # Optional literal-text IP hint, only when the description names an IP
    # explicitly. NOT used as a fingerprint lookup key (the Reducer's
    # fingerprint_index is deliberately IP-agnostic) -- only usable as a
    # post-match filter against a candidate item's src/dst.
    ip_hint: Optional[str] = None


@dataclass
class Step:
    step_id: str
    text: str
    expected_indicators: ExpectedIndicators
    actor_refs: list[str] = field(default_factory=list)


class GroundingStatus(str, Enum):
    GROUNDED = "grounded"
    UNSUPPORTED = "unsupported"
    UNCERTAIN_NEEDS_DRILLDOWN = "uncertain_needs_drilldown"


@dataclass
class LinkedPacketRef:
    packet_id: int
    timestamp: str
    protocol: str = ""
    src: str = ""
    dst: str = ""
    length: int = 0
    info: str = ""


@dataclass
class LinkedAggregateRef:
    fingerprint_key: str
    count: int
    unique_sources: list[str]
    unique_destinations: list[str]


@dataclass
class Grounding:
    status: GroundingStatus
    linked_packets: list[LinkedPacketRef] = field(default_factory=list)
    linked_aggregate_refs: list[LinkedAggregateRef] = field(default_factory=list)
    notes: str = ""
    # NOTE: deliberately no numeric confidence field, for the same reason
    # as Actor.resolution_basis above -- see that comment. `status` +
    # `notes` carry everything Evidence Matcher can currently justify;
    # a calibrated confidence score is future work, gated on the
    # Evaluator producing labeled accuracy data to calibrate against.


@dataclass
class GroundedStep:
    step: Step
    grounding: Grounding


# --------------------------------------------------------------------------
# Evidence Matcher's OWN evidence types.
#
# Deliberately NOT the same classes as preprocessing.schemas.ReducedItem /
# AggregateRef -- Evidence Matcher must not depend on the preprocessing
# package at all. Whatever produced the evidence (today: Preprocessing's
# Reducer; potentially something else later) is the orchestrator/main
# function's concern, not this component's. The orchestrator is
# responsible for adapting Preprocessing's actual ReducerOutput into these
# minimal shapes before calling EvidenceMatcher.match() -- see
# orchestrator.py's adapt_reducer_output() for that adapter. Kept minimal
# deliberately -- extra fields (protocol/src/dst/length/info) were tried
# and reverted, since nothing in Evidence Matcher's logic reads them; if
# a real need for them comes up, add it back then, driven by actual usage.
# --------------------------------------------------------------------------

@dataclass
class EvidenceAggregate:
    """Aggregate statistics for a fingerprint/pattern -- the minimal shape
    Evidence Matcher needs from an aggregation stage, independent of its
    origin."""
    fingerprint_key: str
    count: int
    unique_sources: list[str]
    unique_destinations: list[str]


@dataclass
class EvidenceItem:
    """
    One retained item of traffic evidence.

    REVERSED from an earlier minimal version (packet_id/timestamp/
    fingerprint_key only) -- that trim meant Evidence Matcher's own raw
    items carried no more per-packet detail than the aggregate stats
    already provided, which turned out to matter: real per-packet
    attribution (who actually sent this specific packet, not just "some
    IP in this aggregate's unique_sources") is exactly the kind of detail
    a human (or an LLM given raw PCAP directly) uses to resolve actors
    correctly, and aggregation destroys it. Deliberately carries the same
    fields as preprocessing.schemas.ReducedItem (protocol/src/dst/length/
    info) -- but remains its OWN class, not an import of that one: Evidence
    Matcher must not depend on the preprocessing package (see this
    module's other evidence types and evidence_matcher.py's docstring for
    why). Whoever adapts a real ReducerOutput into this shape (today: the
    orchestrator) is responsible for populating every field.
    """
    packet_id: int
    timestamp: str            # ISO-8601, preserves original capture order
    protocol: str
    src: str
    dst: str
    length: int
    info: str
    fingerprint_key: str


# --------------------------------------------------------------------------
# Top-level Grounder output
# --------------------------------------------------------------------------

@dataclass
class MatchingResult:
    """
    Top-level output of Grounder.run() -- the "Matching JSON" per spec:
    actors[] (role -> IP mapping) and claims[] (claim -> grounding).
    claims here is list[GroundedStep] -- matches EvidenceMatcher.match()'s
    second return value exactly (each entry already carries its Grounding
    result, not just the pre-grounding Step).
    """
    actors: list[Actor]
    claims: list[GroundedStep]

    def to_dict(self) -> dict:
        from dataclasses import asdict

        def _grounded_step_to_dict(gs: GroundedStep) -> dict:
            d = asdict(gs)
            d["grounding"]["status"] = gs.grounding.status.value
            return d

        return {
            "actors": [asdict(a) for a in self.actors],
            "claims": [_grounded_step_to_dict(gs) for gs in self.claims],
        }