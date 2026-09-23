"""
PAnGEA Evaluator -- data schemas.

These are intentionally decoupled from Grounder/models.py -- the Evaluator
must be able to score ANY system's output against gold, not just this
project's own EvidenceMatcher output, so it defines its own minimal input
shape and expects a small adapter (see run_evaluator.py's
`load_system_output_from_pipeline_json`) to translate this project's
actual JSON output into it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------
# Gold (manually annotated)
# --------------------------------------------------------------------------

@dataclass
class GoldActor:
    entity_id: str                  # internal label, never compared directly
    description_ref_gold: str       # text span/paraphrase this entity is known by
    ground_truth_ips: list[str] = field(default_factory=list)  # empty if genuinely unresolvable from traffic
    # NOTE: was a single Optional[str] -- confirmed against a real capture
    # that this is wrong for CDN/load-balanced services: reddit.com alone
    # was observed communicating over 15 distinct external IPs (AWS
    # application servers, Fastly CDN edges) in one real ARP-spoofing
    # capture. A single expected IP for such an entity would mark a
    # correct resolution as wrong just because the system picked a
    # different (also legitimate) IP for the same named service.


@dataclass
class GoldEvidenceRef:
    """
    One piece of gold-linked evidence for a claim: a fingerprint_key,
    optionally disambiguated by which specific destination it refers to.

    CRITICAL, confirmed on real data (ransomware capture): fingerprint_key
    is deliberately IP-agnostic (needed for scan/anomaly detection -- see
    evidence_matcher.py's _find_identity_fanout_anomalies), which means
    entirely different conversations to entirely different hosts can
    collapse into the IDENTICAL fingerprint_key. Confirmed directly: a
    lure-page fetch, a malware-payload download, and a C2 check-in -- three
    completely different real-world events -- all produced the exact same
    ["TCP",["0x0002","80"]] key, because none of the four distinct
    destination IPs involved are part of the key at all.

    flow_dst_ip disambiguates which specific destination this claim's
    evidence refers to, when more than one destination shares the same
    fingerprint_key in a capture. Leave as None only when genuinely
    unambiguous (e.g. only one destination exists for that fingerprint in
    this capture -- as with DNS tunneling, where this fix does NOT apply:
    there the ambiguity is the same single destination reused across many
    DIFFERENT claims over time, not multiple destinations sharing one key
    -- a different problem this field does not solve).
    """
    fingerprint_key: str
    flow_dst_ip: Optional[str] = None


@dataclass
class GoldClaim:
    claim_id: str
    text: str
    references_entities: list[str] = field(default_factory=list)  # GoldActor.entity_id values
    gold_grounding_status: str = "grounded"   # "grounded" | "unsupported" | "uncertain_needs_drilldown"
    gold_linked_evidence: list[GoldEvidenceRef] = field(default_factory=list)
    # RENAMED from gold_linked_fingerprint_keys -- now pairs each key with
    # an optional flow_dst_ip. See GoldEvidenceRef for why this changed.


@dataclass
class GoldSample:
    sample_id: str
    actors: list[GoldActor] = field(default_factory=list)
    claims: list[GoldClaim] = field(default_factory=list)


# --------------------------------------------------------------------------
# System output (whatever is being evaluated)
# --------------------------------------------------------------------------

@dataclass
class SystemActor:
    actor_id: str
    description_ref: str
    resolved_endpoints: list[str] = field(default_factory=list)


@dataclass
class SystemClaim:
    step_id: str
    text: str
    actor_refs: list[str] = field(default_factory=list)
    grounding_status: str = "uncertain_needs_drilldown"
    linked_fingerprint_keys: list[str] = field(default_factory=list)
    # fingerprint_key -> the destinations actually observed for it in this
    # step's linked evidence (from the real Grounder's
    # LinkedAggregateRef.unique_destinations, already present in its
    # output -- no pipeline changes needed to populate this).
    linked_fingerprint_destinations: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class SystemSample:
    sample_id: str
    actors: list[SystemActor] = field(default_factory=list)
    claims: list[SystemClaim] = field(default_factory=list)
    # Needed only for Compliance Testing's "resolved IP must be an observed
    # IP" check -- the full set of IPs actually seen in this sample's
    # traffic (e.g. keys of ip_summary, or unique_sources|unique_destinations
    # across fingerprint_index).
    observed_ips: set[str] = field(default_factory=set)