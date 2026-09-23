"""
Evidence Matcher (Grounder sub-component #2).

  Responsibility: given Steps + Actors from Step Extractor, and traffic
  evidence (EvidenceItem list + EvidenceAggregate index -- see models.py)
  from whatever upstream stage produced it, determine:
    1. Actor Resolution: map each actor ROLE to actual IP endpoint(s)
       observed in the traffic.
    2. Step Grounding: for each step, attach the packets/aggregates that
       support it, and classify -- grounded / unsupported /
       uncertain_needs_drilldown.

  This component is deliberately AGNOSTIC to Preprocessing. It has no
  import of, or dependency on, the preprocessing package -- it only knows
  about EvidenceItem/EvidenceAggregate (defined in models.py). Whatever
  produced that evidence (today: Preprocessing's Reducer; potentially
  something else later) is an orchestrator/main-function concern: the
  orchestrator is responsible for adapting Preprocessing's actual
  ReducerOutput into these generic shapes before calling
  EvidenceMatcher.match(). See the smoke test for a worked adapter example.

  Mechanism differs deliberately between the two responsibilities:
    - Step Grounding is algorithmic-first (fingerprint_index lookup is
      O(1)-ish per step), with LLM escalation reserved for genuinely
      ambiguous cases: multiple competing fingerprint matches, or steps
      with no usable structured indicators at all. This keeps grounding
      cost close to O(P + N) rather than O(N*P): most steps resolve via a
      cheap dict lookup and never touch the LLM at all.
    - Actor Resolution is LLM-first: roles are open-ended text (not a
      fixed enum), so a hand-coded per-role scoring formula can only ever
      cover the couple of roles someone thought to write a branch for. A
      cheap, role-agnostic structural summary is computed per IP (no LLM),
      and the LLM interprets that summary against whatever role label the
      description actually used -- generalizing to roles (resolver, proxy,
      C2 server, ...) without new code per role. The old scoring-heuristic
      approach is kept only as an offline fallback when no llm_client is
      available.

  NOTE on confidence: this component does NOT produce numeric confidence
  scores for grounding or actor resolution. A heuristic-derived score
  isn't indicative of anything until it's been checked against labeled
  ground truth -- that calibration is the Evaluator's job, not this
  component's. `status` and `notes` carry everything Evidence Matcher can
  currently justify; see models.py for the same note on the dataclasses.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Callable, Optional

try:
    from .llm_client import LLMClient
    from .models import (
        Actor, Step, ExpectedIndicators, Grounding, GroundingStatus, GroundedStep,
        LinkedPacketRef, LinkedAggregateRef, EvidenceItem, EvidenceAggregate,
    )
except ImportError:
    from llm_client import LLMClient
    from models import (
        Actor, Step, ExpectedIndicators, Grounding, GroundingStatus, GroundedStep,
        LinkedPacketRef, LinkedAggregateRef, EvidenceItem, EvidenceAggregate,
    )

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# TCP flag bitmasks -- defined locally rather than imported from
# preprocessing.fingerprint. This is a small, stable piece of domain
# knowledge (standard TCP flag bit positions), not something that should
# force a dependency on another package just to reuse five constants.
# --------------------------------------------------------------------------
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

_FLAG_NAME_TO_BIT = {
    "SYN": TCP_SYN, "ACK": TCP_ACK, "FIN": TCP_FIN, "RST": TCP_RST, "PSH": TCP_PSH,
}


def _extract_arp_opcode_hint(flags: list[str]) -> Optional[str]:
    """Extracts an ARP opcode value ("1"=request, "2"=reply) from a
    step's `flags` list. Step Extractor puts ARP opcode information into
    the generic `flags` field (e.g. "Opcode 2", "2", "ARP Reply") since
    ExpectedIndicators has no dedicated opcode field. Returns None if no
    opcode can be determined from any entry, in which case the caller
    should not filter on opcode at all rather than guessing wrong."""
    for f in flags:
        f_lower = f.lower()
        if "reply" in f_lower:
            return "2"
        if "request" in f_lower:
            return "1"
        m = re.search(r"\d+", f)
        if m:
            return m.group(0)
    return None


# --------------------------------------------------------------------------
# Protocol normalization
# --------------------------------------------------------------------------
# Step Extractor's prompt allows application-layer protocol names (DNS,
# HTTP, HTTPS, SSH, ...) since that's how a human/LLM would naturally
# describe traffic from text. Whatever produced the fingerprint keys
# (Preprocessing's Reducer, today) is expected to use transport-layer
# names (TCP, UDP, ARP, ICMP, TCP_DATA_STREAM) plus well-known ports.
# Without normalizing, a step with protocol="DNS" would silently fail to
# match a "UDP" fingerprint and be wrongly marked unsupported -- this
# table exists specifically to prevent that class of false negative.
APP_PROTOCOL_TO_TRANSPORT: dict[str, tuple[str, Optional[int]]] = {
    "dns": ("UDP", 53),
    "http": ("TCP", 80),
    "https": ("TCP", 443),
    "tls": ("TCP", 443),
    "ssl": ("TCP", 443),
    "ssh": ("TCP", 22),
    "ftp": ("TCP", 21),
    "smb": ("TCP", 445),
    "smtp": ("TCP", 25),
    "ntp": ("UDP", 123),
    "tcp": ("TCP", None),
    "udp": ("UDP", None),
    "icmp": ("ICMP", None),
    "arp": ("ARP", None),
}


def _normalize_protocol(protocol: Optional[str]) -> tuple[Optional[str], Optional[int]]:
    """Returns (transport_l4_proto, implied_port) for a possibly
    application-layer protocol name. implied_port is only a hint -- an
    explicit port on the step's expected_indicators always takes priority
    over this."""
    if not protocol:
        return None, None
    key = protocol.strip().lower()
    if key in APP_PROTOCOL_TO_TRANSPORT:
        return APP_PROTOCOL_TO_TRANSPORT[key]
    # Unknown protocol name -- pass through uppercased, on the chance it
    # already matches a transport-level fingerprint key directly.
    return protocol.strip().upper(), None


# --------------------------------------------------------------------------
# Fingerprint index querying
# --------------------------------------------------------------------------

@dataclass
class FingerprintCandidate:
    fingerprint_key: str
    l4_proto: str
    state_signature: tuple
    aggregate: EvidenceAggregate


def _parse_fingerprint_key(fkey: str) -> tuple[str, tuple]:
    """Inverse of the JSON-based fingerprint key encoding
    (see preprocessor.fingerprint.fingerprint_key_str for the producer
    side -- this function only needs to know the encoding shape, not
    import that module)."""
    l4_proto, sig = json.loads(fkey)
    return l4_proto, tuple(sig)


def _canonicalize_fingerprint_key(key) -> Optional[tuple]:
    """
    Normalizes a fingerprint key into a canonical (l4_proto, (sig_elem, ...))
    tuple for robust comparison, regardless of whether it arrives as:
      - the canonical JSON string ('["TCP",["0x02","443"]]')
      - an already-parsed list (LLMs can "unwrap" the key back into real
        JSON structure when generating their own JSON response, since the
        key string itself looks like valid JSON -- confirmed via an actual
        `TypeError: unhashable type: 'list'` crash in
        `set(result.get("chosen_fingerprint_keys", []))`, not just a
        theoretical concern)
    Returns None if the key can't be interpreted at all, so a single
    malformed entry from the LLM doesn't crash the whole grounding
    decision -- it's just silently excluded from matching.
    """
    try:
        parsed = json.loads(key) if isinstance(key, str) else key
        l4_proto, sig = parsed
        return l4_proto, tuple(str(s) for s in sig)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def find_matching_fingerprints(
    fingerprint_index: dict[str, EvidenceAggregate],
    protocol: Optional[str],
    port: Optional[int],
    flags: Optional[list[str]],
) -> list[FingerprintCandidate]:
    """
    Algorithmic lookup: filter fingerprint_index entries structurally
    matching the given (normalized) protocol/port/flags. No LLM involved.
    """
    transport_proto, implied_port = _normalize_protocol(protocol)
    effective_port = port if port is not None else implied_port

    candidates: list[FingerprintCandidate] = []
    for fkey, agg in fingerprint_index.items():
        l4_proto, sig = _parse_fingerprint_key(fkey)

        if transport_proto is not None:
            # TCP_DATA_STREAM is the folded-in-progress-connection bucket
            # for TCP -- treat it as a TCP match too, since a step asking
            # about "TCP traffic to port X" should find established
            # -connection data, not just handshake packets.
            proto_matches = (
                l4_proto == transport_proto
                or (transport_proto == "TCP" and l4_proto == "TCP_DATA_STREAM")
            )
            if not proto_matches:
                continue

        if effective_port is not None:
            # Rather than hard-coding signature positions per protocol
            # (fragile against upstream fingerprinting changes), just
            # check membership across the whole signature tuple.
            if str(effective_port) not in sig:
                continue

        if flags:
            if l4_proto == "ARP":
                # ARP has no "flags" concept, but it does have a directly
                # analogous single-value field: opcode (1=request,
                # 2=reply). Step Extractor reasonably maps ARP opcode
                # into the generic `flags` field (e.g. "Opcode 2", "2",
                # "ARP Reply") since ExpectedIndicators has no dedicated
                # opcode field. Previously this branch fell through to
                # "flags are meaningless outside TCP" and rejected EVERY
                # ARP candidate outright whenever flags was set at all --
                # confirmed via a real ARP-spoofing scenario where this
                # caused steps 4/5 (the core attack signature: unsolicited
                # ARP Reply packets) to always return zero candidates
                # despite matching evidence existing in fingerprint_index.
                opcode_hint = _extract_arp_opcode_hint(flags)
                if opcode_hint is not None and sig and str(sig[0]) != opcode_hint:
                    continue  # opcode explicitly doesn't match
                # If opcode_hint couldn't be determined from the flags
                # text, don't filter on it -- fall through to matching on
                # protocol alone rather than rejecting.
            elif l4_proto in ("TCP", "TCP_DATA_STREAM"):
                if l4_proto == "TCP_DATA_STREAM":
                    # TCP_DATA_STREAM has already lost individual
                    # per-packet flag detail (folded by design upstream).
                    # A flag filter can't be checked against it
                    # structurally; treat as a non-match for
                    # flag-specific queries rather than guessing.
                    continue
                flags_hex = sig[0]
                try:
                    flags_val = int(flags_hex, 16)
                except (TypeError, ValueError):
                    continue
                if not all(flags_val & _FLAG_NAME_TO_BIT.get(f.upper(), 0) for f in flags):
                    continue
            else:
                # No defined flag/opcode semantics for this protocol (UDP,
                # ICMP, ...) -- don't reject a candidate solely because an
                # unsupported filter dimension couldn't be checked. A
                # false "unsupported" from silently-unchecked flags is
                # worse than proceeding on protocol+port alone; if this
                # produces multiple candidates instead, that correctly
                # escalates to LLM judgment rather than a wrong hard "no".
                pass

        candidates.append(FingerprintCandidate(fkey, l4_proto, sig, agg))

    return candidates


def _linked_refs_for_fingerprint(
    fkey: str, reduced_representation: list[EvidenceItem], agg: EvidenceAggregate,
) -> tuple[list[LinkedPacketRef], list[LinkedAggregateRef]]:
    """Cross-reference reduced_representation for raw items carrying this
    fingerprint_key, plus the aggregate summary itself."""
    linked_packets = [
        LinkedPacketRef(
            packet_id=item.packet_id, timestamp=item.timestamp,
            protocol=item.protocol, src=item.src, dst=item.dst,
            length=item.length, info=item.info,
        )
        for item in reduced_representation
        if item.fingerprint_key == fkey
    ]
    linked_aggregates = [
        LinkedAggregateRef(
            fingerprint_key=fkey,
            count=agg.count,
            unique_sources=list(agg.unique_sources),
            unique_destinations=list(agg.unique_destinations),
        )
    ]
    return linked_packets, linked_aggregates


# --------------------------------------------------------------------------
# Actor Resolution
# --------------------------------------------------------------------------
#
# LLM-first, not algorithm-first. Earlier versions hard-coded scoring
# formulas for exactly two role labels (attacker/victim) and fell back to
# a weak generic score for anything else -- which can never scale to the
# real space of roles (resolver, proxy, intermediary, C2 server, ...)
# without endless manual heuristics per role. Instead: compute a single,
# role-agnostic structural summary per IP (cheap, deterministic, no LLM),
# and let the LLM interpret that summary against whatever role label the
# description actually used. The LLM already generalizes to unfamiliar
# roles; hand-written heuristics don't.
#
# The old heuristic (_candidate_ips_with_scores) is kept, but demoted to
# an OFFLINE-ONLY FALLBACK -- used only when no llm_client is available
# (e.g. unit tests without a live model). It still only understands
# attacker/victim-shaped patterns; it is not the primary path anymore.

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ip_hint(text: Optional[str]) -> Optional[str]:
    """Best-effort extraction of a literal IPv4 address mentioned in free
    text (e.g. an actor's description_ref).

    This is NOT trusted directly -- it's passed to the LLM as a hint to be
    weighed against the actual traffic evidence, not used as the
    resolution by itself. A description claiming an IP is still just an
    unverified textual claim (same category as any other claim this whole
    pipeline exists to check) -- it gets validated like one, not taken on
    faith. See _resolve_actor_via_llm's hallucination guard, which also
    rejects an LLM answer that isn't actually present in the traffic.
    """
    if not text:
        return None
    m = _IPV4_RE.search(text)
    return m.group(0) if m else None


# Protocols whose fingerprint_key already fixes a single real-world
# identity (see _find_identity_fanout_anomalies for why this matters).
# Deliberately explicit and small, not "everything except TCP/UDP/ICMP" --
# adding a protocol here should be a conscious choice, verified against
# that protocol's actual fingerprint key shape (does the key include an
# identity field like a MAC address, or only structural fields?).
def _arp_is_unsolicited_claim(sig: tuple) -> bool:
    """Qualifying predicate for ARP: only opcode=2 (REPLY -- "I own this
    IP") represents an unsolicited identity claim. opcode=1 (REQUEST --
    "who has this IP?") is routine network behavior; a host asking about
    several different targets is not anomalous."""
    return bool(sig) and str(sig[0]) == "2"


# Per-protocol qualification: which fingerprints of a given identity-keyed
# protocol are even ELIGIBLE for the cardinality-anomaly check. The
# detection MECHANISM below (cardinality relative to this capture's own
# per-protocol baseline) is protocol-agnostic; what's necessarily
# protocol-specific is WHICH sub-states of that protocol represent an
# unsolicited identity claim versus routine/expected traffic -- that
# distinction depends on protocol semantics, which is real domain
# knowledge, not something a generic formula can infer.
#
# This is a small, explicit, documented lookup -- extended one entry at a
# time as evidence from real captures justifies it (e.g. the ARP
# opcode=1/2 split below was added after opcode=1 produced a real false
# positive), not a preemptive attempt to cover every protocol's semantics
# up front. A protocol with no entry here is simply not checked -- safer
# than guessing at its semantics without evidence.
#
# Each entry: protocol name -> predicate(state_signature) -> bool, "does
# this fingerprint represent an unsolicited identity claim worth checking
# for anomalous cardinality".
_IDENTITY_CLAIM_QUALIFIERS: dict[str, Callable[[tuple], bool]] = {
    "ARP": _arp_is_unsolicited_claim,
}


def _find_identity_fanout_anomalies(
    fingerprint_index: dict[str, EvidenceAggregate],
) -> list[dict]:
    """
    Protocol-agnostic structural anomaly signal: a single fingerprint
    (i.e. one FIXED real-world identity -- e.g. one ARP sender MAC)
    associated with an unusually large number of distinct counterpart
    addresses, RELATIVE TO other fingerprints of the same protocol in
    this specific capture.

    The DETECTION MECHANISM (cardinality relative to this capture's own
    per-protocol median baseline) is fully protocol-agnostic. What is
    necessarily protocol-specific is deciding WHICH fingerprints even
    represent an "unsolicited identity claim" worth checking in the first
    place -- that depends on protocol semantics (e.g. ARP's opcode=2
    reply is a claim; opcode=1 request is not), which is real domain
    knowledge no generic formula can infer on its own. That per-protocol
    knowledge lives entirely in _IDENTITY_CLAIM_QUALIFIERS -- a small,
    explicit, documented lookup table, extended one entry at a time as
    evidence from real captures justifies it (not a preemptive attempt to
    cover every protocol's semantics up front; a protocol with no entry
    is simply not checked, which is safer than guessing at its semantics
    without evidence).

    Two false-positive classes were found and fixed via real testing,
    both addressed by this qualifier-table design:
      - TCP/UDP/ICMP have no identity component in their fingerprint key
        at all (keyed only by structural fields like flags/port) -- high
        cardinality there just means "many different real machines
        produced similar traffic" (e.g. a busy server's many real
        clients), not an identity claim. These protocols simply have no
        entry in the qualifier table.
      - Within ARP, opcode=1 (request) was originally checked alongside
        opcode=2 (reply) -- but a host ARP-requesting several different
        targets is routine network behavior, not a claim of anything.
        _arp_is_unsolicited_claim excludes opcode=1 explicitly.
    """
    import statistics

    by_protocol: dict[str, list[tuple[str, EvidenceAggregate, int, int]]] = {}
    for fkey, agg in fingerprint_index.items():
        l4_proto, sig = _parse_fingerprint_key(fkey)
        qualifies = _IDENTITY_CLAIM_QUALIFIERS.get(l4_proto)
        if qualifies is None or not qualifies(sig):
            continue
        src_card = len(agg.unique_sources)
        dst_card = len(agg.unique_destinations)
        by_protocol.setdefault(l4_proto, []).append((fkey, agg, src_card, dst_card))

    anomalies = []
    for l4_proto, entries in by_protocol.items():
        if len(entries) < 2:
            continue  # no meaningful "relative to the rest" baseline with only one entry
        src_baseline = statistics.median(c[2] for c in entries)
        dst_baseline = statistics.median(c[3] for c in entries)

        for fkey, agg, src_card, dst_card in entries:
            src_anomalous = src_card > 1 and src_card > src_baseline
            dst_anomalous = dst_card > 1 and dst_card > dst_baseline
            if not (src_anomalous or dst_anomalous):
                continue

            anomalies.append({
                "fingerprint_key": fkey,
                "protocol": l4_proto,
                "source_cardinality": src_card,
                "source_cardinality_anomalous": src_anomalous,
                "typical_source_cardinality_for_this_protocol": src_baseline,
                "destination_cardinality": dst_card,
                "destination_cardinality_anomalous": dst_anomalous,
                "typical_destination_cardinality_for_this_protocol": dst_baseline,
                "unique_sources": list(agg.unique_sources),
                "unique_destinations": list(agg.unique_destinations),
                "count": agg.count,
            })
    return anomalies


def _build_ip_summary_table(
    fingerprint_index: dict[str, EvidenceAggregate],
    reduced_representation: Optional[list[EvidenceItem]] = None,
    anomalies: Optional[list[dict]] = None,
    max_ips: int = 50,
    max_fingerprints_per_ip: int = 3,
    max_samples_per_ip: int = 3,
) -> list[dict]:
    """
    Compact, role-agnostic per-IP structural summary. Computed once,
    cheaply, with no LLM call -- then handed to the LLM so IT can reason
    about which IP fits a given role, instead of us hand-coding per-role
    formulas in Python. This is what lets a single mechanism generalize to
    roles we never anticipated, rather than requiring a new heuristic
    branch for every new role label that shows up in a description.

    Four properties added after real-world testing surfaced real gaps:

    1. Per-IP fingerprint breakdown (top_source_fingerprints /
       top_destination_fingerprints). Previously this table was PURELY
       numeric (counts and cardinalities) -- it could tell the LLM an IP
       was "busy" but never WHAT KIND of traffic made it busy. An IP with
       500 SYN-only packets (scan-like) and an IP with 500
       established-connection data packets (a heavy legitimate user) look
       IDENTICAL under packets_as_source alone -- the actual fingerprint
       keys are exactly the information that would let the LLM tell them
       apart. Capped to the top few per IP (by count) rather than every
       fingerprint that IP touched, so one IP scanning thousands of ports
       doesn't blow up its own row.

    2. Hard cap on total IP rows (max_ips), sorted by total traffic
       volume, with a single summarized entry for whatever's excluded.
       CONFIRMED VIA TESTING to be a real, severe gap, not a theoretical
       one: a simulated 3000-source SYN flood produced a ~764KB / ~191,000
       -token table with NO cap at all -- embedded in FULL in every single
       actor-resolution prompt (once per actor, so the true cost
       multiplies by actor count). Capping to the most active IPs is a
       deliberate lossy tradeoff: for a flood/scan scenario the
       INDIVIDUAL identity of the 2951st source IP is rarely what
       distinguishes a role -- the aggregate shape (visible via the
       anomaly mechanism and the summarized tail count) matters more than
       enumerating every source.

    3. Precomputed anomaly involvement per IP (anomaly_involvement). Found
       via a REAL run, even after other_roles awareness was added: the LLM
       was still misreading which side of an anomaly a candidate IP was
       on -- e.g. claiming an IP "is associated with multiple source IPs"
       when that IP was actually only in the anomaly's
       unique_destinations, never its unique_sources. Asking the model to
       mentally cross-reference two separate JSON structures (each IP's
       own row vs. the separate anomalies list) turned out to be an
       error-prone lookup for it to do itself. This precomputes that
       correlation in code instead.

    4. Real per-packet samples (sample_packets), not just aggregate stats.
       EvidenceItem now carries full per-packet detail (protocol/src/dst/
       length/info) -- restored after an earlier trim to a minimal id/
       timestamp/fingerprint_key shape turned out to throw away exactly
       the kind of concrete, individual evidence that made giving an LLM
       raw PCAP directly outperform this aggregate-only table on actor
       identification. Samples are timestamp-ordered, so this also
       surfaces something pure aggregation destroys entirely: WHO acted
       first -- a genuinely discriminating signal (e.g. an initiator
       appearing before anyone it later "responds" to) that no count or
       cardinality can express. Capped per IP for the same size reasons as
       the fingerprint breakdown.
    """
    src_counts: dict[str, int] = {}
    dst_counts: dict[str, int] = {}
    src_to_dsts: dict[str, set] = {}
    dst_to_srcs: dict[str, set] = {}
    src_to_dst_ports: dict[str, set] = {}
    dst_to_src_ports: dict[str, set] = {}
    # Per-IP fingerprint participation, for the breakdown -- separate from
    # the cardinality tracking above since this needs per-fingerprint
    # counts, not just membership.
    src_fingerprint_counts: dict[str, dict[str, int]] = {}
    dst_fingerprint_counts: dict[str, dict[str, int]] = {}

    for fkey, agg in fingerprint_index.items():
        l4_proto, sig = _parse_fingerprint_key(fkey)
        port = None
        if l4_proto == "TCP" and len(sig) > 1:
            port = sig[1]
        elif l4_proto in ("TCP_DATA_STREAM", "UDP") and len(sig) > 0:
            port = sig[0]

        for src in agg.unique_sources:
            src_counts[src] = src_counts.get(src, 0) + agg.count
            src_to_dsts.setdefault(src, set()).update(agg.unique_destinations)
            if port is not None:
                src_to_dst_ports.setdefault(src, set()).add(port)
            src_fingerprint_counts.setdefault(src, {})[fkey] = \
                src_fingerprint_counts.setdefault(src, {}).get(fkey, 0) + agg.count
        for dst in agg.unique_destinations:
            dst_counts[dst] = dst_counts.get(dst, 0) + agg.count
            dst_to_srcs.setdefault(dst, set()).update(agg.unique_sources)
            if port is not None:
                dst_to_src_ports.setdefault(dst, set()).add(port)
            dst_fingerprint_counts.setdefault(dst, {})[fkey] = \
                dst_fingerprint_counts.setdefault(dst, {}).get(fkey, 0) + agg.count

    def _top_fingerprints(fp_counts: dict[str, int]) -> list[dict]:
        ranked = sorted(fp_counts.items(), key=lambda kv: kv[1], reverse=True)
        return [{"fingerprint_key": k, "count": c} for k, c in ranked[:max_fingerprints_per_ip]]

    # Precompute, per IP, which anomalies (if any) it's involved in and on
    # which side -- see docstring point 3 for why this is computed here
    # instead of left for the LLM to cross-reference itself.
    anomaly_involvement: dict[str, dict[str, list[str]]] = {}
    for anomaly in (anomalies or []):
        fkey = anomaly.get("fingerprint_key", "?")
        for ip in anomaly.get("unique_sources", []):
            entry = anomaly_involvement.setdefault(ip, {"as_claiming_source": [], "as_claim_recipient": []})
            entry["as_claiming_source"].append(fkey)
        for ip in anomaly.get("unique_destinations", []):
            entry = anomaly_involvement.setdefault(ip, {"as_claiming_source": [], "as_claim_recipient": []})
            entry["as_claim_recipient"].append(fkey)

    # Per-IP raw packet samples, timestamp-sorted. Built in one pass over
    # reduced_representation (not per-IP re-scans) for efficiency.
    ip_samples: dict[str, list] = {}
    for item in (reduced_representation or []):
        for ip in (item.src, item.dst):
            ip_samples.setdefault(ip, []).append(item)

    def _sample_packets(ip: str) -> list[dict]:
        items = sorted(ip_samples.get(ip, []), key=lambda it: it.timestamp)[:max_samples_per_ip]
        return [
            {
                "packet_id": it.packet_id, "timestamp": it.timestamp,
                "protocol": it.protocol, "src": it.src, "dst": it.dst,
                "length": it.length, "info": it.info,
            }
            for it in items
        ]

    all_ips = set(src_counts) | set(dst_counts)
    full_table = [
        {
            "ip": ip,
            "packets_as_source": src_counts.get(ip, 0),
            "packets_as_destination": dst_counts.get(ip, 0),
            "distinct_destination_ips": len(src_to_dsts.get(ip, set())),
            "distinct_destination_ports": len(src_to_dst_ports.get(ip, set())),
            "distinct_source_ips_contacting_it": len(dst_to_srcs.get(ip, set())),
            "distinct_source_ports_contacting_it": len(dst_to_src_ports.get(ip, set())),
            "top_source_fingerprints": _top_fingerprints(src_fingerprint_counts.get(ip, {})),
            "top_destination_fingerprints": _top_fingerprints(dst_fingerprint_counts.get(ip, {})),
            "anomaly_involvement": anomaly_involvement.get(
                ip, {"as_claiming_source": [], "as_claim_recipient": []}
            ),
            "sample_packets": _sample_packets(ip),
        }
        for ip in all_ips
    ]

    if len(full_table) <= max_ips:
        full_table.sort(key=lambda row: row["ip"])  # deterministic ordering, not semantic
        return full_table

    # Too many IPs to embed individually -- keep the most active ones by
    # total volume (a reasonable proxy for "likely relevant to any role",
    # though not guaranteed; a low-volume IP could still matter for some
    # scenario this doesn't capture -- documented as a lossy tradeoff, not
    # a perfect solution).
    full_table.sort(key=lambda row: row["packets_as_source"] + row["packets_as_destination"], reverse=True)
    kept = full_table[:max_ips]
    excluded = full_table[max_ips:]
    kept.sort(key=lambda row: row["ip"])  # deterministic ordering for the kept subset

    kept.append({
        "ip": None,
        "note": (
            f"{len(excluded)} additional IP(s) omitted from this table "
            f"(capped at {max_ips} most active by traffic volume) -- "
            f"aggregate stats for the omitted set below."
        ),
        "omitted_count": len(excluded),
        "omitted_total_packets_as_source": sum(r["packets_as_source"] for r in excluded),
        "omitted_total_packets_as_destination": sum(r["packets_as_destination"] for r in excluded),
    })
    return kept


ACTOR_RESOLUTION_SYSTEM_PROMPT = """\
You are resolving a described actor's ROLE to a specific IP address, given
a compact structural summary of every IP observed in the traffic.

The role is NOT restricted to a fixed set like "attacker"/"victim" -- it
may be any label (e.g. "DNS resolver", "proxy", "C2 server",
"intermediary", "load balancer"). Use the structural summary (packet
counts, destination/source diversity, port diversity, AND
top_source_fingerprints / top_destination_fingerprints -- which show WHAT
KIND of traffic pattern makes up an IP's activity, e.g. mostly SYN-only
packets suggests scanning, mostly TCP_DATA_STREAM suggests established
data transfer) plus your own understanding of what that role's traffic
typically looks like to decide which IP best fits. Note some candidate
rows may be a single summarized entry (ip: null) representing many
lower-volume IPs omitted for size -- if none of the individually-listed
candidates fit well, consider whether the role more likely belongs to
that omitted long tail, and return null rather than forcing a fit onto
one of the listed IPs.

If STRUCTURAL ANOMALIES are present in the input, treat them as a
STRONGER signal than generic traffic-volume reasoning when relevant to
the role being resolved: an entity actively performing an attack often
looks structurally similar to a legitimate busy host on volume alone
(e.g. relaying traffic can look just as "busy" as being a real gateway),
so a specific structural anomaly (one identity unusually associated with
many counterparts, relative to normal traffic of that same protocol in
this capture) is often more diagnostic than volume. Interpret each
anomaly in light of the specific role/description you're resolving --
the same anomaly shape can mean different things depending on the
scenario (e.g. it may indicate the actor performing the anomaly, or may
help identify which OTHER candidates are the ones being targeted/spoofed
by it, depending on context).

Each candidate IP's own row includes anomaly_involvement, precomputed for
you -- as_claiming_source lists anomalies where THIS IP was doing the
claiming (e.g. the IP whose identity was asserted via unsolicited
traffic); as_claim_recipient lists anomalies where THIS IP merely
received/was targeted by someone else's claim. Use these fields directly
rather than re-deriving which side an IP was on by inspecting the
anomalies list yourself -- a real run showed this exact self-derived
lookup going wrong (an IP that only ever appeared as a claim recipient
was incorrectly described as "associated with multiple source IPs").

Each candidate's sample_packets shows a few ACTUAL packets (timestamp-
ordered) involving that IP, with real per-packet protocol/src/dst/length/
info -- not just aggregate counts. Use these for concrete, individual
evidence, and note that ORDER matters: an IP whose packets consistently
appear before another candidate's in the same exchange is more likely an
initiator; one that only appears after is more likely a responder. This
temporal signal has no equivalent in the aggregate statistics.

If a literal IP address is mentioned in the description, it is provided
as an unverified hint only -- check that it actually appears among the
candidate IPs below before treating it as meaningful. The description is
a claim, not evidence; do not choose an IP just because it was mentioned
in text if the traffic itself doesn't support it.

Return ONLY JSON: {"chosen_ip": "<ip or null>", "reasoning": "..."}

Return chosen_ip: null in BOTH of these cases, not just when no candidate
seems plausible at all:
  1. No candidate plausibly fits the role.
  2. The evidence you'd cite does not actually DISCRIMINATE this role from
     other roles being resolved separately in this same analysis (see
     OTHER ROLES below, if present) -- i.e. the same reasoning would
     equally justify picking the same IP for a different role. A
     generically "busy" or "high-volume" host is not, by itself, evidence
     for any SPECIFIC role -- it is consistent with many different roles
     (attacker, victim of a DDoS, a popular legitimate server, etc.).
     Confirmed via a real run that skipping this check produces real
     errors: an "attacker" role and a "victim" role both resolved to the
     same IP, via two separately-plausible-sounding but mutually
     exclusive stories built from the same underlying evidence. If you
     notice your own reasoning could support more than one role equally
     well, that is a signal to return null, not to commit to one story.
"""


def resolve_actor(
    actor: Actor,
    ip_summary: list[dict],
    anomalies: list[dict],
    other_roles: list[str],
    llm_client: Optional[LLMClient] = None,
) -> Actor:
    """
    LLM-first actor resolution. Falls back to a narrow structural
    heuristic (attacker/victim-shaped patterns only) ONLY when no
    llm_client is available -- e.g. offline tests. That fallback exists so
    the component still returns *something* deterministic without a live
    model; it is not the primary resolution path.

    Takes ip_summary/anomalies as PRECOMPUTED inputs (built once by the
    caller -- see EvidenceMatcher.match()) rather than raw
    fingerprint_index -- both used to be recomputed from scratch on every
    single call to this function, meaning a full re-scan of the entire
    fingerprint_index once per actor (O(actors * fingerprints) instead of
    O(fingerprints) computed once and reused O(actors) times). Confirmed
    as real, not just theoretical: match() calls this once per actor in a
    loop, and fingerprint_index never changes between those calls within
    one match() call.

    other_roles: the ROLE LABELS (not resolutions -- those aren't known
    yet, since every actor is resolved independently) of every OTHER actor
    being resolved in this same run. Confirmed via a real run that this
    gap causes real errors: two roles that must be different hosts by the
    scenario's own logic (an "attacker" role and a "victim" role) both
    resolved to the same IP, via two independently-plausible-sounding but
    mutually exclusive readings of the identical anomaly evidence --
    because each resolve_actor call had zero visibility into what other
    roles existed, it had no way to recognize that its own reasoning was
    generic/non-discriminating rather than genuinely specific to its role.
    This does NOT make resolution joint/coordinated (that would be a
    bigger architectural change) -- it just lets each independent call
    self-check whether its evidence for THIS role would equally explain
    one of THOSE other roles, and if so, decline to guess.
    """
    if llm_client is not None:
        return _resolve_actor_via_llm(actor, ip_summary, anomalies, other_roles, llm_client)

    logger.info(
        "No llm_client provided for actor resolution; using narrow "
        "structural-heuristic fallback (attacker/victim patterns only) "
        "for actor '%s' (role='%s').", actor.actor_id, actor.role,
    )
    return _resolve_actor_via_heuristic(actor, ip_summary)


def _resolve_actor_via_llm(
    actor: Actor,
    ip_summary: list[dict],
    anomalies: list[dict],
    other_roles: list[str],
    llm_client: LLMClient,
) -> Actor:
    if not ip_summary:
        return _unresolved(actor, "no IP candidates found in traffic")

    ip_hint = _extract_ip_hint(actor.description_ref)

    anomaly_section = ""
    if anomalies:
        anomaly_section = (
            "\nSTRUCTURAL ANOMALIES (each entry shows a fingerprint whose "
            "SOURCE-side and/or DESTINATION-side cardinality -- number of "
            "distinct counterpart addresses in that direction -- is "
            "unusually high compared to other traffic of the same "
            "protocol in this capture. The two directions are tracked "
            "separately and can mean very different things: high "
            "SOURCE cardinality with low destination cardinality is "
            "fan-OUT (one entity reaching/claiming many others -- e.g. "
            "one MAC claiming many IPs, or one host scanning many "
            "targets); high DESTINATION cardinality with low source "
            "cardinality is fan-IN (many entities converging on one -- "
            "e.g. many hosts hitting one target). Check "
            "source_cardinality_anomalous / destination_cardinality_anomalous "
            "explicitly rather than assuming a direction -- do not guess "
            "which side is anomalous from the raw numbers alone. Interpret "
            "in light of the specific role/description being resolved, "
            "since the same anomaly shape can mean different things in "
            "different scenarios):\n"
            f"{json.dumps(anomalies, indent=2)}\n"
        )

    other_roles_section = ""
    if other_roles:
        other_roles_section = (
            f"\nOTHER ROLES being resolved separately in this same analysis "
            f"(NOT their IPs -- those aren't known yet): {other_roles}\n"
            f"If your reasoning for THIS role ('{actor.role}') would equally "
            f"justify assigning the same candidate IP to one of those OTHER "
            f"roles, your evidence is not actually specific to this role -- "
            f"return chosen_ip: null rather than guessing based on generic "
            f"plausibility (e.g. \"highest traffic volume\" fits almost any "
            f"role and does not by itself distinguish attacker from victim "
            f"from gateway from an ordinary busy host).\n"
        )

    user_prompt = (
        f"Actor role: {actor.role}\n"
        f"Actor description reference: {actor.description_ref}\n"
        f"IP mentioned in description (unverified hint -- verify against "
        f"candidates below): {ip_hint or 'none'}\n"
        f"{other_roles_section}"
        f"{anomaly_section}\n"
        f"Candidate IPs with structural summary:\n{json.dumps(ip_summary, indent=2)}"
    )
    try:
        result = llm_client.complete_json(ACTOR_RESOLUTION_SYSTEM_PROMPT, user_prompt)
    except Exception as e:
        logger.warning("Actor resolution LLM call failed for %s: %s", actor.actor_id, e)
        return _unresolved(actor, f"LLM call failed: {e}")

    chosen = result.get("chosen_ip")
    if not chosen:
        return _unresolved(actor, result.get("reasoning", "LLM found no plausible candidate"))

    valid_ips = {row["ip"] for row in ip_summary}
    if chosen not in valid_ips:
        # Hallucination guard: the LLM named an IP that isn't actually
        # present in the traffic evidence at all. Treat as unresolved
        # rather than trusting an answer that can't be verified against
        # what we actually observed -- an unverifiable resolution is worse
        # than none, since every step referencing this actor would
        # silently inherit a fabricated identity.
        logger.warning(
            "Actor resolution LLM chose IP %r for actor '%s', which is not "
            "among the observed candidates; treating as unresolved.",
            chosen, actor.actor_id,
        )
        return _unresolved(
            actor, f"LLM chose '{chosen}', which is not among observed traffic IPs"
        )

    return _resolved(actor, [chosen], basis=f"LLM resolution: {result.get('reasoning', '')}")


# --------------------------------------------------------------------------
# Joint resolution -- resolves ALL actors in a single LLM call
# --------------------------------------------------------------------------
#
# Supersedes the per-actor loop (resolve_actor called once per actor) as
# match()'s primary path. The per-actor approach, even after adding
# other_roles (role LABELS only, no visibility into other actors' actual
# conclusions), still let two roles that must be different hosts collapse
# onto the same IP in a real run -- confirmed via two independently
# plausible-sounding but mutually exclusive readings of the identical
# anomaly evidence. Each call was locally coherent and globally wrong,
# because nothing enforced that the N answers be mutually consistent.
#
# Joint resolution fixes this structurally: one continuous reasoning
# process produces every actor's assignment together, so the model
# literally cannot "forget" what it assigned to another role the way N
# independent calls could. It also happens to be cheaper in aggregate --
# ip_summary/anomalies (the bulk of prompt size) are embedded ONCE instead
# of once per actor.
#
# Known limitations, not fixed here (see design discussion):
#   - Does not fix weak/non-discriminating evidence itself -- if the
#     evidence genuinely doesn't distinguish two roles, the model can
#     still assign them the same IP; the difference is this now happens
#     as an explicit, visible choice in one response, not a silent
#     collision across blind independent calls.
#   - Possible attention dilution with many actors in one call, and
#     possible order-sensitivity (position bias) -- neither is mitigated
#     here (e.g. no actor-order shuffling); flagged for future evaluation
#     once there's a labeled eval set to actually measure it against,
#     rather than guessing at a fix for an unconfirmed effect.
#   - Requires an llm_client -- there is no meaningful "offline joint"
#     heuristic; the offline fallback remains per-actor (see
#     resolve_actors below).

JOINT_ACTOR_RESOLUTION_SYSTEM_PROMPT = """\
You are resolving MULTIPLE described actors' ROLES to specific IP
addresses AT ONCE, given a compact structural summary of every IP
observed in the traffic. Resolving them together -- not independently --
lets you keep your answers mutually consistent, which is the entire point
of this joint format.

Roles are NOT restricted to a fixed set like "attacker"/"victim" -- they
may be any label. Use the structural summary (packet counts, destination/
source diversity, port diversity, top_source_fingerprints /
top_destination_fingerprints showing WHAT KIND of traffic makes up an
IP's activity, anomaly_involvement showing precomputed anomaly
correlation, and sample_packets showing real timestamp-ordered packets)
plus your own understanding of what each role's traffic typically looks
like.

anomaly_involvement per candidate IP is precomputed for you --
as_claiming_source lists anomalies where THIS IP was doing the claiming;
as_claim_recipient lists anomalies where THIS IP merely received/was
targeted by someone else's claim. Use these fields directly rather than
re-deriving which side an IP was on by inspecting the anomalies list
yourself.

sample_packets shows a few ACTUAL packets (timestamp-ordered, with real
protocol/src/dst/length/info) per candidate. Order matters: an IP whose
packets consistently appear before another candidate's in the same
exchange is more likely an initiator; one that only appears after is more
likely a responder.

CRITICAL -- CONSISTENCY ACROSS ACTORS, the whole reason for this joint
format: do NOT assign the same IP to two different actor roles unless you
can specifically justify why they really are the same underlying host
(rare -- most roles in a real scenario are distinct hosts). If your
reasoning for one role's IP would equally justify assigning that same IP
to a different role in this list, that means your evidence is not
actually specific to either role -- return chosen_ip: null for whichever
role(s) the evidence doesn't discriminate, rather than guessing based on
generic plausibility (e.g. "highest traffic volume" fits many different
roles and does not by itself distinguish any one of them).

Before committing to any individual answer, mentally review ALL actors
and the evidence available for each, so your final assignments are
consistent as a whole -- do not resolve them one at a time in isolation.

If a literal IP is mentioned in an actor's own description (ip_hint
below), it is an unverified hint only -- confirm it actually appears
among the candidates before treating it as meaningful.

Return ONLY JSON, with EXACTLY one entry per actor_id listed in the input
(same actor_ids, any order):
{
  "resolutions": [
    {"actor_id": "<id>", "chosen_ip": "<ip or null>", "reasoning": "..."}
  ]
}
"""


def _resolve_actors_jointly_via_llm(
    actors: list[Actor],
    ip_summary: list[dict],
    anomalies: list[dict],
    llm_client: LLMClient,
) -> list[Actor]:
    if not ip_summary:
        return [_unresolved(a, "no IP candidates found in traffic") for a in actors]

    actor_entries = [
        {
            "actor_id": a.actor_id,
            "role": a.role,
            "description_ref": a.description_ref,
            "ip_hint": _extract_ip_hint(a.description_ref),
        }
        for a in actors
    ]

    user_prompt = (
        f"Actors to resolve (respond with exactly one entry per actor_id):\n"
        f"{json.dumps(actor_entries, indent=2)}\n\n"
        f"Candidate IPs with structural summary:\n{json.dumps(ip_summary, indent=2)}"
    )

    by_id = {a.actor_id: a for a in actors}
    valid_actor_ids = set(by_id.keys())
    valid_ips = {row["ip"] for row in ip_summary if row.get("ip") is not None}

    try:
        result = llm_client.complete_json(JOINT_ACTOR_RESOLUTION_SYSTEM_PROMPT, user_prompt)
    except Exception as e:
        logger.warning("Joint actor resolution LLM call failed: %s", e)
        return [_unresolved(a, f"joint LLM call failed: {e}") for a in actors]

    resolved_by_id: dict[str, Actor] = {}
    for entry in result.get("resolutions", []):
        actor_id = entry.get("actor_id")

        # Per-entry error handling -- one malformed/unrecognized entry
        # must not lose every other actor's resolution in the same batch
        # (the same principle already applied to Step Extractor's
        # per-step error handling).
        if actor_id not in valid_actor_ids:
            logger.warning(
                "Joint resolution returned an unknown actor_id %r "
                "(not in the requested set); ignoring this entry.", actor_id,
            )
            continue
        if actor_id in resolved_by_id:
            logger.warning(
                "Joint resolution returned a duplicate entry for actor_id "
                "%r; keeping the first, ignoring the rest.", actor_id,
            )
            continue

        actor = by_id[actor_id]
        chosen = entry.get("chosen_ip")
        reasoning = entry.get("reasoning", "")

        if not chosen:
            resolved_by_id[actor_id] = _unresolved(
                actor, reasoning or "LLM found no plausible candidate"
            )
            continue

        if chosen not in valid_ips:
            # Hallucination guard -- same principle as the per-actor path:
            # an unverifiable resolution is worse than none.
            logger.warning(
                "Joint resolution chose IP %r for actor '%s', which is "
                "not among the observed candidates; treating as "
                "unresolved.", chosen, actor_id,
            )
            resolved_by_id[actor_id] = _unresolved(
                actor, f"LLM chose '{chosen}', which is not among observed traffic IPs"
            )
            continue

        resolved_by_id[actor_id] = _resolved(
            actor, [chosen], basis=f"Joint LLM resolution: {reasoning}"
        )

    # Any actor entirely missing from the response (not just null) --
    # the model skipped it rather than explicitly declining it.
    for actor in actors:
        if actor.actor_id not in resolved_by_id:
            logger.warning(
                "Joint resolution response had no entry at all for "
                "actor_id %r; treating as unresolved.", actor.actor_id,
            )
            resolved_by_id[actor.actor_id] = _unresolved(
                actor, "no resolution entry returned for this actor"
            )

    # Post-hoc duplicate-IP detector -- NOT a fix (does not change any
    # resolution), just a visibility net: even with the model explicitly
    # instructed to avoid unjustified collisions, log clearly if one
    # still occurs, since a silent duplicate is worse than a logged one.
    ip_to_actor_ids: dict[str, list[str]] = {}
    for a in resolved_by_id.values():
        for ip in a.resolved_endpoints:
            ip_to_actor_ids.setdefault(ip, []).append(a.actor_id)
    for ip, actor_ids in ip_to_actor_ids.items():
        if len(actor_ids) > 1:
            logger.warning(
                "Multiple actors resolved to the same IP %s despite joint "
                "resolution: %s -- review whether this is a genuine shared "
                "host or an unresolved discrimination failure.",
                ip, actor_ids,
            )

    return [resolved_by_id[a.actor_id] for a in actors]  # preserve input order


def resolve_actors(
    actors: list[Actor],
    ip_summary: list[dict],
    anomalies: list[dict],
    llm_client: Optional[LLMClient] = None,
) -> list[Actor]:
    """
    Resolves ALL actors together. This is match()'s primary entry point --
    see the module note above this section for why joint resolution
    replaced the per-actor loop.

    Falls back to independent per-actor heuristic resolution ONLY when no
    llm_client is available -- joint reasoning inherently requires a
    model; there is no meaningful "offline joint" heuristic to substitute.
    The singular resolve_actor() (LLM-or-heuristic, with other_roles
    awareness) is kept unchanged and still directly callable -- e.g. for
    standalone testing -- even though match() no longer calls it in a loop.
    """
    if llm_client is not None:
        return _resolve_actors_jointly_via_llm(actors, ip_summary, anomalies, llm_client)

    logger.info(
        "No llm_client provided for actor resolution; using narrow "
        "structural-heuristic fallback (attacker/victim patterns only), "
        "per actor -- joint reasoning requires a model."
    )
    return [_resolve_actor_via_heuristic(a, ip_summary) for a in actors]


# --------------------------------------------------------------------------
# Offline-only fallback heuristic (attacker/victim patterns only)
# --------------------------------------------------------------------------

_ATTACKER_ROLE_HINTS = {"attacker", "scanner", "client", "source", "initiator"}
_VICTIM_ROLE_HINTS = {"victim", "target", "server", "destination"}


def _candidate_ips_with_scores(
    ip_summary: list[dict],
    role: str,
) -> list[tuple[str, float]]:
    """
    Narrow, offline-only fallback -- NOT the primary resolution mechanism
    (see resolve_actor). Only understands attacker/victim-shaped
    structural patterns; any other role label falls through to a weak
    generic volume score. This limitation is exactly why the primary path
    is LLM-first now: a hard-coded formula can only ever cover the couple
    of role labels someone thought to write a branch for.

    Scanner-like behavior for "attacker"-style roles accounts for BOTH
    host-scan signal (many distinct destination IPs) AND port-scan signal
    (many distinct destination ports against a single IP) -- a
    single-target port scan has destination-IP cardinality of exactly 1
    and would otherwise score as "boring" against an ordinary host that
    merely talks to two unrelated IPs (found via testing).

    Takes the already-computed ip_summary table (see
    _build_ip_summary_table) rather than re-deriving the same per-IP
    statistics from fingerprint_index independently -- this used to be a
    separate computation over fingerprint_index with its own dict names,
    which was both redundant (recomputing what _build_ip_summary_table
    already computes) and a maintenance risk (two independent
    implementations of nearly the same statistics that could drift out of
    sync). Now there is exactly one source of per-IP structural stats.
    """
    role_key = role.strip().lower()
    scores: dict[str, float] = {}

    if role_key in _ATTACKER_ROLE_HINTS:
        for row in ip_summary:
            scores[row["ip"]] = row["distinct_destination_ips"] + row["distinct_destination_ports"]
    elif role_key in _VICTIM_ROLE_HINTS:
        for row in ip_summary:
            scores[row["ip"]] = row["distinct_source_ips_contacting_it"] + row["distinct_source_ports_contacting_it"]
    else:
        for row in ip_summary:
            scores[row["ip"]] = row["packets_as_source"] + row["packets_as_destination"]

    return sorted(scores.items(), key=lambda kv: kv[1], reverse=True)


def _resolve_actor_via_heuristic(actor: Actor, ip_summary: list[dict]) -> Actor:
    ranked = _candidate_ips_with_scores(ip_summary, actor.role)

    if not ranked:
        return _unresolved(actor, "no IP candidates found in traffic")

    top_ip, top_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0

    if top_score > 0 and (second_score == 0 or top_score >= second_score * 2):
        return _resolved(
            actor, [top_ip],
            basis=f"fallback structural heuristic for role '{actor.role}': "
                  f"top candidate score={top_score} vs runner-up={second_score}",
        )

    return _unresolved(
        actor,
        f"fallback heuristic ambiguous (top={ranked[:3]}) and no llm_client available",
    )


def _resolved(actor: Actor, ips: list[str], basis: str) -> Actor:
    return Actor(
        actor_id=actor.actor_id, role=actor.role, description_ref=actor.description_ref,
        resolved_endpoints=ips, resolution_basis=basis,
    )


def _unresolved(actor: Actor, reason: str) -> Actor:
    return Actor(
        actor_id=actor.actor_id, role=actor.role, description_ref=actor.description_ref,
        resolved_endpoints=[], resolution_basis=reason,
    )


# --------------------------------------------------------------------------
# Step Grounding
# --------------------------------------------------------------------------

GROUNDING_ESCALATION_SYSTEM_PROMPT = """\
You are the Evidence Matcher's escalation path, used only when algorithmic
fingerprint lookup could not confidently decide a step's grounding status --
either because multiple structurally-similar traffic patterns matched, or
because the step has no usable structured indicators at all.

Given a step's text and a compact summary of candidate traffic evidence,
decide the grounding status. Return ONLY JSON:
{
  "status": "grounded" | "unsupported" | "uncertain_needs_drilldown",
  "chosen_fingerprint_keys": ["..."],
  "reasoning": "..."
}

CRITICAL RULE: status "grounded" REQUIRES at least one entry in
chosen_fingerprint_keys, copied EXACTLY (character-for-character) from a
"key=" value in the candidate evidence below. A general, plausible-sounding
explanation is NOT sufficient on its own -- if you cannot point to a
specific candidate key that concretely supports the step, you MUST use
"uncertain_needs_drilldown" instead of "grounded", even if the traffic
pattern seems generally consistent with the step's description. Do not
reason about what the traffic "typically looks like" for this kind of
step without tying that reasoning to a specific listed key.

Use "uncertain_needs_drilldown" when the evidence is suggestive but you
cannot confirm it from the summary alone (e.g. only aggregate counts are
available, no per-packet detail, or no single candidate key concretely
matches).
"""


def _summarize_candidates_for_llm(
    candidates: list[FingerprintCandidate], reduced_representation: list[EvidenceItem],
) -> str:
    lines = []
    for c in candidates:
        raw_count = sum(1 for item in reduced_representation if item.fingerprint_key == c.fingerprint_key)
        lines.append(
            f"- key={c.fingerprint_key} proto={c.l4_proto} sig={c.state_signature} "
            f"total_count={c.aggregate.count} raw_samples_available={raw_count} "
            f"srcs={c.aggregate.unique_sources[:5]} dsts={c.aggregate.unique_destinations[:5]}"
        )
    return "\n".join(lines) if lines else "(no candidates)"


def ground_step(
    step: Step,
    resolved_actors: dict[str, Actor],
    reduced_representation: list[EvidenceItem],
    fingerprint_index: dict[str, EvidenceAggregate],
    llm_client: Optional[LLMClient] = None,
) -> Grounding:
    """
    Core per-step grounding decision. Algorithmic lookup first; LLM
    escalation only for competing matches or unstructured-only steps.
    """
    # Dependency check: if this step references an actor that failed to
    # resolve, don't bother searching -- flag immediately as uncertain
    # rather than spending a lookup on evidence we can't correctly filter
    # by actor anyway.
    for ref in step.actor_refs:
        actor = resolved_actors.get(ref)
        if actor is None or not actor.resolved_endpoints:
            return Grounding(
                status=GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN,
                notes=f"depends on unresolved actor '{ref}'",
            )

    ei = step.expected_indicators
    has_structured = any([ei.protocol, ei.port, ei.flags])

    if not has_structured:
        # No structured hints at all -- can't do a lookup, must escalate
        # directly using indicator_description against a compact summary
        # of everything available.
        if llm_client is None:
            return Grounding(
                status=GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN,
                notes="no structured indicators and no llm_client for escalation",
            )
        all_candidates = [
            FingerprintCandidate(fkey, *_parse_fingerprint_key(fkey), agg)
            for fkey, agg in fingerprint_index.items()
        ]
        return _escalate_grounding(step, all_candidates, reduced_representation, llm_client)

    candidates = find_matching_fingerprints(fingerprint_index, ei.protocol, ei.port, ei.flags)

    if len(candidates) == 0:
        return Grounding(
            status=GroundingStatus.UNSUPPORTED,
            notes="no matching traffic pattern found for the specified indicators",
        )

    if len(candidates) == 1:
        c = candidates[0]
        linked_packets, linked_aggs = _linked_refs_for_fingerprint(
            c.fingerprint_key, reduced_representation, c.aggregate
        )
        raw_sample_count = len(linked_packets)
        if raw_sample_count < c.aggregate.count:
            # More packets exist in this pattern than we have raw detail
            # for -- exactly the "aggregate-only" trigger condition for
            # drill-down.
            return Grounding(
                status=GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN,
                linked_packets=linked_packets,
                linked_aggregate_refs=linked_aggs,
                notes=f"matches fingerprint {c.fingerprint_key}, but only "
                      f"{raw_sample_count}/{c.aggregate.count} packets have raw detail",
            )
        return Grounding(
            status=GroundingStatus.GROUNDED,
            linked_packets=linked_packets,
            linked_aggregate_refs=linked_aggs,
            notes=f"clean structural match on {c.fingerprint_key}",
        )

    # Multiple competing matches -- escalate.
    if llm_client is None:
        return Grounding(
            status=GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN,
            notes=f"{len(candidates)} competing fingerprint matches and no "
                  f"llm_client for escalation",
        )
    return _escalate_grounding(step, candidates, reduced_representation, llm_client)


def _escalate_grounding(
    step: Step, candidates: list[FingerprintCandidate],
    reduced_representation: list[EvidenceItem], llm_client: LLMClient,
) -> Grounding:
    user_prompt = (
        f"Step: {step.text}\n"
        f"Indicator description: {step.expected_indicators.indicator_description}\n\n"
        f"Candidate evidence:\n{_summarize_candidates_for_llm(candidates, reduced_representation)}"
    )
    try:
        result = llm_client.complete_json(GROUNDING_ESCALATION_SYSTEM_PROMPT, user_prompt)
    except Exception as e:
        logger.warning("Grounding escalation failed for step %s: %s", step.step_id, e)
        return Grounding(
            status=GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN,
            notes=f"LLM escalation failed: {e}",
        )

    # Canonicalized comparison, not raw set() membership -- the LLM can
    # return a chosen fingerprint key either as the canonical JSON string
    # or "unwrapped" into real JSON structure (since the string itself
    # looks like valid JSON to it), and set(...) on a mix of strings and
    # lists raises TypeError (lists aren't hashable). Comparing canonical
    # forms handles both, plus incidental type mismatches (e.g. a port
    # returned as int 443 instead of str "443").
    chosen_canonical = {
        c for c in (_canonicalize_fingerprint_key(k)
                     for k in result.get("chosen_fingerprint_keys", []))
        if c is not None
    }
    linked_packets, linked_aggs = [], []
    for c in candidates:
        if _canonicalize_fingerprint_key(c.fingerprint_key) in chosen_canonical:
            p, a = _linked_refs_for_fingerprint(c.fingerprint_key, reduced_representation, c.aggregate)
            linked_packets.extend(p)
            linked_aggs.extend(a)

    try:
        status = GroundingStatus(result.get("status", "uncertain_needs_drilldown"))
    except ValueError:
        status = GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN

    reasoning = result.get("reasoning", "")

    # Structural consistency enforcement -- do NOT trust the LLM's
    # self-reported status in isolation. A status of "grounded" with zero
    # linked_packets AND zero linked_aggregate_refs is an internal
    # contradiction: the model asserted support without pointing at any
    # specific evidence, i.e. exactly the "hidden hallucination" case this
    # whole pipeline exists to catch (a claim that sounds justified in
    # prose but isn't tied to a concrete fingerprint). This was observed
    # in practice (a step returned "grounded" with empty linked_packets
    # AND empty linked_aggregate_refs for a step with no structured
    # indicators), not just as a theoretical risk -- so this is enforced
    # here rather than left to prompt wording alone.
    if status == GroundingStatus.GROUNDED and not linked_packets and not linked_aggs:
        logger.warning(
            "Step %s: LLM escalation returned status=grounded with NO linked "
            "evidence (chosen_fingerprint_keys=%r did not match any candidate) "
            "-- downgrading to uncertain_needs_drilldown rather than trusting "
            "the self-reported status.",
            step.step_id, result.get("chosen_fingerprint_keys"),
        )
        status = GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN
        reasoning = (
            f"[DOWNGRADED from grounded: no evidence was actually linked, "
            f"despite the LLM's self-reported status] {reasoning}"
        )

    return Grounding(
        status=status,
        linked_packets=linked_packets,
        linked_aggregate_refs=linked_aggs,
        notes=f"LLM escalation: {reasoning}",
    )


# --------------------------------------------------------------------------
# Top-level entry point
# --------------------------------------------------------------------------

class EvidenceMatcher:
    """
    Consumes generic evidence (EvidenceItem list + EvidenceAggregate index)
    -- NOT a preprocessing.schemas.ReducerOutput. Adapting a real
    ReducerOutput into these shapes is the orchestrator's responsibility;
    see the smoke test for a worked example.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client

    def match(
        self,
        actors: list[Actor],
        steps: list[Step],
        reduced_representation: list[EvidenceItem],
        fingerprint_index: dict[str, EvidenceAggregate],
    ) -> tuple[list[Actor], list[GroundedStep]]:
        # Computed ONCE here, not per-actor -- both were previously
        # recomputed from scratch inside every resolve_actor() call, a
        # full re-scan of fingerprint_index per actor even though it
        # never changes within one match() call (O(actors*fingerprints)
        # instead of O(fingerprints) once + O(actors) reuse).
        # anomalies computed first -- ip_summary now depends on it (for
        # per-IP anomaly_involvement correlation).
        anomalies = _find_identity_fanout_anomalies(fingerprint_index)
        ip_summary = _build_ip_summary_table(fingerprint_index, reduced_representation, anomalies)

        resolved_actors = resolve_actors(actors, ip_summary, anomalies, self.llm_client)
        resolved_by_id = {a.actor_id: a for a in resolved_actors}

        grounded_steps = [
            GroundedStep(
                step=s,
                grounding=ground_step(
                    s, resolved_by_id, reduced_representation,
                    fingerprint_index, self.llm_client,
                ),
            )
            for s in steps
        ]
        return resolved_actors, grounded_steps
    

def _serialize_result(resolved_actors: list[Actor], grounded_steps: list[GroundedStep]) -> dict:
    """Converts dataclasses (including nested ones and the GroundingStatus
    enum) into a plain JSON-serializable dict. Using dataclasses.asdict
    directly on GroundedStep would leave GroundingStatus as an Enum member
    -- json.dump would then fail on it -- so status is pulled out to its
    .value explicitly."""
    from dataclasses import asdict

    def _grounded_step_to_dict(gs: GroundedStep) -> dict:
        d = asdict(gs)
        d["grounding"]["status"] = gs.grounding.status.value
        return d

    return {
        "resolved_actors": [asdict(a) for a in resolved_actors],
        "grounded_steps": [_grounded_step_to_dict(gs) for gs in grounded_steps],
    }


def _print_summary(resolved_actors: list[Actor], grounded_steps: list[GroundedStep]) -> None:
    print("=" * 70)
    print("RESOLVED ACTORS")
    print("=" * 70)
    for a in resolved_actors:
        ips = ", ".join(a.resolved_endpoints) if a.resolved_endpoints else "UNRESOLVED"
        print(f"  {a.actor_id:12s} ({a.role:10s}) -> {ips}")
        print(f"    basis: {a.resolution_basis}")

    print()
    print("=" * 70)
    print("GROUNDED STEPS")
    print("=" * 70)
    status_symbol = {
        "grounded": "\u2713",                    # check
        "unsupported": "\u2717",                 # x
        "uncertain_needs_drilldown": "?",
    }
    for gs in grounded_steps:
        g = gs.grounding
        symbol = status_symbol.get(g.status.value, " ")
        print(f"  [{symbol}] {gs.step.step_id}: {g.status.value}")
        print(f"      text: {gs.step.text}")
        if g.linked_packets:
            print(f"      linked_packets: {len(g.linked_packets)}")
        if g.linked_aggregate_refs:
            keys = ", ".join(r.fingerprint_key for r in g.linked_aggregate_refs)
            print(f"      linked_aggregates: {keys}")
        print(f"      notes: {g.notes}")
        print()

    total = len(grounded_steps)
    grounded = sum(1 for gs in grounded_steps if gs.grounding.status.value == "grounded")
    unsupported = sum(1 for gs in grounded_steps if gs.grounding.status.value == "unsupported")
    uncertain = sum(1 for gs in grounded_steps if gs.grounding.status.value == "uncertain_needs_drilldown")
    print("=" * 70)
    print(f"SUMMARY: {total} steps total | grounded={grounded} "
          f"unsupported={unsupported} uncertain={uncertain}")
    print("=" * 70)


def main():
    # Example usage of the EvidenceMatcher
    # This is a placeholder for actual test cases or integration with other components.

    with open("actors.json", "r") as f:
        data = json.load(f)
        actors = [Actor(**actor) for actor in data["actors"]]
    with open("steps.json", "r") as f:
        data = json.load(f)
        # NOTE: Step(**step) alone would leave expected_indicators as a
        # plain dict, not an ExpectedIndicators instance -- dataclasses
        # don't auto-convert nested dicts. ground_step() immediately
        # crashes on ei.protocol (AttributeError: 'dict' object has no
        # attribute 'protocol') without this explicit construction.
        steps = []
        for step in data["steps"]:
            step = dict(step)
            step["expected_indicators"] = ExpectedIndicators(**step.get("expected_indicators", {}))
            steps.append(Step(**step))
    with open("reduced_representation.json", "r") as f:
        data = json.load(f)
        reduced_representation = [EvidenceItem(**item) for item in data["reduced_representation"]]
    with open("fingerprint_index.json", "r") as f:
        data = json.load(f)
        fingerprint_index = {k: EvidenceAggregate(**v) for k, v in data["fingerprint_index"].items()}
    evidence_matcher = EvidenceMatcher()

    resolved_actors, grounded_steps = evidence_matcher.match(
        actors, steps, reduced_representation, fingerprint_index)

    _print_summary(resolved_actors, grounded_steps)

    output_path = "evidence_matcher_output.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(_serialize_result(resolved_actors, grounded_steps), f, indent=2, ensure_ascii=False)
    print(f"\nWrote full results to: {output_path}")


if __name__ == "__main__":
    main()