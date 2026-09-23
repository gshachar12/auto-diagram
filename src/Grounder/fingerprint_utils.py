"""
Data contract for the Preprocessor's output, which the Grounder consumes as-is
(per spec: "Fingerprint_index - the lookup structure built during Preprocessing's
compression pass, reused here rather than rebuilt").

The spec does not pin down an exact wire format for Reduced_representation /
Fingerprint_index, only the invariants they must satisfy (R1-R5). This module
defines a concrete shape consistent with those invariants, plus helper functions
the Evidence Matcher relies on. If your Preprocessor implementation uses a
different shape, adapt `evidence_matcher.py`'s calls into this module rather than
touching the matching logic itself.

Reduced PCAP item (raw sample), one per retained packet:
    {
        "packet_id": <int>,           # R1: reference back to original PCAP
        "timestamp": <float>,         # R1/R2
        "protocol": "TCP"|"UDP"|"ICMP"|"ARP"|"DNS"|"HTTP"|...,
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.17",
        "src_port": 443,              # None for protocols without ports
        "dst_port": 51820,
        "flags": ["SYN"],             # TCP flags, ARP opcode, ICMP type/code, etc.
        "length": 60,                 # bytes, for volume/cardinality stats
    }

Fingerprint_index entry, one per structural fingerprint bucket (per spec Reducer:
"Bucket by fingerprint; retain first Filtering_limit raw instances per bucket;
fold the rest into aggregate stats attached to the first retained instance"):
    {
        "fingerprint_key": "TCP|SYN|445",
        "protocol": "TCP",
        "raw_packet_ids": [101, 102, 105],   # R1: retained raw instances in this bucket
        "aggregate": {                        # R3: trace of everything folded in
            "count": 4231,
            "bytes": 253860,
            "unique_src": ["203.0.113.17"],
            "unique_dst": ["10.0.0.5", "10.0.0.6", "10.0.0.7"],
        },
    }
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional


def build_fingerprint_key(
    protocol: Optional[str],
    port: Optional[int] = None,
    flags: Optional[list[str]] = None,
) -> Optional[str]:
    """Build a lookup key mirroring the Reducer's structural fingerprinting logic
    (per spec: "TCP flag/stream-state, UDP port, ARP opcode+MAC, ICMP type/code").

    Returns None if there isn't enough structured signal to fingerprint at all.
    """
    if not protocol:
        return None
    protocol = protocol.upper()
    parts = [protocol]
    if protocol == "TCP":
        parts.append("+".join(sorted(flags)) if flags else "ANY")
    elif protocol == "UDP":
        parts.append(str(port) if port is not None else "ANY")
    elif protocol == "ICMP":
        parts.append("+".join(sorted(flags)) if flags else "ANY")  # flags carries type/code here
    elif protocol == "ARP":
        parts.append("+".join(sorted(flags)) if flags else "ANY")  # flags carries opcode(+MAC) here
    else:
        # Generic fallback for protocols not explicitly enumerated in the spec (DNS/HTTP/...).
        parts.append(str(port) if port is not None else "ANY")
    return "|".join(parts)


class IPBehaviorProfile:
    """Per-IP behavioral stats derived from the Reduced PCAP, used for Actor
    Resolution's structural-signature matching (spec: e.g. "attacker" -> source
    with high destination-cardinality, consistent with scanning behavior).

    Built once per Grounder run and reused across all actors/Steps - this keeps
    Actor Resolution close to O(P) rather than re-scanning per actor.
    """

    def __init__(self, reduced_pcap: list[dict[str, Any]], fingerprint_index: dict[str, dict[str, Any]]):
        self.dst_count_by_src: dict[str, set[str]] = defaultdict(set)
        self.src_count_by_dst: dict[str, set[str]] = defaultdict(set)
        self.packet_count_by_ip: dict[str, int] = defaultdict(int)
        self.ports_touched_by_ip: dict[str, set[int]] = defaultdict(set)

        for pkt in reduced_pcap:
            src, dst = pkt.get("src_ip"), pkt.get("dst_ip")
            if src and dst:
                self.dst_count_by_src[src].add(dst)
                self.src_count_by_dst[dst].add(src)
            if src:
                self.packet_count_by_ip[src] += 1
                if pkt.get("src_port") is not None:
                    self.ports_touched_by_ip[src].add(pkt["src_port"])
            if dst:
                self.packet_count_by_ip[dst] += 1
                if pkt.get("dst_port") is not None:
                    self.ports_touched_by_ip[dst].add(pkt["dst_port"])

        # Also fold in aggregate-only evidence so IPs that only appear in folded
        # buckets (R3: nothing vanishes without a trace) still contribute signal.
        for entry in fingerprint_index.values():
            agg = entry.get("aggregate", {})
            for src in agg.get("unique_src", []):
                for dst in agg.get("unique_dst", []):
                    self.dst_count_by_src[src].add(dst)
                    self.src_count_by_dst[dst].add(src)

    def destination_cardinality(self, ip: str) -> int:
        return len(self.dst_count_by_src.get(ip, ()))

    def source_cardinality(self, ip: str) -> int:
        return len(self.src_count_by_dst.get(ip, ()))

    def all_ips(self) -> set[str]:
        return set(self.dst_count_by_src) | set(self.src_count_by_dst)
