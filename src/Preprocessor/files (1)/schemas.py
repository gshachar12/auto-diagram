"""
PAnGEA — Preprocessing stage schemas.

Design constraints:
  R1  Referential Integrity       — every output item carries packet_id +
                                    timestamp back to the source PCAP.
  R2  Description-Blindness       — Attack Description never crosses into
                                    the Reducer. It is consumed only by
                                    layer0_attack_context.py, whose output
                                    (AttackContext) is a structured enum-
                                    constrained object, not free text.
  R3  Aggregate Traceability      — every dropped/folded packet leaves a
                                    quantitative trace; nothing vanishes
                                    silently.
  R4  Temporal Order Preservation — output preserves original chronological
                                    order; compression never reorders.
  R5  Budget Compliance           — best-effort, NOT silent truncation.
  R6  Protocol Agnosticism        — fingerprint logic never branches on
                                    attack type, only on structural protocol
                                    state.

Layer ownership:
  layer0  AttackContext           (this file: AttackContext, enums)
  layer1  PacketFeatures          (this file: PacketFeatures)
  layer2  fingerprint key         (layer2_fingerprint.py — no schema here)
  layer3  Cluster                 (this file: Cluster, AggregateStats)
  layer4  analysis metadata       (this file: ClusterMetadata, ClusterTier)
  output  ReducerOutput           (this file)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Optional


# ---------------------------------------------------------------------------
# Shared enums
# ---------------------------------------------------------------------------

class BudgetStatus(str, Enum):
    WITHIN_BUDGET = "within_budget"
    EXCEEDED = "exceeded"


class ClusterTier(str, Enum):
    """Assigned by layer4 analysis based on relevance to the AttackContext."""
    PRIMARY   = "primary"    # high TF-IDF weight, matches attack context signal
    SECONDARY = "secondary"  # low weight but structurally coherent
    REMNANT   = "remnant"    # background noise / no distinguishing signal


class EntropyBucket(str, Enum):
    LOW       = "low"        # [0, 3)   structured/repetitive
    MEDIUM    = "medium"     # [3, 5.5) readable protocol data
    HIGH      = "high"       # [5.5, 7) compressed or binary
    VERY_HIGH = "very_high"  # [7, 8]   encrypted or encoded


class PortClass(str, Enum):
    WELL_KNOWN  = "well_known"   # 0–1023
    REGISTERED  = "registered"   # 1024–49151
    EPHEMERAL   = "ephemeral"    # 49152–65535


# ---------------------------------------------------------------------------
# Layer 0 — AttackContext
# ---------------------------------------------------------------------------

class SuspectedProtocol(str, Enum):
    TCP  = "TCP"
    UDP  = "UDP"
    ICMP = "ICMP"
    ARP  = "ARP"
    DNS  = "DNS"     # L7, may ride on UDP or TCP
    HTTP = "HTTP"
    TLS  = "TLS"
    SSH  = "SSH"


class SuspectedBehavior(str, Enum):
    FLOOD           = "flood"
    UNANSWERED_SYN  = "unanswered_syn"
    AMPLIFICATION   = "amplification"
    EXFILTRATION    = "exfiltration"
    SCANNING        = "scanning"
    TUNNELING       = "tunneling"
    BEACONING       = "beaconing"
    SPOOFING        = "spoofing"


class TargetIndicator(str, Enum):
    SINGLE_DST   = "single_dst"    # all traffic aimed at one target
    HIGH_RATE    = "high_rate"     # abnormally high packet rate
    NO_RESPONSE  = "no_response"   # requests without replies
    MANY_SOURCES = "many_sources"  # distributed origin (DDoS)
    SINGLE_SRC   = "single_src"    # single attacker


@dataclass
class AttackContext:
    """
    Structured intent extracted from the free-text Attack Description.
    Produced by layer0_attack_context.py; consumed by layer4_analysis.py
    to weight cluster relevance. Never derived from pcap contents (R2).
    """
    suspected_protocols: list[SuspectedProtocol] = field(default_factory=list)
    suspected_behaviors: list[SuspectedBehavior] = field(default_factory=list)
    target_indicators:   list[TargetIndicator]   = field(default_factory=list)
    raw_description:     str                     = ""


# ---------------------------------------------------------------------------
# Layer 1 — PacketFeatures
# Populated layer-by-layer through the dissection sub-pipeline.
# layer1_dissection.py is the ONLY module that touches raw pyshark objects;
# everything downstream works exclusively on PacketFeatures.
# ---------------------------------------------------------------------------

@dataclass
class PacketFeatures:
    """
    Fully extracted, typed representation of a single packet.
    Fields are Optional because not every layer is present in every packet;
    the dissection pipeline populates what it can and leaves the rest None.
    """
    # Bookkeeping (R1)
    packet_id: int
    timestamp: float          # Unix epoch float for arithmetic (IAT, bucketing)
    timestamp_iso: str        # ISO-8601 string for human-readable output

    # L2
    l2_proto: Optional[str] = None          # "Ethernet", "ARP", ...
    src_mac:  Optional[str] = None
    dst_mac:  Optional[str] = None

    # L3
    l3_proto: Optional[str] = None          # "IP", "IPv6", "ARP"
    src_ip:   Optional[str] = None
    dst_ip:   Optional[str] = None

    # L4
    l4_proto:     Optional[str] = None      # "TCP", "UDP", "ICMP", "IP_RAW"
    src_port:     Optional[int] = None
    dst_port:     Optional[int] = None
    tcp_flags:    Optional[int] = None      # parsed bitmask
    tcp_flags_hex:Optional[str] = None      # raw hex string for fingerprint
    tcp_stream_id:Optional[str] = None
    icmp_type:    Optional[str] = None
    icmp_code:    Optional[str] = None
    arp_opcode:   Optional[str] = None
    arp_sender_mac: Optional[str] = None

    # L7
    l7_proto: Optional[str] = None          # "HTTP", "DNS", "TLS", "SSH", None

    # Payload
    payload_length:  int             = 0
    payload_entropy: Optional[float] = None
    entropy_bucket:  Optional[EntropyBucket] = None

    # Packet-level
    total_length: int = 0
    highest_layer: str = ""          # pyshark's raw highest_layer, kept for fallback


# ---------------------------------------------------------------------------
# Layer 3 — Cluster
# ---------------------------------------------------------------------------

@dataclass
class ReducedItem:
    """
    A single retained packet sample within a Cluster.
    Always carries a reference back to the original PCAP (R1).
    Pure packet record — no aggregate data lives here.
    """
    packet_id:       int
    timestamp:       str    # ISO-8601
    protocol:        str    # display protocol (highest meaningful layer)
    src:             str
    dst:             str
    length:          int
    info:            str    # human-readable fingerprint summary
    fingerprint_key: str


@dataclass
class AggregateStats:
    """
    Running statistics for all packets folded into a Cluster (R3).
    Always present and always up-to-date, even for singletons (count=1).
    """
    count:               int
    total_bytes:         int
    unique_sources:      list[str]
    unique_destinations: list[str]
    first_seen:          str           # ISO-8601 timestamp of first packet
    last_seen:           str           # ISO-8601 timestamp of last packet

    # Derived inter-arrival time stats (computed in layer3, updated per packet)
    iat_mean: Optional[float] = None   # seconds
    iat_std:  Optional[float] = None
    iat_min:  Optional[float] = None
    iat_max:  Optional[float] = None

    # Directionality: bytes flowing src→dst vs dst→src within the cluster.
    # Populated in layer4 where flow direction can be inferred from first-
    # packet initiator. None until layer4 runs.
    outbound_bytes: Optional[int] = None
    inbound_bytes:  Optional[int] = None


@dataclass
class ClusterMetadata:
    """
    Analysis-derived metadata assigned by layer4_analysis.py.
    None until layer4 has run; the Cluster is valid without it.
    """
    tier:             Optional[ClusterTier] = None
    traffic_share:    Optional[float]       = None  # fraction of total pcap bytes
    tfidf_weight:     Optional[float]       = None  # rareness score
    dst_port_class:   Optional[PortClass]   = None
    dst_port_service: Optional[str]         = None  # e.g. "DNS", "SSH", "unknown"
    zscore_anomalies: dict[str, float]      = field(default_factory=dict)
    # e.g. {"packet_rate": 3.7, "unique_sources": 2.1}
    context_match:    bool                  = False
    # True if this cluster matches any suspected_protocol/behavior in AttackContext


@dataclass
class Cluster:
    """
    The central unit of the reduced PCAP representation.

    A Cluster groups all packets sharing the same fingerprint_key (same
    structural signature + temporal bucket). It always has:
      - at least one representative_item (the first packet seen)
      - an always-up-to-date aggregate (even for singletons)
      - metadata populated after layer4 analysis

    Singletons are Clusters where aggregate.count == 1.
    There is no separate singleton structure.
    """
    fingerprint_key:      str
    representative_items: list[ReducedItem]    = field(default_factory=list)
    aggregate:            Optional[AggregateStats] = None
    metadata:             ClusterMetadata      = field(default_factory=ClusterMetadata)

    @property
    def is_singleton(self) -> bool:
        return self.aggregate is not None and self.aggregate.count == 1


# ---------------------------------------------------------------------------
# Output schemas
# ---------------------------------------------------------------------------

@dataclass
class CompressionStats:
    raw_packet_count_in:   int
    packet_count_out:      int    # total representative items across all clusters
    cluster_count:         int
    estimated_tokens_out:  int
    dropped_parse_failures:int
    compression_ratio:     float


@dataclass
class ReducerOutput:
    """
    Full output contract of the Preprocessor.

    clusters is the primary output — a flat list covering all tiers.
    Callers filter by cluster.metadata.tier for primary/secondary/remnant.

    fingerprint_index is a derived convenience lookup retained for
    compatibility with the downstream adapter in pipeline_runner.py
    (adapt_reducer_output). It mirrors aggregate data already in clusters
    and should not be treated as the source of truth.
    """
    clusters:              list[Cluster]
    compression_stats:     CompressionStats
    budget_status:         BudgetStatus
    attack_context:        Optional[AttackContext]  = None
    budget_status_detail:  Optional[str]            = None
    filter_string_used:    Optional[str]            = None  # kept for pipeline_runner compat

    @property
    def fingerprint_index(self) -> dict[str, AggregateStats]:
        """
        Compatibility shim for adapt_reducer_output() in pipeline_runner.py.
        Returns a dict keyed by fingerprint_key -> AggregateStats.
        """
        return {
            c.fingerprint_key: c.aggregate
            for c in self.clusters
            if c.aggregate is not None
        }

    @property
    def reduced_representation(self) -> list[ReducedItem]:
        """
        Compatibility shim for adapt_reducer_output() in pipeline_runner.py.
        Returns all representative items across all clusters, in insertion order.
        """
        items = []
        for cluster in self.clusters:
            items.extend(cluster.representative_items)
        return items
