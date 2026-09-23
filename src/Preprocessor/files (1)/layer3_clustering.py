"""
PAnGEA — Layer 3: Cluster Construction.

Responsibility: maintain a dict[fingerprint_key → Cluster] as packets
arrive, enforcing:

  - filtering_limit: how many raw ReducedItems to keep per cluster before
    folding into aggregate-only.
  - AggregateStats: always present, always up-to-date, even for singletons.
    Updated on EVERY packet, regardless of whether a ReducedItem is kept.
  - IAT (Inter-Arrival Time): tracked per cluster using the timestamp of
    the previous packet in that cluster. Stored as a running list and
    summarised (mean, std, min, max) when the cluster is finalised.
  - Token budget: checked before adding a ReducedItem. If exceeded, the
    item is dropped but the aggregate is still updated (R3 — nothing
    vanishes silently even under budget pressure).

Input:  PacketFeatures (from layer 1) + fingerprint_key (from layer 2)
Output: dict[str, Cluster]  — handed to layer 4 for analysis
"""
from __future__ import annotations

import logging
import math
from typing import Optional

from Preprocessor.schemas import (
    AggregateStats,
    Cluster,
    ClusterMetadata,
    ReducedItem,
)
from Preprocessor.token_budget import estimate_item_tokens
from Preprocessor.schemas import PacketFeatures, BudgetStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry point — called once per packet from preprocessor.py
# ---------------------------------------------------------------------------

def process_packet(
    features: PacketFeatures,
    fingerprint_key: str,
    clusters: dict[str, Cluster],
    _iat_scratch: dict[str, list[float]],    # fingerprint_key → list of IAT values
    _last_ts: dict[str, float],              # fingerprint_key → timestamp of prev packet
    filtering_limit: int,
    token_budget: int,
    running_tokens: int,
) -> tuple[int, BudgetStatus, Optional[str]]:
    """
    Integrate one packet into the cluster index.

    Args:
        features:         dissected packet from layer 1.
        fingerprint_key:  string key from layer 2.
        clusters:         mutable cluster dict — updated in place.
        _iat_scratch:     mutable scratch space for IAT calculation — updated in place.
        _last_ts:         mutable last-timestamp tracker — updated in place.
        filtering_limit:  max ReducedItems to keep per cluster.
        token_budget:     total token budget for ReducedItems.
        running_tokens:   tokens consumed so far.

    Returns:
        (new_running_tokens, budget_status, budget_detail)
        budget_status is EXCEEDED only if a ReducedItem was attempted but
        would push past the budget. The aggregate is still updated.
    """
    src = features.src_ip or features.src_mac or "N/A"
    dst = features.dst_ip or features.dst_mac or "N/A"
    proto = _display_protocol(features)
    timestamp_iso = features.timestamp_iso

    # -----------------------------------------------------------------------
    # IAT update (before anything else — we want this even on budget exceeded)
    # -----------------------------------------------------------------------
    if fingerprint_key in _last_ts:
        iat = features.timestamp - _last_ts[fingerprint_key]
        _iat_scratch.setdefault(fingerprint_key, []).append(iat)
    _last_ts[fingerprint_key] = features.timestamp

    # -----------------------------------------------------------------------
    # New fingerprint — create cluster
    # -----------------------------------------------------------------------
    if fingerprint_key not in clusters:
        item = ReducedItem(
            packet_id=features.packet_id,
            timestamp=timestamp_iso,
            protocol=proto,
            src=src,
            dst=dst,
            length=features.total_length,
            info=_make_info(features),
            fingerprint_key=fingerprint_key,
        )
        item_tokens = estimate_item_tokens(vars(item))

        if running_tokens + item_tokens > token_budget:
            # Can't even store the representative — still create the cluster
            # but with an empty representative list (R3: aggregate is created).
            aggregate = AggregateStats(
                count=1,
                total_bytes=features.total_length,
                unique_sources=[src],
                unique_destinations=[dst],
                first_seen=timestamp_iso,
                last_seen=timestamp_iso,
            )
            clusters[fingerprint_key] = Cluster(
                fingerprint_key=fingerprint_key,
                representative_items=[],
                aggregate=aggregate,
                metadata=ClusterMetadata(),
            )
            return running_tokens, BudgetStatus.EXCEEDED, (
                f"stopped before packet_id={features.packet_id} "
                f"(timestamp={timestamp_iso})"
            )

        aggregate = AggregateStats(
            count=1,
            total_bytes=features.total_length,
            unique_sources=[src],
            unique_destinations=[dst],
            first_seen=timestamp_iso,
            last_seen=timestamp_iso,
        )
        clusters[fingerprint_key] = Cluster(
            fingerprint_key=fingerprint_key,
            representative_items=[item],
            aggregate=aggregate,
            metadata=ClusterMetadata(),
        )
        return running_tokens + item_tokens, BudgetStatus.WITHIN_BUDGET, None

    # -----------------------------------------------------------------------
    # Existing fingerprint — update aggregate, maybe add representative item
    # -----------------------------------------------------------------------
    cluster = clusters[fingerprint_key]
    agg = cluster.aggregate

    agg.count += 1
    agg.total_bytes += features.total_length
    agg.last_seen = timestamp_iso
    if src not in agg.unique_sources:
        agg.unique_sources.append(src)
    if dst not in agg.unique_destinations:
        agg.unique_destinations.append(dst)

    if agg.count <= filtering_limit:
        item = ReducedItem(
            packet_id=features.packet_id,
            timestamp=timestamp_iso,
            protocol=proto,
            src=src,
            dst=dst,
            length=features.total_length,
            info=_make_info(features),
            fingerprint_key=fingerprint_key,
        )
        item_tokens = estimate_item_tokens(vars(item))

        if running_tokens + item_tokens > token_budget:
            # Budget exceeded — skip this item but aggregate already updated
            return running_tokens, BudgetStatus.EXCEEDED, (
                f"stopped before packet_id={features.packet_id} "
                f"(timestamp={timestamp_iso})"
            )

        cluster.representative_items.append(item)
        running_tokens += item_tokens

    return running_tokens, BudgetStatus.WITHIN_BUDGET, None


# ---------------------------------------------------------------------------
# Finalisation — called after all packets have been processed
# ---------------------------------------------------------------------------

def finalise_clusters(
    clusters: dict[str, Cluster],
    _iat_scratch: dict[str, list[float]],
) -> list[Cluster]:
    """
    Finalise all clusters: compute IAT summary statistics and return
    as a list (order preserved from dict insertion, i.e. chronological
    order of first appearance).
    """
    for fkey, cluster in clusters.items():
        iats = _iat_scratch.get(fkey, [])
        if iats:
            cluster.aggregate.iat_mean = _mean(iats)
            cluster.aggregate.iat_std  = _std(iats)
            cluster.aggregate.iat_min  = min(iats)
            cluster.aggregate.iat_max  = max(iats)

    return list(clusters.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _display_protocol(features: PacketFeatures) -> str:
    """Human-readable protocol label for ReducedItem.protocol."""
    if features.l7_proto:
        return features.l7_proto
    if features.l4_proto:
        return features.l4_proto
    if features.l3_proto:
        return features.l3_proto
    return features.highest_layer or "UNKNOWN"


def _make_info(features: PacketFeatures) -> str:
    """Human-readable summary line for ReducedItem.info."""
    parts = []
    if features.l4_proto == "TCP" and features.tcp_flags_hex:
        parts.append(f"Flags:{features.tcp_flags_hex}")
    if features.l4_proto == "ICMP":
        parts.append(f"Type:{features.icmp_type} Code:{features.icmp_code}")
    if features.l4_proto == "ARP":
        parts.append(f"Op:{features.arp_opcode}")
    if features.dst_port is not None:
        parts.append(f"DPort:{features.dst_port}")
    if features.l7_proto:
        parts.append(f"L7:{features.l7_proto}")
    if features.entropy_bucket:
        parts.append(f"Entropy:{features.entropy_bucket.value}")
    return " | ".join(parts) if parts else features.highest_layer


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / len(values)
    return math.sqrt(variance)
