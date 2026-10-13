"""
PAnGEA — Layer 4: Cluster Analysis.

Responsibility: enrich each Cluster with analysis-derived metadata and
assign a relevance tier (PRIMARY / SECONDARY / REMNANT). Also produces
two supplementary outputs consumed by the downstream adapter:

  - ip_summary:  per-IP structural summary (who sent what, to whom, how much)
  - anomalies:   fingerprints with unusually high cardinality relative to
                 the per-protocol baseline in this capture

Analysis steps (in order):
  1. Traffic share    — each cluster's fraction of total pcap bytes.
  2. TF-IDF weight    — rare signatures score high; background noise scores low.
  3. Per-protocol Z-scores — anomaly scores computed within each protocol
                 family (TCP vs TCP, UDP vs UDP), not across all clusters.
                 Log-transformed + MAD-based for robustness to heavy tails.
  4. Context match    — cluster protocol matches AttackContext suspects.
  5. Port metadata    — dst_port_class and dst_port_service name.
  6. Tier assignment  — combines TF-IDF, Z-scores, context match.
  7. IP summary       — per-IP structural profile across all clusters.
  8. Anomaly detection — per-protocol cardinality fanout anomalies.

Z-score design note:
  Scores are computed per-protocol-family, not across all clusters.
  A SYN cluster is compared to other SYN/TCP clusters, not to DNS clusters.
  This avoids the false positive where "everything looks anomalous" when
  the pcap is dominated by one protocol type. The baseline is always this
  capture's own per-protocol population — there is no external "normal"
  reference. This limitation should be documented: Z-scores are meaningful
  only when the pcap contains a mixture of normal and abnormal traffic.
"""
from __future__ import annotations

import json
import logging
import math
import statistics
from collections import defaultdict
from typing import Optional

from Preprocessor.schemas import (
    AttackContext,
    Cluster,
    ClusterMetadata,
    ClusterTier,
    PortClass,
    SuspectedProtocol,
)
from Preprocessor.layer4_serialization import serialize_cluster

logger = logging.getLogger(__name__)

# Tier assignment thresholds — tunable.
_PRIMARY_TFIDF_THRESHOLD   = 0.6
_PRIMARY_ZSCORE_THRESHOLD  = 2.0
_REMNANT_TFIDF_THRESHOLD   = 0.15

# IP summary caps (mirrors evidence_matcher.py's defaults)
_MAX_IPS                   = 50
_MAX_FINGERPRINTS_PER_IP   = 3
_MAX_SAMPLES_PER_IP        = 3

_PORT_SERVICE: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP",     53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP",     110: "POP3", 143: "IMAP", 161: "SNMP",
    443: "HTTPS/TLS", 445: "SMB", 465: "SMTPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB",
}

_L7_TO_SUSPECTED: dict[str, SuspectedProtocol] = {
    "HTTP": SuspectedProtocol.HTTP, "HTTP2": SuspectedProtocol.HTTP,
    "TLS":  SuspectedProtocol.TLS,  "DNS":   SuspectedProtocol.DNS,
    "SSH":  SuspectedProtocol.SSH,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyse_clusters(
    clusters: list[Cluster],
    attack_context: Optional[AttackContext],
    total_bytes: int,
) -> tuple[list[Cluster], list[dict], list[dict]]:
    """
    Enrich clusters with metadata, assign tiers, and produce supplementary
    IP summary and anomaly outputs.

    Returns:
        (enriched clusters, ip_summary, anomalies)
    """
    if not clusters:
        return clusters, [], []

    _compute_traffic_shares(clusters, total_bytes)
    _compute_tfidf(clusters)
    _compute_per_protocol_zscores(clusters)
    _compute_port_metadata(clusters)
    _compute_context_match(clusters, attack_context)
    _assign_tiers(clusters)

    anomalies  = build_anomalies(clusters)
    ip_summary = build_ip_summary(clusters, anomalies)

    # Serialization last — it reads every metadata field set above.
    for cluster in clusters:
        cluster.metadata.cluster_text = serialize_cluster(cluster)

    return clusters, ip_summary, anomalies


# ---------------------------------------------------------------------------
# Step 1 — Traffic share
# ---------------------------------------------------------------------------

def _compute_traffic_shares(clusters: list[Cluster], total_bytes: int) -> None:
    if total_bytes == 0:
        return
    for cluster in clusters:
        if cluster.aggregate:
            cluster.metadata.traffic_share = (
                cluster.aggregate.total_bytes / total_bytes
            )


# ---------------------------------------------------------------------------
# Step 2 — TF-IDF
# ---------------------------------------------------------------------------

def _compute_tfidf(clusters: list[Cluster]) -> None:
    total_packets = sum(c.aggregate.count for c in clusters if c.aggregate)
    n_clusters = len(clusters)
    if total_packets == 0 or n_clusters == 0:
        return

    # Each packet is a document with one word (its fingerprint), so TF = 1
    # and only IDF matters: log(total_packets / count). Rare = high score.
    raw_scores = []
    max_tfidf = 0.0

    for cluster in clusters:
        if not cluster.aggregate or cluster.aggregate.count == 0:
            raw_scores.append(0.0)
            continue
        score = math.log(total_packets / cluster.aggregate.count)
        raw_scores.append(score)
        max_tfidf = max(max_tfidf, score)

    for cluster, score in zip(clusters, raw_scores):
        cluster.metadata.tfidf_weight = (
            score / max_tfidf if max_tfidf > 0 else 0.0
        )


# ---------------------------------------------------------------------------
# Step 3 — Per-protocol Z-scores (log-transformed, MAD-based)
#
# Key design decision vs a naive cross-cluster Z-score:
#   We group clusters by their L4 protocol family extracted from the
#   fingerprint key, then compute Z-scores WITHIN each group.
#   A SYN-flood cluster is anomalous relative to OTHER TCP clusters,
#   not relative to DNS or ARP clusters — comparing across protocol
#   families produces meaningless scores because the distributions
#   are completely different (TCP packet rates vs ARP counts).
#
# Dimensions analysed per cluster:
#   - packet_rate    (count / duration seconds)
#   - byte_volume    (total_bytes)
#   - src_cardinality (unique_sources count)
#   - dst_cardinality (unique_destinations count)
#   - iat_mean       (mean inter-arrival time, if available)
# ---------------------------------------------------------------------------

_ZSCORE_DIMS = ["packet_rate", "byte_volume", "src_cardinality",
                "dst_cardinality", "iat_mean"]


def _compute_per_protocol_zscores(clusters: list[Cluster]) -> None:
    # Group clusters by L4 proto extracted from fingerprint key
    by_proto: dict[str, list[Cluster]] = defaultdict(list)
    for cluster in clusters:
        proto = _extract_l4_proto(cluster.fingerprint_key) or "UNKNOWN"
        by_proto[proto].append(cluster)

    for proto, proto_clusters in by_proto.items():
        if len(proto_clusters) < 2:
            # Can't compute a meaningful within-group baseline with one member.
            # Assign zero scores rather than leaving anomalies empty.
            for c in proto_clusters:
                c.metadata.zscore_anomalies = {}
            continue
        _zscore_cluster_group(proto_clusters)


def _zscore_cluster_group(clusters: list[Cluster]) -> None:
    """Compute MAD-based Z-scores for a group of same-protocol clusters."""
    vectors: dict[str, list[float]] = {dim: [] for dim in _ZSCORE_DIMS}

    for cluster in clusters:
        agg = cluster.aggregate
        if not agg:
            for dim in _ZSCORE_DIMS:
                vectors[dim].append(0.0)
            continue

        duration = _cluster_duration_seconds(agg) # duration of the whole cluster (from first to last packet)
        vectors["packet_rate"].append(
            agg.count / duration if duration > 0 else float(agg.count)
        )
        vectors["byte_volume"].append(float(agg.total_bytes))
        vectors["src_cardinality"].append(float(len(agg.unique_sources))) # source cardinality
        vectors["dst_cardinality"].append(float(len(agg.unique_destinations))) # destination cardinality
        vectors["iat_mean"].append(
            agg.iat_mean if agg.iat_mean is not None else 0.0
        )

    # Log-transform (heavy-tailed distributions)
    log_vectors = {
        dim: [math.log1p(v) for v in vals]
        for dim, vals in vectors.items()
    }

    # MAD-based Z-scores: robust to the outliers we're trying to detect
    zscores_per_dim: dict[str, list[float]] = {}
    for dim, log_vals in log_vectors.items():
        med = _median(log_vals)
        mad = _mad(log_vals, med)
        if mad == 0:
            zscores_per_dim[dim] = [0.0] * len(log_vals)
        else:
            # 1.4826 makes MAD consistent with std for normal distributions
            zscores_per_dim[dim] = [
                abs(v - med) / (mad * 1.4826) for v in log_vals
            ]

    for i, cluster in enumerate(clusters):
        anomalies: dict[str, float] = {}
        for dim in _ZSCORE_DIMS:
            score = zscores_per_dim[dim][i]
            if score > 0.01:
                anomalies[dim] = round(score, 3)
        cluster.metadata.zscore_anomalies = anomalies


# ---------------------------------------------------------------------------
# Step 4 — Context match
# ---------------------------------------------------------------------------

def _behavior_match_score(
    cluster: Cluster,
    all_clusters: list[Cluster],
    attack_context: Optional[AttackContext],
) -> bool:
    """
    Check whether this cluster's statistical profile matches any
    suspected_behavior in the AttackContext.
    Returns True if at least one behavior matches.
    """
    if not attack_context or not attack_context.suspected_behaviors:
        return False

    agg  = cluster.aggregate
    meta = cluster.metadata
    if not agg:
        return False

    behaviors = {b.value for b in attack_context.suspected_behaviors}
    matched = False

    # flood — high packet rate, very low IAT
    if "flood" in behaviors:
        if (agg.iat_mean is not None and agg.iat_mean < 0.01
                and meta.zscore_anomalies.get("packet_rate", 0) > 2.0):
            matched = True

    # unanswered_syn — look for a SYN cluster with no corresponding
    # SYN-ACK cluster of comparable size in the same time bucket
    if "unanswered_syn" in behaviors:
        state = _extract_state_sig(cluster.fingerprint_key)
        if state == "SYN":
            time_bucket = _extract_time_bucket(cluster.fingerprint_key)
            dst_port    = _extract_dst_port(cluster.fingerprint_key)
            # Find the SYN-ACK cluster for same port and time bucket
            synack_count = next(
                (
                    c.aggregate.count for c in all_clusters
                    if _extract_state_sig(c.fingerprint_key) == "SYN-ACK"
                    and _extract_dst_port(c.fingerprint_key) == dst_port
                    and _extract_time_bucket(c.fingerprint_key) == time_bucket
                    and c.aggregate
                ),
                0,
            )
            # Unanswered if SYN count is at least 10x the SYN-ACK count
            if synack_count == 0 or (agg.count / synack_count) > 10:
                matched = True

    # scanning — many unique destinations, few unique sources
    if "scanning" in behaviors:
        if (len(agg.unique_destinations) > 10
                and len(agg.unique_sources) <= 2):
            matched = True

    # beaconing — very regular IAT (low std relative to mean)
    if "beaconing" in behaviors:
        if (agg.iat_mean and agg.iat_std is not None
                and agg.iat_mean > 0
                and (agg.iat_std / agg.iat_mean) < 0.1):
            matched = True

    # exfiltration — outbound bytes >> inbound
    if "exfiltration" in behaviors:
        if (agg.outbound_bytes and agg.inbound_bytes is not None
                and agg.inbound_bytes > 0
                and (agg.outbound_bytes / agg.inbound_bytes) > 10):
            matched = True

    # amplification — inbound bytes >> outbound
    if "amplification" in behaviors:
        if (agg.inbound_bytes and agg.outbound_bytes is not None
                and agg.outbound_bytes > 0
                and (agg.inbound_bytes / agg.outbound_bytes) > 10):
            matched = True

    return matched

def _compute_context_match(
    clusters: list[Cluster],
    attack_context: Optional[AttackContext],
) -> None:
    if not attack_context:
        return

    suspected_proto_values = {p.value for p in attack_context.suspected_protocols}

    for cluster in clusters:
        # Protocol match (existing)
        l4 = _extract_l4_proto(cluster.fingerprint_key)
        if l4 and l4.upper() in suspected_proto_values:
            cluster.metadata.context_match = True
            continue

        l7 = _extract_l7_proto(cluster.fingerprint_key)
        if l7 and l7.upper() in suspected_proto_values:
            cluster.metadata.context_match = True
            continue

        # Behavior match (new) — checked only if protocol didn't already match
        if _behavior_match_score(cluster, clusters, attack_context):
            cluster.metadata.context_match = True

# ---------------------------------------------------------------------------
# Step 5 — Port metadata
# ---------------------------------------------------------------------------

def _compute_port_metadata(clusters: list[Cluster]) -> None:
    for cluster in clusters:
        port = _extract_dst_port(cluster.fingerprint_key)
        if port is None:
            continue
        cluster.metadata.dst_port_class   = _classify_port(port)
        cluster.metadata.dst_port_service = _PORT_SERVICE.get(port, "unknown")


def _classify_port(port: int) -> PortClass:
    if port < 1024:
        return PortClass.WELL_KNOWN
    if port < 49152:
        return PortClass.REGISTERED
    return PortClass.EPHEMERAL


# ---------------------------------------------------------------------------
# Step 6 — Tier assignment
# ---------------------------------------------------------------------------

def _assign_tiers(clusters: list[Cluster]) -> None:
    for cluster in clusters:
        meta    = cluster.metadata
        tfidf   = meta.tfidf_weight or 0.0
        context = meta.context_match
        max_z   = max(meta.zscore_anomalies.values(), default=0.0)

        is_high_tfidf = tfidf >= _PRIMARY_TFIDF_THRESHOLD
        is_anomalous  = max_z  >= _PRIMARY_ZSCORE_THRESHOLD
        is_low_tfidf  = tfidf  <  _REMNANT_TFIDF_THRESHOLD

        if (is_high_tfidf or is_anomalous) and context:
            meta.tier = ClusterTier.PRIMARY
        elif is_anomalous:
            # Anomalous but no context match — still worth surfacing
            meta.tier = ClusterTier.SECONDARY
        elif is_low_tfidf and not context and max_z < 1.0:
            meta.tier = ClusterTier.REMNANT
        else:
            meta.tier = ClusterTier.SECONDARY


# ---------------------------------------------------------------------------
# Step 7 — IP Summary
#
# Per-IP structural profile — role-agnostic, computed once from clusters.
# Mirrors _build_ip_summary_table in evidence_matcher.py but works
# on Cluster / AggregateStats instead of EvidenceAggregate.
#
# Four properties per IP:
#   - packets_as_source / packets_as_destination: traffic volume
#   - unique_destinations / unique_sources: fanout cardinality
#   - top_source_fingerprints / top_destination_fingerprints: WHAT traffic
#     (a pure count can't tell scanner from heavy legitimate user)
#   - anomaly_involvement: which anomalies this IP appears in, and on which side
#   - sample_packets: first few packets, timestamp-ordered (captures who acted first)
# ---------------------------------------------------------------------------

def build_ip_summary(
    clusters: list[Cluster],
    anomalies: list[dict],
) -> list[dict]:
    """
    Compact per-IP structural summary across all clusters.
    Capped to _MAX_IPS most active IPs; tail is summarised, not enumerated.
    """
    src_counts:          dict[str, int]       = defaultdict(int)
    dst_counts:          dict[str, int]       = defaultdict(int)
    src_to_dsts:         dict[str, set]       = defaultdict(set)
    dst_to_srcs:         dict[str, set]       = defaultdict(set)
    src_to_dst_ports:    dict[str, set]       = defaultdict(set)
    dst_to_src_ports:    dict[str, set]       = defaultdict(set)
    src_fingerprint_counts: dict[str, dict[str, int]] = defaultdict(dict)
    dst_fingerprint_counts: dict[str, dict[str, int]] = defaultdict(dict)

    for cluster in clusters:
        agg  = cluster.aggregate
        fkey = cluster.fingerprint_key
        if not agg:
            continue

        dst_port = _extract_dst_port(fkey)

        for src in agg.unique_sources:
            src_counts[src]          += agg.count
            src_to_dsts[src].update(agg.unique_destinations)
            if dst_port is not None:
                src_to_dst_ports[src].add(dst_port)
            src_fingerprint_counts[src][fkey] = (
                src_fingerprint_counts[src].get(fkey, 0) + agg.count
            )

        for dst in agg.unique_destinations:
            dst_counts[dst]          += agg.count
            dst_to_srcs[dst].update(agg.unique_sources)
            if dst_port is not None:
                dst_to_src_ports[dst].add(dst_port)
            dst_fingerprint_counts[dst][fkey] = (
                dst_fingerprint_counts[dst].get(fkey, 0) + agg.count
            )

    # Precompute anomaly involvement per IP
    anomaly_involvement: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: {"as_source": [], "as_destination": []}
    )
    for anomaly in anomalies:
        fkey = anomaly.get("fingerprint_key", "?")
        for ip in anomaly.get("unique_sources", []):
            anomaly_involvement[ip]["as_source"].append(fkey)
        for ip in anomaly.get("unique_destinations", []):
            anomaly_involvement[ip]["as_destination"].append(fkey)

    # Per-IP sample packets (from representative items, timestamp-sorted)
    ip_samples: dict[str, list] = defaultdict(list)
    for cluster in clusters:
        for item in cluster.representative_items:
            ip_samples[item.src].append(item)
            ip_samples[item.dst].append(item)

    def _top_fingerprints(fp_counts: dict[str, int]) -> list[dict]:
        ranked = sorted(fp_counts.items(), key=lambda kv: kv[1], reverse=True)
        return [
            {"fingerprint_key": k, "count": c}
            for k, c in ranked[:_MAX_FINGERPRINTS_PER_IP]
        ]

    def _sample_packets(ip: str) -> list[dict]:
        items = sorted(ip_samples.get(ip, []), key=lambda it: it.timestamp)
        return [
            {
                "packet_id": it.packet_id,
                "timestamp":  it.timestamp,
                "protocol":   it.protocol,
                "src":        it.src,
                "dst":        it.dst,
                "length":     it.length,
                "info":       it.info,
            }
            for it in items[:_MAX_SAMPLES_PER_IP]
        ]

    all_ips = set(src_counts) | set(dst_counts)
    full_table = [
        {
            "ip": ip,
            "total_traffic": src_counts.get(ip, 0) + dst_counts.get(ip, 0),
            "packets_as_source":      src_counts.get(ip, 0),
            "packets_as_destination": dst_counts.get(ip, 0),
            # Unique IP addresses that this IP has communicated with
            "unique_destinations":    len(src_to_dsts.get(ip, set())),
            "unique_sources":         len(dst_to_srcs.get(ip, set())),
            "unique_dst_ports":       len(src_to_dst_ports.get(ip, set())),
            "unique_src_ports":       len(dst_to_src_ports.get(ip, set())),
            "top_source_fingerprints":
                _top_fingerprints(src_fingerprint_counts.get(ip, {})),
            "top_destination_fingerprints":
                _top_fingerprints(dst_fingerprint_counts.get(ip, {})),
            "anomaly_involvement":
                dict(anomaly_involvement.get(ip, {"as_source": [], "as_destination": []})),
            "sample_packets": _sample_packets(ip),
        }
        for ip in all_ips
    ]

    # Sort by total traffic volume; cap to max_ips
    full_table.sort(key=lambda row: row["total_traffic"], reverse=True)
    if len(full_table) > _MAX_IPS:
        tail = full_table[_MAX_IPS:]
        full_table = full_table[:_MAX_IPS]
        full_table.append({
            "ip": f"[{len(tail)} additional IPs not shown]",
            "total_traffic": sum(r["total_traffic"] for r in tail),
            "packets_as_source":      sum(r["packets_as_source"] for r in tail),
            "packets_as_destination": sum(r["packets_as_destination"] for r in tail),
            "unique_destinations": None,
            "unique_sources":      None,
            "note": "tail summarised — individual IPs omitted to stay within token budget",
        })

    return full_table


# ---------------------------------------------------------------------------
# Step 8 — Anomaly detection
#
# Per-protocol cardinality fanout: a fingerprint associated with an
# unusually HIGH number of distinct counterpart addresses, relative to
# the median cardinality of other fingerprints of the SAME protocol.
#
# This is more principled than a cross-protocol Z-score because it
# compares like with like: an ARP entry is anomalous relative to other
# ARP entries, not relative to DNS or TCP entries.
#
# Mirrors _find_identity_fanout_anomalies in evidence_matcher.py.
# ---------------------------------------------------------------------------

def build_anomalies(clusters: list[Cluster]) -> list[dict]:
    """
    Find clusters with unusually high source or destination cardinality
    relative to the per-protocol median in this capture.
    """
    # Group clusters by L4 proto
    by_proto: dict[str, list[tuple[Cluster, int, int]]] = defaultdict(list)
    for cluster in clusters:
        agg = cluster.aggregate
        if not agg:
            continue
        proto = _extract_l4_proto(cluster.fingerprint_key) or "UNKNOWN"
        src_card = len(agg.unique_sources) # source cardinality
        dst_card = len(agg.unique_destinations) # destination cardinality
        by_proto[proto].append((cluster, src_card, dst_card)) # by_proto = {proto: [(cluster, src_card, dst_card), ...]}

    anomalies = []
    for proto, entries in by_proto.items():
        if len(entries) < 2: 
            continue  # no meaningful baseline with only one cluster

        src_baseline = statistics.median(e[1] for e in entries) # median source cardinality
        dst_baseline = statistics.median(e[2] for e in entries) # median destination cardinality

        for cluster, src_card, dst_card in entries:
            agg = cluster.aggregate
            src_anomalous = src_card > 1 and src_card > src_baseline
            dst_anomalous = dst_card > 1 and dst_card > dst_baseline
            if not (src_anomalous or dst_anomalous):
                continue

            anomalies.append({
                "fingerprint_key":   cluster.fingerprint_key,
                "protocol":          proto,
                "tier":              cluster.metadata.tier.value
                                     if cluster.metadata.tier else None,
                "source_cardinality":         src_card,
                "source_cardinality_anomalous": src_anomalous,
                "typical_source_cardinality":  src_baseline,
                "destination_cardinality":         dst_card,
                "destination_cardinality_anomalous": dst_anomalous,
                "typical_destination_cardinality":   dst_baseline,
                "unique_sources":      list(agg.unique_sources),
                "unique_destinations": list(agg.unique_destinations),
                "count":               agg.count,
            })

    return anomalies


# ---------------------------------------------------------------------------
# Fingerprint key field extractors
# key_parts = [l4_proto, state_sig, l7_proto, dst_port, entropy_bucket, time_bucket]
# ---------------------------------------------------------------------------

def _extract_l4_proto(fkey: str) -> Optional[str]:
    try:
        return json.loads(fkey)[0]
    except (json.JSONDecodeError, IndexError):
        return None


def _extract_l7_proto(fkey: str) -> Optional[str]:
    try:
        return json.loads(fkey)[2]
    except (json.JSONDecodeError, IndexError):
        return None


def _extract_dst_port(fkey: str) -> Optional[int]:
    try:
        val = json.loads(fkey)[3]
        return int(val) if val is not None else None
    except (json.JSONDecodeError, IndexError, TypeError, ValueError):
        return None

def _extract_state_sig(fkey: str) -> Optional[str]:
    try:
        return json.loads(fkey)[1]
    except (json.JSONDecodeError, IndexError):
        return None


def _extract_time_bucket(fkey: str) -> Optional[int]:
    try:
        val = json.loads(fkey)[5]
        return int(val) if val is not None else None
    except (json.JSONDecodeError, IndexError, TypeError, ValueError):
        return None


# _extract_dst_port already exists — no change needed

# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def _cluster_duration_seconds(agg) -> float:
    try:
        from datetime import datetime
        t0 = datetime.fromisoformat(agg.first_seen)
        t1 = datetime.fromisoformat(agg.last_seen)
        return max((t1 - t0).total_seconds(), 0.001)
    except Exception:
        return 1.0


def _median(values: list[float]) -> float:
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    mid = n // 2
    return sorted_vals[mid] if n % 2 else (sorted_vals[mid - 1] + sorted_vals[mid]) / 2


def _mad(values: list[float], median: float) -> float:
    return _median([abs(v - median) for v in values])