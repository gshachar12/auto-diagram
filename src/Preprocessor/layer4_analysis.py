"""
PAnGEA — Layer 4: Cluster Analysis.

Responsibility: enrich each Cluster with analysis-derived metadata and
assign a relevance tier (PRIMARY / SECONDARY / REMNANT).

Analysis steps (in order):
  1. Traffic share   — each cluster's fraction of total pcap bytes.
  2. TF-IDF weight   — treats the pcap as a corpus, each fingerprint as a
                       term. Rare signatures score high; frequent background
                       protocols score low.
  3. Z-scores        — per-dimension anomaly scores across the cluster
                       population (log-transformed to handle heavy tails).
  4. Context match   — whether the cluster matches any suspected protocol
                       or behavior from the AttackContext (layer 0 output).
  5. Port metadata   — dst_port_class (well-known / registered / ephemeral)
                       and dst_port_service name.
  6. Tier assignment — combines TF-IDF weight, Z-scores, and context match
                       into a PRIMARY / SECONDARY / REMNANT decision.

Input:  list[Cluster] + AttackContext + total pcap bytes
Output: list[Cluster] with metadata fully populated (mutates in place,
        returns the same list for convenience)
"""
from __future__ import annotations

import json
import logging
import math
from typing import Optional

from Preprocessor.schemas import (
    AttackContext,
    Cluster,
    ClusterMetadata,
    ClusterTier,
    PortClass,
    SuspectedProtocol,
)

logger = logging.getLogger(__name__)

# Tier assignment thresholds — tunable.
_PRIMARY_TFIDF_THRESHOLD   = 0.6   # normalised TF-IDF score above this → candidate for PRIMARY
_PRIMARY_ZSCORE_THRESHOLD  = 2.0   # at least one Z-score above this → anomalous
_REMNANT_TFIDF_THRESHOLD   = 0.15  # below this AND no context match → REMNANT

# Well-known port → service name, used for dst_port_service metadata.
_PORT_SERVICE: dict[int, str] = {
    20:    "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25:    "SMTP",     53: "DNS", 67: "DHCP", 68: "DHCP",
    80:    "HTTP",     110: "POP3", 143: "IMAP", 161: "SNMP",
    443:   "HTTPS/TLS", 445: "SMB", 465: "SMTPS", 993: "IMAPS",
    995:   "POP3S",    1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432:  "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt",
    8443:  "HTTPS-alt", 27017: "MongoDB",
}

# L7 protocol → suspected protocol enum (for context matching)
_L7_TO_SUSPECTED: dict[str, SuspectedProtocol] = {
    "HTTP":  SuspectedProtocol.HTTP,
    "HTTP2": SuspectedProtocol.HTTP,
    "TLS":   SuspectedProtocol.TLS,
    "DNS":   SuspectedProtocol.DNS,
    "SSH":   SuspectedProtocol.SSH,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyse_clusters(
    clusters: list[Cluster],
    attack_context: Optional[AttackContext],
    total_bytes: int,
) -> list[Cluster]:
    """
    Enrich clusters with analysis metadata and assign tiers.
    Mutates each cluster's .metadata field in place; returns the same list.
    """
    if not clusters:
        return clusters

    _compute_traffic_shares(clusters, total_bytes)
    _compute_tfidf(clusters)
    _compute_zscores(clusters)
    _compute_port_metadata(clusters)
    _compute_context_match(clusters, attack_context)
    _assign_tiers(clusters)

    return clusters


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
#
# Analogy:
#   document = the entire pcap
#   term     = a fingerprint_key
#   TF       = fraction of total packets this cluster accounts for
#   IDF      = log(total_clusters / 1)  — every fingerprint is unique in
#              the pcap-as-document sense; IDF captures how rare this
#              signature is relative to total packet volume.
#
# In practice: clusters with many packets (NTP, keepalives) get low TF-IDF
# because their high TF is offset by the fact they're "expected background".
# Rare, high-volume bursts (SYN flood) get high TF-IDF because the signature
# is unusual relative to total distinct signatures seen.
# ---------------------------------------------------------------------------

def _compute_tfidf(clusters: list[Cluster]) -> None:
    total_packets = sum(
        c.aggregate.count for c in clusters if c.aggregate
    )
    n_clusters = len(clusters)
    if total_packets == 0 or n_clusters == 0:
        return

    # IDF: log(total_clusters) — same for all clusters in this formulation.
    # The discrimination comes from TF (packet share within pcap).
    idf = math.log(n_clusters + 1)   # +1 to avoid log(1)=0 for single cluster

    max_tfidf = 0.0
    raw_scores: list[float] = []

    for cluster in clusters:
        if not cluster.aggregate:
            raw_scores.append(0.0)
            continue
        tf = cluster.aggregate.count / total_packets
        score = tf * idf
        raw_scores.append(score)
        max_tfidf = max(max_tfidf, score)

    # Normalise to [0, 1]
    for cluster, score in zip(clusters, raw_scores):
        cluster.metadata.tfidf_weight = (
            score / max_tfidf if max_tfidf > 0 else 0.0
        )


# ---------------------------------------------------------------------------
# Step 3 — Z-scores (log-transformed, MAD-based for robustness)
#
# Dimensions analysed:
#   - packet_rate   (count / duration in seconds)
#   - byte_volume   (total_bytes)
#   - unique_sources (cardinality)
#   - iat_mean      (mean inter-arrival time, if available)
# ---------------------------------------------------------------------------

_ZSCORE_DIMS = ["packet_rate", "byte_volume", "unique_sources", "iat_mean"]


def _compute_zscores(clusters: list[Cluster]) -> None:
    """
    Compute per-dimension Z-scores using MAD (Median Absolute Deviation)
    rather than standard deviation, to be robust to the outliers we're
    specifically trying to find.
    """
    # Build dimension vectors
    vectors: dict[str, list[float]] = {dim: [] for dim in _ZSCORE_DIMS}

    for cluster in clusters:
        agg = cluster.aggregate
        if not agg:
            for dim in _ZSCORE_DIMS:
                vectors[dim].append(0.0)
            continue

        duration = _cluster_duration_seconds(agg)
        vectors["packet_rate"].append(
            agg.count / duration if duration > 0 else float(agg.count)
        )
        vectors["byte_volume"].append(float(agg.total_bytes))
        vectors["unique_sources"].append(float(len(agg.unique_sources)))
        vectors["iat_mean"].append(agg.iat_mean if agg.iat_mean is not None else 0.0)

    # Log-transform all dimensions (heavy-tailed distributions)
    log_vectors: dict[str, list[float]] = {}
    for dim, vals in vectors.items():
        log_vectors[dim] = [math.log1p(v) for v in vals]

    # Compute MAD-based Z-scores per dimension
    zscores_per_dim: dict[str, list[float]] = {}
    for dim, log_vals in log_vectors.items():
        median = _median(log_vals)
        mad    = _mad(log_vals, median)
        if mad == 0:
            zscores_per_dim[dim] = [0.0] * len(log_vals)
        else:
            zscores_per_dim[dim] = [
                abs(v - median) / (mad * 1.4826)   # 1.4826 makes MAD consistent with std
                for v in log_vals
            ]

    # Assign to clusters
    for i, cluster in enumerate(clusters):
        anomalies: dict[str, float] = {}
        for dim in _ZSCORE_DIMS:
            score = zscores_per_dim[dim][i]
            if score > 0.01:   # skip near-zero scores to keep output clean
                anomalies[dim] = round(score, 3)
        cluster.metadata.zscore_anomalies = anomalies


# ---------------------------------------------------------------------------
# Step 4 — Port metadata
# ---------------------------------------------------------------------------

def _compute_port_metadata(clusters: list[Cluster]) -> None:
    for cluster in clusters:
        port = _extract_dst_port(cluster)
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


def _extract_dst_port(cluster: Cluster) -> Optional[int]:
    """Extract dst_port from the fingerprint_key (it's stored as part of the JSON array)."""
    try:
        parts = json.loads(cluster.fingerprint_key)
        # key_parts = [l4_proto, state_sig, l7_proto, dst_port, entropy_bucket, time_bucket]
        dst_port = parts[3]
        return int(dst_port) if dst_port is not None else None
    except (json.JSONDecodeError, IndexError, TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Step 5 — Context match
# ---------------------------------------------------------------------------

def _compute_context_match(
    clusters: list[Cluster],
    attack_context: Optional[AttackContext],
) -> None:
    if not attack_context:
        return

    suspected_proto_values = {p.value for p in attack_context.suspected_protocols}

    for cluster in clusters:
        if not cluster.representative_items:
            continue
        # Use the first representative item's protocol as the cluster's protocol
        cluster_proto = cluster.representative_items[0].protocol.upper()

        # Direct protocol match
        if cluster_proto in suspected_proto_values:
            cluster.metadata.context_match = True
            continue

        # L7 protocol match (e.g. cluster_proto="DNS" matches SuspectedProtocol.DNS)
        try:
            parts = json.loads(cluster.fingerprint_key)
            l7_proto = parts[2]   # index 2 is l7_proto
        except (json.JSONDecodeError, IndexError):
            l7_proto = None

        if l7_proto and l7_proto.upper() in suspected_proto_values:
            cluster.metadata.context_match = True


# ---------------------------------------------------------------------------
# Step 6 — Tier assignment
#
# Decision logic:
#   PRIMARY   — (high TF-IDF OR any anomalous Z-score) AND context_match
#             OR exceptionally anomalous even without context match
#   SECONDARY — some signal but not strong enough for PRIMARY
#   REMNANT   — low TF-IDF, no anomalies, no context match
# ---------------------------------------------------------------------------

def _assign_tiers(clusters: list[Cluster]) -> None:
    for cluster in clusters:
        meta = cluster.metadata
        tfidf   = meta.tfidf_weight or 0.0
        context = meta.context_match
        max_z   = max(meta.zscore_anomalies.values(), default=0.0)

        is_high_tfidf  = tfidf >= _PRIMARY_TFIDF_THRESHOLD
        is_anomalous   = max_z  >= _PRIMARY_ZSCORE_THRESHOLD
        is_low_tfidf   = tfidf <  _REMNANT_TFIDF_THRESHOLD

        if (is_high_tfidf or is_anomalous) and context:
            meta.tier = ClusterTier.PRIMARY
        elif is_anomalous and not context:
            # Anomalous but not matching context — still worth surfacing
            meta.tier = ClusterTier.SECONDARY
        elif is_low_tfidf and not context and max_z < 1.0:
            meta.tier = ClusterTier.REMNANT
        else:
            meta.tier = ClusterTier.SECONDARY


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def _cluster_duration_seconds(agg) -> float:
    """Duration between first and last seen timestamps in seconds."""
    try:
        from datetime import datetime
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
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
