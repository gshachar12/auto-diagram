"""
PAnGEA — Layer 4 (Serialization): Cluster Text Serialization.

Responsibility: convert a fully-analyzed Cluster into a natural-language
string suitable for input to the cross-encoder grounder.

Design constraints:
  - Called only after all Layer 4 analysis is complete (tier, Z-scores,
    TF-IDF, anomalies, context_match are all finalized).
  - Output must be readable as natural language — not a key-value dump.
    The cross-encoder was trained on natural language pairs; structured
    output degrades matching quality.
  - Must include all fields an analyst would mention when describing the
    cluster: protocol, behavior, scale, anomalies, and tier.
  - Deterministic: same cluster always produces the same string.
  - Concise: cross-encoders typically have a 512-token limit.
"""
from __future__ import annotations

import json
from typing import Optional

from Preprocessor.schemas import Cluster, ClusterTier, EntropyBucket


# ---------------------------------------------------------------------------
# Port → service name (subset — same as layer4_analysis._PORT_SERVICE)
# ---------------------------------------------------------------------------
_PORT_SERVICE: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP",     53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3",    143: "IMAP", 161: "SNMP",
    443: "HTTPS/TLS", 445: "SMB", 3306: "MySQL",
    3389: "RDP",    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

_ENTROPY_DESCRIPTIONS: dict[EntropyBucket, str] = {
    EntropyBucket.LOW:       "low entropy (structured, human-readable payload)",
    EntropyBucket.MEDIUM:    "medium entropy (readable protocol data)",
    EntropyBucket.HIGH:      "high entropy (compressed or binary payload)",
    EntropyBucket.VERY_HIGH: "very high entropy (encrypted or encoded payload)",
}

_STATE_DESCRIPTIONS: dict[str, str] = {
    "SYN":           "connection initiation (SYN)",
    "SYN-ACK":       "connection response (SYN-ACK)",
    "ACK_HANDSHAKE": "handshake completion (ACK)",
    "DATA":          "established data transfer",
    "FIN":           "graceful connection close (FIN)",
    "RST":           "connection reset (RST)",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def serialize_cluster(cluster: Cluster) -> str:
    """
    Convert a fully-analyzed Cluster to a natural-language summary string.
    Called at the end of analyse_clusters(), result stored in
    cluster.metadata.cluster_text.
    """
    parts: list[str] = []

    fkey_parts = _parse_fkey(cluster.fingerprint_key)
    l4_proto      = fkey_parts[0]
    state_sig     = fkey_parts[1]
    l7_proto      = fkey_parts[2]
    dst_port      = fkey_parts[3]
    entropy_bucket= fkey_parts[4]

    agg  = cluster.aggregate
    meta = cluster.metadata

    # ── Protocol and behavior description ────────────────────────────────────
    proto_desc = _describe_protocol(l4_proto, state_sig, l7_proto, dst_port)
    parts.append(proto_desc)

    # ── Scale and volume ──────────────────────────────────────────────────────
    if agg:
        scale = _describe_scale(agg)
        parts.append(scale)

    # ── Payload entropy ───────────────────────────────────────────────────────
    if entropy_bucket:
        try:
            bucket_enum = EntropyBucket(entropy_bucket)
            parts.append(
                f"Payload: {_ENTROPY_DESCRIPTIONS[bucket_enum]}."
            )
        except ValueError:
            pass

    # ── Temporal behavior ─────────────────────────────────────────────────────
    if agg and agg.iat_mean is not None:
        parts.append(_describe_timing(agg))

    # ── Anomalies ─────────────────────────────────────────────────────────────
    if meta and meta.zscore_anomalies:
        parts.append(_describe_anomalies(meta.zscore_anomalies))

    # ── Traffic share ─────────────────────────────────────────────────────────
    if meta and meta.traffic_share is not None:
        pct = round(meta.traffic_share * 100, 1)
        parts.append(f"Accounts for {pct}% of total capture traffic.")

    # ── Tier and context match ────────────────────────────────────────────────
    if meta:
        tier_str = meta.tier.value.upper() if meta.tier else "UNASSIGNED"
        ctx_str  = "matches attack context" if meta.context_match else "no context match"
        parts.append(f"Relevance tier: {tier_str} ({ctx_str}).")

    return " ".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Sub-description helpers
# ---------------------------------------------------------------------------

def _describe_protocol(
    l4_proto: Optional[str],
    state_sig: Optional[str],
    l7_proto:  Optional[str],
    dst_port:  Optional[int],
) -> str:
    """Produce a natural-language protocol description."""
    port_str = ""
    if dst_port is not None:
        service = _PORT_SERVICE.get(dst_port, "")
        port_str = (
            f"port {dst_port} ({service})" if service
            else f"port {dst_port}"
        )

    # TCP — use state description
    if l4_proto == "TCP" and state_sig:
        state_desc = _STATE_DESCRIPTIONS.get(state_sig, state_sig)
        if l7_proto:
            return (
                f"TCP {state_desc} carrying {l7_proto} traffic"
                + (f" on {port_str}" if port_str else "") + "."
            )
        return (
            f"TCP {state_desc}"
            + (f" on {port_str}" if port_str else "") + "."
        )

    # UDP
    if l4_proto == "UDP":
        if l7_proto:
            return (
                f"UDP {l7_proto} traffic"
                + (f" on {port_str}" if port_str else "") + "."
            )
        return f"UDP traffic" + (f" on {port_str}" if port_str else "") + "."

    # ICMP
    if l4_proto == "ICMP" and state_sig:
        # state_sig format: "ICMP:type:code"
        parts = state_sig.split(":")
        type_code = f"type {parts[1]} code {parts[2]}" if len(parts) == 3 else state_sig
        return f"ICMP traffic ({type_code})."

    # ARP
    if l4_proto == "ARP" and state_sig:
        # state_sig format: "ARP:opcode:sender_mac" — the MAC itself contains
        # colons, so split at most twice.
        parts = state_sig.split(":", 2)
        opcode = parts[1] if len(parts) > 1 else "?"
        op_name = "request" if opcode == "1" else "reply" if opcode == "2" else f"opcode {opcode}"
        sender  = parts[2] if len(parts) > 2 else "unknown"
        return f"ARP {op_name} from MAC {sender}."

    return f"{l4_proto or 'Unknown'} traffic" + (f" on {port_str}" if port_str else "") + "."


def _describe_scale(agg) -> str:
    """Produce a natural-language scale description."""
    src_count = len(agg.unique_sources)
    dst_count = len(agg.unique_destinations)

    src_str = (
        "one source" if src_count == 1
        else f"{src_count} unique sources"
    )
    dst_str = (
        "one destination" if dst_count == 1
        else f"{dst_count} unique destinations"
    )

    return (
        f"{agg.count} packets ({agg.total_bytes} bytes total) "
        f"from {src_str} to {dst_str}."
    )


def _describe_timing(agg) -> str:
    """Produce a natural-language timing description."""
    mean_ms = round(agg.iat_mean * 1000, 2)

    if agg.iat_mean < 0.001:
        rate_desc = "extremely high packet rate"
    elif agg.iat_mean < 0.01:
        rate_desc = "very high packet rate"
    elif agg.iat_mean < 0.1:
        rate_desc = "moderate packet rate"
    else:
        rate_desc = "low packet rate"

    regularity = ""
    if agg.iat_std is not None and agg.iat_mean > 0:
        cv = agg.iat_std / agg.iat_mean
        if cv < 0.1:
            regularity = ", highly regular interval (possible beaconing)"
        elif cv > 2.0:
            regularity = ", highly irregular interval"

    return f"Inter-arrival time: mean {mean_ms}ms ({rate_desc}{regularity})."


def _describe_anomalies(zscore_anomalies: dict[str, float]) -> str:
    """Produce a natural-language anomaly description."""
    _DIM_NAMES = {
        "packet_rate":     "packet rate",
        "byte_volume":     "byte volume",
        "src_cardinality": "number of unique sources",
        "dst_cardinality": "number of unique destinations",
        "iat_mean":        "inter-arrival time",
    }

    high = [
        (dim, score) for dim, score in zscore_anomalies.items()
        if score >= 2.0
    ]
    if not high:
        return ""

    high.sort(key=lambda x: x[1], reverse=True)
    desc_parts = [
        f"{_DIM_NAMES.get(dim, dim)} (Z={score:.1f})"
        for dim, score in high
    ]
    return f"Statistically anomalous: {', '.join(desc_parts)}."


# ---------------------------------------------------------------------------
# Fingerprint key parser
# ---------------------------------------------------------------------------

def _parse_fkey(fkey: str) -> list:
    """
    Parse fingerprint key into [l4_proto, state_sig, l7_proto,
    dst_port, entropy_bucket, time_bucket].
    Returns list of None on failure.
    """
    try:
        parts = json.loads(fkey)
        while len(parts) < 6:
            parts.append(None)
        # dst_port as int
        if parts[3] is not None:
            parts[3] = int(parts[3])
        return parts
    except (json.JSONDecodeError, ValueError, TypeError):
        return [None] * 6
