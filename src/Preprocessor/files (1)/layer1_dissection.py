"""
PAnGEA — Layer 1: Packet Dissection Sub-Pipeline.

Responsibility: transform a raw pyshark packet into a fully populated
PacketFeatures object by passing it through a layered dissection pipeline:

    L2 (Ethernet / ARP)
    → L3 (IP, IPv6, ARP)
    → L4 (TCP, UDP, ICMP, IP_RAW)
    → L7 (HTTP, DNS, TLS, SSH — with fallback hierarchy)
    → Payload entropy (last, most expensive, structurally independent)

Design constraints:
  - This is the ONLY module that touches raw pyshark packet objects.
    Every downstream layer works exclusively on PacketFeatures.
  - Each dissection stage is additive — it populates its own fields and
    leaves all others untouched. Missing layers are silently skipped;
    PacketFeatures fields remain None.
  - R6 (Protocol Agnosticism): no branching on attack type. Only structural
    protocol fields (flags, opcodes, ports, layer presence) are read.
  - Payload entropy is computed last because it is the most expensive step
    and depends on no other layer's output.
"""
from __future__ import annotations

import math
import logging
from typing import Optional

from Preprocessor.schemas import EntropyBucket, PacketFeatures

logger = logging.getLogger(__name__)

# TCP flag bitmasks (kept here as layer 1 owns raw flag parsing)
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_PSH = 0x08
_TCP_ACK = 0x10

# ---------------------------------------------------------------------------
# Well-known port → L7 protocol name mapping used as fallback when no
# dedicated dissector fires. Deliberately coarse (protocol class, not
# application name). Ordered by frequency to short-circuit the lookup fast.
# ---------------------------------------------------------------------------
_PORT_TO_L7: dict[int, str] = {
    80:   "HTTP",
    443:  "TLS",
    8080: "HTTP",
    8443: "TLS",
    53:   "DNS",
    22:   "SSH",
    21:   "FTP",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017:"MongoDB",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def dissect_packet(pkt) -> Optional[PacketFeatures]:
    """
    Full dissection pipeline for a single pyshark packet.

    Returns a PacketFeatures instance, or None if the packet cannot be
    meaningfully parsed (e.g. no IP or ARP layer — not an error, just
    outside our scope).
    """
    try:
        features = _init_features(pkt)
        if features is None:
            return None

        _dissect_l2(pkt, features)
        _dissect_l3(pkt, features)
        _dissect_l4(pkt, features)
        _dissect_l7(pkt, features)
        _compute_entropy(pkt, features)

        return features

    except Exception as exc:
        logger.debug("dissect_packet failed for packet %s: %s",
                     getattr(pkt, "number", "?"), exc)
        return None


# ---------------------------------------------------------------------------
# Init — bookkeeping fields that don't belong to any specific layer
# ---------------------------------------------------------------------------

def _init_features(pkt) -> Optional[PacketFeatures]:
    """
    Initialise PacketFeatures with packet-level bookkeeping.
    Returns None if the packet lacks the minimum fields we need.
    """
    try:
        packet_id    = int(pkt.number)
        timestamp    = float(pkt.sniff_timestamp)
        timestamp_iso = pkt.sniff_time.isoformat()
        total_length = int(pkt.length)
        highest_layer = pkt.highest_layer or ""
    except (AttributeError, ValueError):
        return None

    return PacketFeatures(
        packet_id=packet_id,
        timestamp=timestamp,
        timestamp_iso=timestamp_iso,
        total_length=total_length,
        highest_layer=highest_layer,
    )


# ---------------------------------------------------------------------------
# L2 — Ethernet / ARP data-link fields
# ---------------------------------------------------------------------------

def _dissect_l2(pkt, features: PacketFeatures) -> None:
    if hasattr(pkt, "eth"):
        features.l2_proto = "Ethernet"
        features.src_mac  = _safe_str(pkt.eth, "src")
        features.dst_mac  = _safe_str(pkt.eth, "dst")
    elif hasattr(pkt, "arp"):
        features.l2_proto = "ARP"
        features.src_mac  = _safe_str(pkt.arp, "src_hw_mac")
        features.dst_mac  = _safe_str(pkt.arp, "dst_hw_mac")


# ---------------------------------------------------------------------------
# L3 — IP / ARP network-layer fields
# ---------------------------------------------------------------------------

def _dissect_l3(pkt, features: PacketFeatures) -> None:
    if hasattr(pkt, "ip"):
        features.l3_proto = "IP"
        features.src_ip   = _safe_str(pkt.ip, "src")
        features.dst_ip   = _safe_str(pkt.ip, "dst")
    elif hasattr(pkt, "ipv6"):
        features.l3_proto = "IPv6"
        features.src_ip   = _safe_str(pkt.ipv6, "src")
        features.dst_ip   = _safe_str(pkt.ipv6, "dst")
    elif hasattr(pkt, "arp"):
        features.l3_proto  = "ARP"
        features.src_ip    = _safe_str(pkt.arp, "src_proto_ipv4")
        features.dst_ip    = _safe_str(pkt.arp, "dst_proto_ipv4")
        features.arp_opcode    = _safe_str(pkt.arp, "opcode")
        features.arp_sender_mac = _safe_str(pkt.arp, "src_hw_mac")

    # If we still have no L3 — packet is outside scope, mark l4 as IP_RAW
    # so fingerprinting can still produce *something* rather than silently
    # skipping it.
    if features.l3_proto is None and features.l2_proto is not None:
        features.l4_proto = "IP_RAW"


# ---------------------------------------------------------------------------
# L4 — TCP / UDP / ICMP transport-layer fields
# ---------------------------------------------------------------------------

def _dissect_l4(pkt, features: PacketFeatures) -> None:
    if hasattr(pkt, "tcp"):
        features.l4_proto      = "TCP"
        features.src_port      = _safe_int(pkt.tcp, "srcport")
        features.dst_port      = _safe_int(pkt.tcp, "dstport")
        features.tcp_flags_hex = _safe_str(pkt.tcp, "flags")
        features.tcp_stream_id = _safe_str(pkt.tcp, "stream")
        if features.tcp_flags_hex:
            try:
                features.tcp_flags = int(features.tcp_flags_hex, 16)
            except ValueError:
                features.tcp_flags = 0

    elif hasattr(pkt, "udp"):
        features.l4_proto = "UDP"
        features.src_port = _safe_int(pkt.udp, "srcport")
        features.dst_port = _safe_int(pkt.udp, "dstport")

    elif hasattr(pkt, "icmp"):
        features.l4_proto  = "ICMP"
        features.icmp_type = _safe_str(pkt.icmp, "type")
        features.icmp_code = _safe_str(pkt.icmp, "code")

    elif hasattr(pkt, "arp"):
        # ARP has no L4 — already handled at L3, nothing to add here.
        pass


# ---------------------------------------------------------------------------
# L7 — Application-layer protocol detection
# Fallback hierarchy:
#   1. pyshark layer presence (most reliable when dissector fires)
#   2. well-known destination port mapping
#   3. TLS handshake signature (ClientHello record type byte)
#   4. None (unknown — entropy bucketing still runs)
# ---------------------------------------------------------------------------

def _dissect_l7(pkt, features: PacketFeatures) -> None:
    # 1. Dissector presence — pyshark already parsed the L7 layer
    for layer_name, proto_name in [
        ("http",  "HTTP"),
        ("http2", "HTTP2"),
        ("dns",   "DNS"),
        ("tls",   "TLS"),
        ("ssh",   "SSH"),
        ("ftp",   "FTP"),
        ("smtp",  "SMTP"),
        ("pop",   "POP3"),
        ("imap",  "IMAP"),
    ]:
        if hasattr(pkt, layer_name):
            features.l7_proto = proto_name
            return

    # 2. Well-known port fallback
    if features.dst_port is not None:
        l7 = _PORT_TO_L7.get(features.dst_port)
        if l7:
            features.l7_proto = l7
            return

    # 3. TLS handshake signature — check raw payload first byte
    #    TLS record starts with 0x16 (handshake) or 0x17 (application data)
    if features.l4_proto in ("TCP", "UDP") and features.dst_port is not None:
        raw = _get_raw_payload(pkt)
        if raw and len(raw) >= 1 and raw[0] in (0x16, 0x17):
            features.l7_proto = "TLS"
            return

    # 4. No L7 detected — leave as None
    features.l7_proto = None


# ---------------------------------------------------------------------------
# Payload entropy — computed last, independent of protocol structure
# ---------------------------------------------------------------------------

def _compute_entropy(pkt, features: PacketFeatures) -> None:
    raw = _get_raw_payload(pkt)
    if not raw:
        features.payload_length  = 0
        features.payload_entropy = None
        features.entropy_bucket  = None
        return

    features.payload_length  = len(raw)
    entropy = _shannon_entropy(raw)
    features.payload_entropy = entropy
    features.entropy_bucket  = _bucket_entropy(entropy)


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. Result is in [0, 8]."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    n = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _bucket_entropy(entropy: float) -> EntropyBucket:
    if entropy < 3.0:
        return EntropyBucket.LOW
    if entropy < 5.5:
        return EntropyBucket.MEDIUM
    if entropy < 7.0:
        return EntropyBucket.HIGH
    return EntropyBucket.VERY_HIGH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_raw_payload(pkt) -> Optional[bytes]:
    """
    Extract raw payload bytes from a pyshark packet.
    Tries DATA layer first (explicit payload), falls back to the
    highest-layer raw field if available.
    """
    try:
        if hasattr(pkt, "data") and hasattr(pkt.data, "data"):
            return bytes.fromhex(pkt.data.data.replace(":", ""))
    except (ValueError, AttributeError):
        pass
    return None


def _safe_str(layer, field: str) -> Optional[str]:
    try:
        val = getattr(layer, field, None)
        return str(val) if val is not None else None
    except Exception:
        return None


def _safe_int(layer, field: str) -> Optional[int]:
    try:
        val = getattr(layer, field, None)
        return int(val) if val is not None else None
    except (ValueError, TypeError):
        return None
