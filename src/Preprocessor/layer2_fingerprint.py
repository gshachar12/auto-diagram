"""
PAnGEA — Layer 2: Fingerprint & Signature Construction.

Responsibility: derive a stable, hashable fingerprint key from a
PacketFeatures object. The key determines which Cluster a packet joins.

Fingerprint dimensions (in order of specificity):
  1. L4 protocol + state signature  (TCP handshake phase, UDP, ICMP, ARP)
  2. L7 protocol                    (HTTP, DNS, TLS, SSH, or None)
  3. Destination port               (raw int — port classification is L4 metadata)
  4. Entropy bucket                 (LOW / MEDIUM / HIGH / VERY_HIGH, or None)
  5. Temporal bucket                (floor(timestamp / delta_t) as int)

The temporal bucket is what separates two instances of "the same attack"
occurring hours apart into distinct clusters, without splitting packets
within the same attack wave. For example:

    ("TCP", "SYN", None, 80, None, 0)   — first SYN flood wave
    ("TCP", "SYN", None, 80, None, 1)   — second wave, delta_t seconds later

Design constraints (R6): no branching on attack type. The fingerprint is
derived purely from structural protocol state.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from Preprocessor.schemas import EntropyBucket, PacketFeatures

logger = logging.getLogger(__name__)

# TCP flag bitmasks — duplicated from layer1 to keep layers independent.
_TCP_SYN = 0x02
_TCP_ACK = 0x10
_TCP_FIN = 0x01
_TCP_RST = 0x04

# Default temporal bucket size in seconds.
# Two packets within the same window share a bucket index; packets more
# than delta_t seconds apart (at a window boundary) get different indices.
DEFAULT_DELTA_T: float = 300.0  # 5 minutes


def build_fingerprint_key(
    features: PacketFeatures,
    handshakes_completed: set[str],
    delta_t: float = DEFAULT_DELTA_T,
) -> Optional[str]:
    """
    Derive a stable string fingerprint key from PacketFeatures.

    Args:
        features:             fully dissected packet features (layer 1 output).
        handshakes_completed: mutable set tracking TCP stream IDs whose
                              three-way handshake has completed. Updated
                              in-place as SYN-ACK / ACK packets are seen.
        delta_t:              temporal bucket size in seconds.

    Returns:
        A JSON-encoded string key, or None if the packet cannot be
        fingerprinted (e.g. unknown protocol with no useful fields).
    """
    sig = _build_state_signature(features, handshakes_completed)
    if sig is None:
        return None

    time_bucket = _temporal_bucket(features.timestamp, delta_t)
    entropy_val = features.entropy_bucket.value if features.entropy_bucket else None

    key_parts = [
        features.l4_proto or "UNKNOWN",
        sig,                       # protocol-specific state string
        features.l7_proto,         # None if not detected
        features.dst_port,         # None for ICMP/ARP
        entropy_val,               # None if no payload
        time_bucket,               # int
    ]

    return json.dumps(key_parts, separators=(",", ":"))


def _temporal_bucket(timestamp: float, delta_t: float) -> int:
    """Map a Unix timestamp to a bucket index."""
    return int(timestamp // delta_t)


# ---------------------------------------------------------------------------
# Protocol-specific state signature builders
# Each returns a short string describing the structural state of the packet.
# These strings become part of the fingerprint key — they must be:
#   - stable (same packet always → same string)
#   - discriminating (structurally different packets → different strings)
#   - agnostic (no attack-type labels, only protocol state)
# ---------------------------------------------------------------------------

def _build_state_signature(
    features: PacketFeatures,
    handshakes_completed: set[str],
) -> Optional[str]:
    proto = features.l4_proto

    if proto == "TCP":
        return _tcp_state(features, handshakes_completed)
    if proto == "UDP":
        return "UDP"
    if proto == "ICMP":
        return f"ICMP:{features.icmp_type}:{features.icmp_code}"
    if proto == "ARP":
        return f"ARP:{features.arp_opcode}:{features.arp_sender_mac}"
    if proto == "IP_RAW":
        return "IP_RAW"

    return None


def _tcp_state(
    features: PacketFeatures,
    handshakes_completed: set[str],
) -> str:
    """
    TCP state machine — mirrors the logic from the original fingerprint.py
    but operates on PacketFeatures rather than raw pyshark fields.

    States:
      SYN          — handshake initiation
      SYN-ACK      — handshake response
      ACK_HANDSHAKE— handshake-completing ACK (marks stream as established)
      DATA         — post-handshake data transfer (ACK bit set, stream known)
      FIN          — graceful close
      RST          — reset
      OTHER        — any other flag combination
    """
    flags = features.tcp_flags or 0
    stream_id = features.tcp_stream_id or ""

    is_syn = bool(flags & _TCP_SYN)
    is_ack = bool(flags & _TCP_ACK)
    is_fin = bool(flags & _TCP_FIN)
    is_rst = bool(flags & _TCP_RST)

    if is_syn and is_ack:
        return "SYN-ACK"

    if is_syn:
        return "SYN"

    if is_fin:
        handshakes_completed.discard(stream_id)
        return "FIN"

    if is_rst:
        handshakes_completed.discard(stream_id)
        return "RST"

    if is_ack:
        if stream_id in handshakes_completed:
            # Post-handshake data stream — collapse into generic DATA bucket.
            # Keyed only by port, not by flags, so all data packets on the
            # same port share a fingerprint (prevents oversegmentation of
            # normal data streams).
            return "DATA"
        else:
            # First ACK on this stream — the handshake-completing ACK.
            handshakes_completed.add(stream_id)
            return "ACK_HANDSHAKE"

    return f"OTHER:{features.tcp_flags_hex or '0x00'}"
