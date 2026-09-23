"""
PAnGEA — Structural fingerprinting logic.

Implements R6 (Protocol/Attack-Type Agnosticism): fingerprint keys are derived
purely from structural protocol state (flags, ports, opcodes), never from
knowledge of what kind of attack/protocol/traffic is being analyzed.

Fixes two bugs identified in the original prototype (extract_relevant_packets):
  1. TCP flags were matched via substring checks ("0x02" in flags), which is
     fragile against combined flags and can false-positive/negative. This
     version parses flags as an integer bitmask.
  2. Pure-ACK detection required an exact "0x10" match, so PSH-ACK (0x18)
     packets — the common case for actual data transfer — never collapsed
     into TCP_DATA_STREAM as intended. This version checks the ACK bit
     generically, independent of other bits, once a stream's handshake has
     completed.
"""
from __future__ import annotations
import json
from dataclasses import dataclass

# TCP flag bitmasks
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


@dataclass
class FingerprintResult:
    l4_proto: str            # e.g. "TCP", "TCP_DATA_STREAM", "UDP", "ARP", "ICMP", "IP_RAW"
    state_signature: tuple    # hashable, protocol-specific structural signature
    info: str                 # human-readable summary of the structural state


def _parse_tcp_flags(flags_hex: str) -> int:
    """Parse a pyshark tcp.flags hex string (e.g. '0x18') into an int bitmask."""
    try:
        return int(flags_hex, 16)
    except (TypeError, ValueError):
        return 0


def fingerprint_tcp(flags_hex: str, dst_port: str, stream_id: str,
                     handshakes_completed: set[str]) -> FingerprintResult:
    """
    Structural TCP fingerprinting.

    - SYN or SYN-ACK -> handshake-phase signature (kept fine-grained; these
      are usually low-volume and highly diagnostic, so they are not folded
      into a generic data-stream bucket).
    - ACK bit set (regardless of PSH or other bits) on a stream whose
      handshake already completed -> TCP_DATA_STREAM, keyed by port only.
      This is the fix for bug #2 above.
    - First ACK seen on a stream (handshake not yet marked complete) ->
      treated as the handshake-completing ACK; marks the stream complete
      for subsequent packets.
    - FIN or RST -> stream considered closed; removed from tracking so a
      reused stream id / new connection on the same port starts fresh.
    """
    flags = _parse_tcp_flags(flags_hex)

    is_syn = bool(flags & TCP_SYN) # bitmask for syn packets
    is_ack = bool(flags & TCP_ACK) # bitmask for ack packets
    is_fin = bool(flags & TCP_FIN) # bitmask for ack packets
    is_rst = bool(flags & TCP_RST) # bit mask for reset packets

    if is_syn:
        flag_name = "SYN-ACK" if is_ack else "SYN"
        return FingerprintResult(
            l4_proto="TCP",
            state_signature=(flags_hex, dst_port),
            info=f"Handshake Phase | Flags: {flags_hex} ({flag_name}) | DPort: {dst_port}",
        )

    if is_ack:
        if stream_id in handshakes_completed:
            return FingerprintResult(
                l4_proto="TCP_DATA_STREAM",
                state_signature=(dst_port,),
                info=f"Data Transfer | DPort: {dst_port}",
            )
        # First ACK on this stream — treat as the handshake-completing ACK.
        handshakes_completed.add(stream_id)
        return FingerprintResult(
            l4_proto="TCP",
            state_signature=(flags_hex, dst_port),
            info=f"Handshake Completed (ACK) | Flags: {flags_hex} | DPort: {dst_port}",
        )

    # Non-SYN, non-ACK packets (rare on their own, e.g. bare FIN/RST)
    if is_fin or is_rst:
        handshakes_completed.discard(stream_id)

    return FingerprintResult(
        l4_proto="TCP",
        state_signature=(flags_hex, dst_port),
        info=f"Flags: {flags_hex} | DPort: {dst_port}",
    )


def fingerprint_udp(dst_port: str) -> FingerprintResult:
    return FingerprintResult(
        l4_proto="UDP",
        state_signature=(dst_port,),
        info=f"DPort: {dst_port}",
    )


def fingerprint_arp(opcode: str, sender_mac: str) -> FingerprintResult:
    # MAC is kept in the signature deliberately: collapsing purely by opcode
    # would let an attacker spoofing a legitimate router's replies blend
    # into the same fingerprint as the real router.
    return FingerprintResult(
        l4_proto="ARP",
        state_signature=(opcode, sender_mac),
        info=f"Opcode: {opcode} | Sender MAC: {sender_mac}",
    )


def fingerprint_icmp(icmp_type: str, icmp_code: str) -> FingerprintResult:
    return FingerprintResult(
        l4_proto="ICMP",
        state_signature=(icmp_type, icmp_code),
        info=f"Type: {icmp_type} | Code: {icmp_code}",
    )


def fingerprint_key_str(l4_proto: str, state_signature: tuple) -> str:
    """Stable string key for use in dicts / JSON output (fingerprint_index)."""
    return json.dumps([l4_proto, list(state_signature)], separators=(",", ":"))