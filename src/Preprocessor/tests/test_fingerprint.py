"""
Unit tests for src/preprocessing/fingerprint.py — the structural
fingerprinting logic itself, independent of the full Reducer pipeline.
"""
import sys
sys.path.insert(0, "src")

from fingerprint import (
    fingerprint_tcp, fingerprint_arp, fingerprint_key_str,
)


class TestTCPFingerprinting:

    def test_syn_is_handshake_phase(self):
        result = fingerprint_tcp("0x02", "443", "0", handshakes_completed=set())
        assert result.l4_proto == "TCP"
        assert "Handshake" in result.info

    def test_syn_ack_is_handshake_phase(self):
        result = fingerprint_tcp("0x12", "443", "0", handshakes_completed=set())
        assert result.l4_proto == "TCP"
        assert "SYN-ACK" in result.info

    def test_first_ack_completes_handshake_and_marks_stream(self):
        completed = set()
        result = fingerprint_tcp("0x10", "443", "stream-1", handshakes_completed=completed)
        assert result.l4_proto == "TCP"
        assert "Handshake Completed" in result.info
        assert "stream-1" in completed

    def test_psh_ack_after_handshake_collapses_to_data_stream(self):
        """This is the bug-fix case: PSH-ACK (0x18) data-transfer packets
        must collapse into TCP_DATA_STREAM once the handshake is marked
        complete — not stay as individual 'Flags: 0x18' entries."""
        completed = {"stream-1"}
        result = fingerprint_tcp("0x18", "443", "stream-1", handshakes_completed=completed)
        assert result.l4_proto == "TCP_DATA_STREAM"
        assert result.state_signature == ("443",)

    def test_ack_only_after_handshake_also_collapses_to_data_stream(self):
        """Bare ACK (0x10) after handshake completion should also be
        treated as data-stream traffic, not re-trigger 'handshake completed'."""
        completed = {"stream-1"}
        result = fingerprint_tcp("0x10", "443", "stream-1", handshakes_completed=completed)
        assert result.l4_proto == "TCP_DATA_STREAM"

    def test_fin_clears_stream_from_handshake_tracking(self):
        completed = {"stream-1"}
        fingerprint_tcp("0x11", "443", "stream-1", handshakes_completed=completed)  # FIN-ACK
        assert "stream-1" not in completed

    def test_rst_clears_stream_from_handshake_tracking(self):
        completed = {"stream-1"}
        fingerprint_tcp("0x14", "443", "stream-1", handshakes_completed=completed)  # RST-ACK
        assert "stream-1" not in completed

    def test_reused_stream_id_does_not_inherit_stale_completion_state(self):
        """After FIN clears a stream, a fresh SYN on the same stream_id
        must go through the handshake phase again, not be misread as
        already-completed data-stream traffic."""
        completed = {"stream-1"}
        fingerprint_tcp("0x11", "443", "stream-1", handshakes_completed=completed)  # FIN
        assert "stream-1" not in completed
        result = fingerprint_tcp("0x02", "443", "stream-1", handshakes_completed=completed)  # new SYN
        assert result.l4_proto == "TCP"
        assert "Handshake" in result.info

    def test_key_excludes_source_ip_and_port_by_design(self):
        """TCP fingerprint keys must be IP-agnostic — this is what enables
        host-scan collapsing. Confirmed here at the signature level: the
        signature only ever contains (flags, dst_port)."""
        result = fingerprint_tcp("0x02", "22", "0", handshakes_completed=set())
        assert result.state_signature == ("0x02", "22")


class TestARPFingerprinting:

    def test_same_mac_same_opcode_produces_same_key(self):
        r1 = fingerprint_arp(opcode="2", sender_mac="aa:aa:aa:aa:aa:aa")
        r2 = fingerprint_arp(opcode="2", sender_mac="aa:aa:aa:aa:aa:aa")
        assert fingerprint_key_str(r1.l4_proto, r1.state_signature) == \
               fingerprint_key_str(r2.l4_proto, r2.state_signature)

    def test_spoofed_reply_from_different_mac_produces_different_key(self):
        """Security-critical: a spoofed ARP reply (different MAC, same
        opcode) must NOT collapse into the same fingerprint as a
        legitimate reply — this is the deliberate exception to the
        IP/identity-agnostic rule elsewhere in the fingerprinting scheme."""
        legit = fingerprint_arp(opcode="2", sender_mac="aa:aa:aa:aa:aa:aa")
        spoofed = fingerprint_arp(opcode="2", sender_mac="bb:bb:bb:bb:bb:bb")
        key_legit = fingerprint_key_str(legit.l4_proto, legit.state_signature)
        key_spoofed = fingerprint_key_str(spoofed.l4_proto, spoofed.state_signature)
        assert key_legit != key_spoofed
