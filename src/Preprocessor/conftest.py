"""
Shared fixtures for the Preprocessing test suite.

All synthetic PCAPs are built with scapy and written to a temp file, then
read back as bytes — matching the shape reduce_pcap()/run_preprocessing()
actually expect (raw bytes, not a file path).
"""
from __future__ import annotations

import tempfile

import pytest
from scapy.all import IP, TCP, UDP, ARP, ICMP, wrpcap, Ether


def _pcap_bytes(packets) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    wrpcap(path, packets)
    with open(path, "rb") as f:
        return f.read()


VICTIM = "10.0.0.5"
ATTACKER = "203.0.113.17"


@pytest.fixture
def empty_pcap_bytes() -> bytes:
    return _pcap_bytes([])


@pytest.fixture
def single_syn_packet_bytes() -> bytes:
    return _pcap_bytes([IP(src=ATTACKER, dst=VICTIM) / TCP(dport=80, flags="S")])


@pytest.fixture
def handshake_and_data_bytes() -> bytes:
    """3-way handshake on port 443, followed by 20 PSH-ACK data packets."""
    packets = [
        IP(src=ATTACKER, dst=VICTIM) / TCP(dport=443, sport=55000, flags="S", seq=2000),
        IP(src=VICTIM, dst=ATTACKER) / TCP(sport=443, dport=55000, flags="SA", seq=3000, ack=2001),
        IP(src=ATTACKER, dst=VICTIM) / TCP(dport=443, sport=55000, flags="A", seq=2001, ack=3001),
    ]
    for i in range(20):
        packets.append(
            IP(src=ATTACKER, dst=VICTIM)
            / TCP(dport=443, sport=55000, flags="PA", seq=2001 + i * 100, ack=3001)
            / (b"X" * 50)
        )
    return _pcap_bytes(packets)


@pytest.fixture
def port_scan_bytes() -> bytes:
    """Single source, many destination ports, all SYN — the known
    non-collapsing case documented in the README."""
    return _pcap_bytes([
        IP(src=ATTACKER, dst=VICTIM) / TCP(dport=port, flags="S", seq=1000)
        for port in range(1000, 1050)
    ])


@pytest.fixture
def host_scan_bytes() -> bytes:
    """Many sources, single destination port, all SYN — SHOULD collapse
    into one fingerprint (IP-agnostic by design)."""
    return _pcap_bytes([
        IP(src=f"192.168.1.{i}", dst=VICTIM) / TCP(dport=22, flags="S")
        for i in range(2, 52)
    ])


@pytest.fixture
def identical_packets_bytes() -> bytes:
    """1000 fully identical DNS query packets -> one item + aggregate count=1000."""
    return _pcap_bytes([
        IP(src=VICTIM, dst="8.8.8.8") / UDP(dport=53, sport=40000)
        for _ in range(1000)
    ])


@pytest.fixture
def fin_rst_reuse_bytes() -> bytes:
    """A connection that completes a handshake, closes (FIN), and then the
    same 4-tuple/stream context is reused by a fresh handshake — used to
    confirm handshakes_completed is cleared on FIN/RST rather than leaking
    stale state into the new connection."""
    packets = [
        # First connection: full handshake + FIN
        IP(src=ATTACKER, dst=VICTIM) / TCP(dport=8080, sport=6000, flags="S", seq=1),
        IP(src=VICTIM, dst=ATTACKER) / TCP(sport=8080, dport=6000, flags="SA", seq=100, ack=2),
        IP(src=ATTACKER, dst=VICTIM) / TCP(dport=8080, sport=6000, flags="A", seq=2, ack=101),
        IP(src=ATTACKER, dst=VICTIM) / TCP(dport=8080, sport=6000, flags="FA", seq=2, ack=101),
        # Second "connection" on the same port after close
        IP(src=ATTACKER, dst=VICTIM) / TCP(dport=8080, sport=6001, flags="S", seq=1),
    ]
    return _pcap_bytes(packets)


@pytest.fixture
def arp_spoof_bytes() -> bytes:
    """Two ARP replies Steping the same IP, from two different MACs —
    should NOT collapse into the same fingerprint (spoofing-detection
    requirement)."""
    packets = [
        Ether() / ARP(op=2, psrc=VICTIM, hwsrc="aa:aa:aa:aa:aa:aa"),
        Ether() / ARP(op=2, psrc=VICTIM, hwsrc="bb:bb:bb:bb:bb:bb"),
    ]
    return _pcap_bytes(packets)


@pytest.fixture
def icmp_bytes() -> bytes:
    return _pcap_bytes([
        IP(src=ATTACKER, dst=VICTIM) / ICMP(type=8, code=0)
        for _ in range(5)
    ])


@pytest.fixture
def mixed_protocol_bytes() -> bytes:
    """A little of everything, for integration-style tests."""
    packets = []
    for port in range(1000, 1020):
        packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(dport=port, flags="S"))
    packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(dport=443, sport=55000, flags="S", seq=1))
    packets.append(IP(src=VICTIM, dst=ATTACKER) / TCP(sport=443, dport=55000, flags="SA", seq=1, ack=2))
    packets.append(IP(src=ATTACKER, dst=VICTIM) / TCP(dport=443, sport=55000, flags="A", seq=2, ack=2))
    packets.append(IP(src=VICTIM, dst="8.8.8.8") / UDP(dport=53, sport=40000))
    packets.append(IP(src=ATTACKER, dst=VICTIM) / ICMP(type=8, code=0))
    return _pcap_bytes(packets)
