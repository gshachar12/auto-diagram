"""
Quick sanity test for the Reducer, using a synthetically generated PCAP:
  - a TCP 3-way handshake + PSH-ACK data transfer (checks the R6/flag fix)
  - a port scan (many SYNs, single source, many destination ports -> should
    collapse into a single fingerprint with high aggregate cardinality)
  - a couple of DNS (UDP/53) queries
Not a rigorous test suite — just enough to confirm the pipeline runs and
the key behaviors (fingerprint collapsing, R1 traceability, R5 budget
handling) are visible in the output.
"""
import io
import sys

from scapy.all import IP, TCP, UDP, wrpcap
from scapy.utils import PcapWriter

sys.path.insert(0, ".")
from reducer import reduce_pcap
from filter_generator import generate_filter, NO_OP_FILTER


def build_test_pcap() -> bytes:
    packets = []
    victim = "10.0.0.5"
    attacker = "203.0.113.17"

    # --- Port scan: SYNs from attacker to many destination ports on victim ---
    for port in range(1000, 1050):
        packets.append(IP(src=attacker, dst=victim) / TCP(dport=port, flags="S", seq=1000))

    # --- Legit 3-way handshake + data transfer on port 443 ---
    packets.append(IP(src=attacker, dst=victim) / TCP(dport=443, sport=55000, flags="S", seq=2000))
    packets.append(IP(src=victim, dst=attacker) / TCP(sport=443, dport=55000, flags="SA", seq=3000, ack=2001))
    packets.append(IP(src=attacker, dst=victim) / TCP(dport=443, sport=55000, flags="A", seq=2001, ack=3001))
    # Data transfer — PSH-ACK packets (this is the bug-fix case: these should
    # collapse into TCP_DATA_STREAM, not stay as individual "Flags: 0x18" entries)
    for i in range(20):
        packets.append(
            IP(src=attacker, dst=victim)
            / TCP(dport=443, sport=55000, flags="PA", seq=2001 + i * 100, ack=3001)
            / (b"X" * 50)
        )

    # --- A couple of DNS queries ---
    packets.append(IP(src=victim, dst="8.8.8.8") / UDP(dport=53, sport=40000))
    packets.append(IP(src=victim, dst="8.8.8.8") / UDP(dport=53, sport=40001))

    buf = io.BytesIO()
    # scapy needs a real file path for wrpcap; use a temp file instead of BytesIO
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    wrpcap(path, packets)
    with open(path, "rb") as f:
        data = f.read()
    return data


def main():
    pcap_bytes = build_test_pcap()
    print(f"Synthetic PCAP size: {len(pcap_bytes)} bytes\n")

    # --- Filter Generator (keyword fallback, no LLM) ---
    description = "The attacker performed a port scan against the victim, then established an HTTPS session."
    filt = generate_filter(description)
    print(f"Generated filter: {filt!r}\n")

    # --- Reducer, generous budget ---
    out = reduce_pcap(
        pcap_bytes=pcap_bytes,
        token_budget=5000,
        filtering_limit=3,
        filter_string=None,  # run unfiltered first to see full behavior
    )

    print("=== Compression stats ===")
    print(out.compression_stats)
    print(f"Budget status: {out.budget_status.value} ({out.budget_status_detail})\n")

    print("=== Reduced representation ===")
    for item in out.reduced_representation:
        agg_note = ""
        if item.aggregate:
            agg_note = (
                f"  [AGGREGATE: count={item.aggregate.count}, "
                f"srcs={len(item.aggregate.unique_sources)}, "
                f"dsts={len(item.aggregate.unique_destinations)}]"
            )
        print(f"  #{item.packet_id:>4} {item.timestamp}  {item.protocol:<6} "
              f"{item.src:>15} -> {item.dst:<15}  {item.info}{agg_note}")

    print(f"\n=== Fingerprint index ({len(out.fingerprint_index)} keys) ===")
    for key, agg in out.fingerprint_index.items():
        print(f"  {key}: count={agg.count}, bytes={agg.total_bytes}, "
              f"srcs={agg.unique_sources}, dsts={len(agg.unique_destinations)} unique")

    # --- Reducer again, with a very tight budget, to exercise R5 (fail-loud) ---
    print("\n\n=== Tight-budget run (expect budget_status=exceeded) ===")
    tight_out = reduce_pcap(
        pcap_bytes=pcap_bytes,
        token_budget=50,  # deliberately too small to fit everything
        filtering_limit=3,
    )
    print(f"Budget status: {tight_out.budget_status.value}")
    print(f"Detail: {tight_out.budget_status_detail}")
    print(f"Items retained before stopping: {len(tight_out.reduced_representation)}")


if __name__ == "__main__":
    main()
