import os
import json
import asyncio
import sys
from preprocessing import extract_relevant_packets

def run_pcap_compression_test(pcap_path):
    """
    Cross-platform test matrix. Seamlessly runs on Windows, macOS, and Linux.
    """
    print("=" * 60)
    print(f"STARTING PCAP COMPRESSION TEST (CROSS-PLATFORM)")
    print(f"Target File: {os.path.basename(pcap_path)}")
    print("=" * 60)
    
    print("[*] Assessing storage metrics...")
    raw_file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
    print(f"--> Raw File Size: {raw_file_size_mb:.2f} MB")
    print("-" * 60)

    print("[*] Running Adaptive Reduction Engine...")
    compressed_json_data, raw_packet_count = extract_relevant_packets(
        pcap_path, max_packets=250, sampling_limit=8
    )
    
    compressed_packet_count = len(compressed_json_data)
    
    if raw_packet_count > 0:
        compression_ratio = (1 - (compressed_packet_count / raw_packet_count)) * 100
    else:
        compression_ratio = 0

    print("\n" + "=" * 20 + " CONDENSED STORYBOARD OUTPUT (TO LLM) " + "=" * 20)
    preview_limit = 5
    print(json.dumps(compressed_json_data, indent=2))
    
    if compressed_packet_count > preview_limit:
        print(f"\n... [Truncated {compressed_packet_count - preview_limit} more unique/sampled storyboard frames] ...")
    print("=" * 78 + "\n")

    print("=" * 60)
    print("FINAL METRIC COMPARISON REPORT")
    print("=" * 60)
    print(f"📊 Raw Packets in Captured File: {raw_packet_count:,} packets")
    print(f"⚡ Rows/Packets sent to LLM:    {compressed_packet_count:,} unique entries")
    print(f"📉 Total Context Window Savings: {compression_ratio:.2f}% fewer tokens/lines")
    print(f"📦 Status:                      {'SUCCESS (Safe for LLM)' if compressed_packet_count <= 250 else 'WARNING'}")
    print("=" * 60)

def main(argv):

    # if __name__ == "__main__":
    # target_pcap = "../pcaps/ARP_Spoofing/arp_spoofing.pcap"
    # if not os.path.exists(target_pcap):
    #     print(f"[!] Error: Target PCAP file not found at {target_pcap}")
    # else:
    #     run_pcap_compression_test(target_pcap)


    if len(argv) < 2:
        print("Usage: python test_preprocessing.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_path = argv[1]
    if not os.path.isfile(pcap_path):
        print(f"[!] Error: File not found at {pcap_path}")
        sys.exit(1)

    run_pcap_compression_test(pcap_path)

if __name__ == "__main__":
    main(sys.argv)

