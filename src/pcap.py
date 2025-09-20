import argparse
import tokens
from scapy.all import PcapReader

MAX_PCAP_TOKENS = 200_000


def parse(pcap_file, mode=""):
    packets = []
    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if mode == "full":
                packets.append(packet.show(dump=True))
            else:
                packets.append(packet.summary())
    return packets


def prompt(pcap_file_name, pcap_file, mode=""):
    packets = parse(pcap_file=pcap_file, mode=mode)
    prompt = ""
    if mode == "full":
        separator = "\n" + "=" * 50 + "\n"
        content = separator.join(packets)
        prompt = f"""
### Detailed Packets ###

**Source PCAP File:** `{pcap_file_name}`
**Packet Count:** `{len(packets)}`
**Content Type:** Full, layer-by-layer packet details.

Packets of network capture for diagram request

<DETAILED_PACKETS>
{content}
</DETAILED_PACKETS>
"""
    else:
        # Clear and concise prompt for summary analysis
        content = "\n".join(packets)
        prompt = f"""
### Packet Summary Analysis Request ###

**Source PCAP File:** `{pcap_file_name}`
**Packet Count:** `{len(packets)}`
**Content Type:** One-line packet summaries.

Packet summaries of network capture for diagram request

<PACKET_SUMMARIES>
{content}
</PACKET_SUMMARIES>
"""

    prompt_tokens = tokens.count_tokens(prompt)
    print(f"pcap: {pcap_file_name} mode: {mode} tokens: {prompt_tokens}")
    if prompt_tokens > MAX_PCAP_TOKENS:
        raise Exception(
            f"PCAP file (mode={mode}) too large: {prompt_tokens} > {MAX_PCAP_TOKENS}."
        )
    return prompt


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("pcap_path")
    args = p.parse_args()
    with open(args.pcap_path, "rb") as r:
        prompt(args.pcap_path, r)
