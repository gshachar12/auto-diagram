import argparse
import tokens
from scapy.all import PcapReader
from scapy.all import rdpcap, TCP, UDP, DNS, Raw
from collections import Counter
import pyshark
import streamlit as st
import tempfile
import re
import os
import asyncio
most_common_ip_addresses = 2 # If more than 2 IPs dominate the traffic, it's likely a DoS/DDoS or an automated exfiltration vector.
layer2_traffic_ratio_threshold = 0.25  # If ARP or similar Layer 2 traffic exceeds 25% of total, it's likely a discovery phase or ARP storm.
heavy_hitter_threshold = 0.40  # If a single IP is responsible for more than 40% of traffic, it's likely a DoS/DDoS source or an automated exfiltration vector.
port_scan_threshold = 0.15  # If a specific port is targeted in more than 15% of traffic, it may indicate a port scan or brute force attempt.       
MAX_PCAP_TOKENS = 200_000

def get_protocol_name(pkt):
    # Check for IPv4
    if pkt.haslayer("IP"):
        return pkt["IP"].payload.name
    
    # Check for IPv6
    elif pkt.haslayer("IPv6"):
        return pkt["IPv6"].payload.name
    
    # Check for ARP (Very common in local PCAPs)
    elif pkt.haslayer("ARP"):
        return "ARP"
    
    # Fallback to the Highest Layer name (e.g., 'Ethernet' or 'Dot11')
    return pkt.lastlayer().name

def build_step_evidence_map(steps_json: str, packets: Optional[List[Dict]]) -> Dict[str, List[Dict]]:
    """
    Extracts packet evidence links from the steps JSON and maps each step 
    to its corresponding list of raw packet dictionaries.
    """
    if not packets:
        return {}
        
    try:
        steps_list = json.loads(steps_json) if steps_json else []
    except Exception as e:
        print(f"Error parsing steps JSON in build_step_evidence_map: {e}")
        steps_list = []

    step_evidence_map = {}
    if not steps_list:
        return {}

    for item in steps_list:
        step_num = item.get("STEP", "?")
        raw_evidence = item.get('EVIDENCE', [])
        
        # Handle EVIDENCE correctly whether it's a single string or a list
        evidence_list = [raw_evidence] if isinstance(raw_evidence, str) else raw_evidence
        
        # Parse out numerical packet IDs using regex
        target_ids = []
        for s in evidence_list:
            match = re.search(r"(\d+)", str(s))
            if match:
                target_ids.append(int(match.group(1)))
                
        # Filter and bind the actual matching packet objects
        step_evidence_map[step_num] = [p for p in packets if int(p.get("id", -1)) in target_ids]
        
    return step_evidence_map


def extract_relevant_packets(
    pcap_bytes, max_packets=250, sampling_limit=3, display_filter="ip or arp"
):
    """Final Agnostic PCAP Reduction Engine.

    Transforms raw network captures into a high-fidelity condensed
    "Storyboard". Defends against Token Bloat from DDoS (Botnets), Network
    Sweeps, and Data Streams by tracking fingerprintal state signatures
    independently of endpoint scales.
    """
    relevant = []
    print("sampling_limit:", sampling_limit)

    # Core memory engine tracking abstract fingerprintal patterns
    # Schema: { fingerprint_key: { "count": int, "total_bytes": int, "first_idx": int, "srcs": set, "dsts": set } }
    fingerprint_tracker = {}
    handshakes_completed = set()

    # Global diagnostic counters
    total_raw_packets = 0

    # Initialize a new event loop for asynchronous pyshark processing
    loop = asyncio.new_event_loop()

    # --- WINDOWS FIX: Use delete=False to avoid exclusive file locking ---
    temp_pcap = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    pcap_file_path = temp_pcap.name

    try:
        # Write binary data and immediately close the handle to release the OS lock
        temp_pcap.write(pcap_bytes)
        temp_pcap.close()

        # Open the temporary file path using FileCapture safely
        cap = pyshark.FileCapture(
            pcap_file_path, display_filter=display_filter, eventloop=loop
        )

        # Wrap in an inner try-catch to guarantee cap.close() runs if packet parsing fails
        try:
            for pkt in cap:
                total_raw_packets += 1
                try:
                    # 1. Agnostic Layer 2/3 Identity Extraction
                    if hasattr(pkt, "ip"):
                        src = pkt.ip.src
                        dst = pkt.ip.dst
                        l4_proto = (
                            pkt.transport_layer
                            if pkt.transport_layer
                            else "IP_RAW"
                        )
                    elif hasattr(pkt, "arp"):
                        src = (
                            pkt.arp.src_proto_ipv4
                            if hasattr(pkt.arp, "src_proto_ipv4")
                            else "N/A"
                        )
                        dst = (
                            pkt.arp.dst_proto_ipv4
                            if hasattr(pkt.arp, "dst_proto_ipv4")
                            else "N/A"
                        )
                        l4_proto = "ARP"
                    else:
                        continue

                    state_signature = ""
                    info_str = ""

                    # 2. Extract Structural Protocol State (Agnostic to high-volume background noise)
                    if l4_proto == "TCP":
                        flags = pkt.tcp.flags
                        dst_port = pkt.tcp.dstport
                        stream_id = pkt.tcp.stream
                        state_signature = (flags, dst_port)
                        info_str = f"Flags: {flags} | DPort: {dst_port}"

                        if (
                            "0x02" in flags or "0x12" in flags
                        ):  # SYN or SYN-ACK, indicating handshake initiation
                            l4_proto = "TCP"
                            state_signature = (flags, dst_port)
                            flag_name = "SYN" if "0x02" in flags else "SYN-ACK"
                            info_str = f"Handshake Phase | Flags: {flags} ({flag_name}) | DPort: {dst_port}"

                        # Handle pure ACKs in the context of completed handshakes
                        elif flags == "0x10":
                            # If this stream has already completed a handshake, treat it as data transfer
                            if stream_id in handshakes_completed:
                                l4_proto = "TCP_DATA_STREAM"
                                state_signature = dst_port
                                info_str = f"Data Transfer | DPort: {dst_port}"
                            else:
                                # If this is the first time we see a pure ACK in this stream,
                                # and there were previous SYN/SYN-ACK messages, this is the ACK that completes the handshake!
                                l4_proto = "TCP"
                                state_signature = (flags, dst_port)
                                info_str = f"Handshake Completed (ACK) | Flags: {flags} | DPort: {dst_port}"

                                # Now, all subsequent packets in this stream will be classified as data
                                handshakes_completed.add(stream_id)

                        # 3. If this is a FIN or RST, we can consider the stream closed and remove it from tracking
                        else:
                            l4_proto = "TCP"
                            state_signature = (flags, dst_port)
                            info_str = f"Flags: {flags} | DPort: {dst_port}"

                            # If this stream has been closed or reset, remove it from tracking
                            if "0x01" in flags or "0x04" in flags:  # FIN or RST
                                handshakes_completed.discard(stream_id)

                    elif l4_proto == "UDP":
                        dst_port = pkt.udp.dstport
                        state_signature = dst_port
                        info_str = f"DPort: {dst_port}"

                    elif l4_proto == "ARP":
                        opcode = pkt.arp.opcode
                        sender_mac = (
                            pkt.arp.src_hw_mac
                            if hasattr(pkt.arp, "src_hw_mac")
                            else "N/A"
                        )
                        # CRITICAL FIX: Keeping MAC in the fingerprint state to prevent an attacker
                        # from masking a legitimate router's vital signals.
                        state_signature = (opcode, sender_mac)
                        info_str = f"Opcode: {opcode} | Sender MAC: {sender_mac}"

                    elif l4_proto == "ICMP":
                        state_signature = f"{pkt.icmp.type}:{pkt.icmp.code}"
                        info_str = f"Type: {pkt.icmp.type} | Code: {pkt.icmp.code}"

                    # 3. Dynamic Decoupled fingerprint Key Creation
                    # We omit explicit IP boundaries from the key to auto-collapse horizontal sweeps and botnets
                    fingerprint_key = (l4_proto, state_signature)
                    pkt_length = int(pkt.length)

                    if fingerprint_key not in fingerprint_tracker:
                        # --- STATE TRANSITION DETECTED (New fingerprint Blueprint) ---
                        fingerprint_tracker[fingerprint_key] = {
                            "count": 1,
                            "total_bytes": pkt_length,
                            "first_index_in_relevant": len(relevant),
                            "unique_sources": {src},
                            "unique_destinations": {dst},
                        }

                        relevant.append({
                            "id": int(pkt.number),
                            "timestamp": pkt.sniff_time.isoformat(),
                            "protocol": pkt.highest_layer,
                            "src": src,
                            "dst": dst,
                            "length": pkt_length,
                            "info": info_str,
                        })
                    else:
                        # --- REPETITIVE CONTEXT RECOGNIZED ---
                        stats = fingerprint_tracker[fingerprint_key]
                        stats["count"] += 1
                        stats["total_bytes"] += pkt_length
                        stats["unique_sources"].add(src)
                        stats["unique_destinations"].add(dst)

                        # Preserve initial timeline resolution for structural sequence verification
                        if stats["count"] <= sampling_limit:
                            relevant.append({
                                "id": int(pkt.number),
                                "timestamp": pkt.sniff_time.isoformat(),
                                "protocol": pkt.highest_layer,
                                "src": src,
                                "dst": dst,
                                "length": pkt_length,
                                "info": info_str,
                            })
                        else:
                            # --- COMPRESSION DEFENSE ACTIVATED ---
                            # Drop the raw packet, back-propagate density context into the first sample block
                            orig_idx = stats["first_index_in_relevant"]
                            omitted = stats["count"] - sampling_limit
                            total_mb = stats["total_bytes"] / (1024 * 1024)

                            src_count = len(stats["unique_sources"])
                            dst_count = len(stats["unique_destinations"])

                            relevant[orig_idx]["info"] = (
                                f"{info_str} | [Omitted {omitted} structurally identical packets "
                                f"across {src_count} unique source(s) -> {dst_count} target destination(s). "
                                f"Accumulated Volume: {total_mb:.2f} MB]"
                            )

                    # Hard Context Window safety brake
                    if len(relevant) >= max_packets:
                        break

                except (AttributeError, ValueError):
                    continue
        finally:
            cap.close()

    finally:
        # --- CLEANUP: Manually wipe the file from disk on function exit ---
        try:
            if os.path.exists(pcap_file_path):
                os.remove(pcap_file_path)
        except Exception:
            pass
        loop.close()

    return relevant


def parse_with_indices(pcap_file, mode=""):
    """_summary_

    Args:
        pcap_file (_type_): _description_
        mode (str, optional): _description_. Defaults to "".

    Returns:
        _type_: _description_
        
        takes a pcap file and mode, returns list of dicts with packet summaries or details with a unique id.
    """
    pcap_file = IOBytes(pcap_file)  # Read the uploaded file into bytes
    packets_data = [] # List to hold packet info with indices
    st.info(f"PCAP file found, file size: {len(pcap_file.getbuffer())} bytes")
    with PcapReader(pcap_file) as pcap_reader: # Use context manager to ensure proper file handling
        pcap_reader_list  = list(pcap_reader) # Convert to list for multiple iterations
        start_time = float(pcap_reader_list[0].time)
        for idx, packet in enumerate(pcap_reader_list):
            summary = packet.summary()
            details = packet.show(dump=True) if mode == "full" or mode == "extraction" else ""
            raw_packet = packet if mode == "full" or mode == "extraction" else None # Get raw bytes for potential future use
            packets_data.append({
                "id": idx,
                "timestamp": f"{float(packet.time)-start_time:.6f}", # Relative timestamp for better readability
                "summary": summary,
                "details": details,
                "raw": raw_packet
            })
    return packets_data


def prompt(pcap_file_name, pcap_file, mode=""):
    packets_text = []
    packets_data = []
    if mode == "full" or mode == "extract":
        packets_data = parse_with_indices(pcap_file=pcap_file, mode=mode)
        # Extract text for the LLM prompt
        if mode == "full":
            packets_text = [p["details"] for p in packets_data]
        elif mode == "summary":
            packets_text = [p["summary"] for p in packets_data]
    elif mode == "extraction":
        # 1. Filter the data into a new variable to avoid overwriting the original list
        packets_data =  extract_relevant_packets(pcap_file, max_packets=200, sampling_limit=3)
        # 2. Format the text for the LLM using the correct keys ('pkt_index', 'type', 'info', etc.)
        packets_text = [
            f"Packet #{p['id']}: type: {p['protocol']}, src: {p['src']}, dst: {p['dst']}, info: {p['info']}, timestamp: {p['timestamp']}"
            for p in packets_data
        ]        
    content = "\n".join(packets_text)
    
    # Build the prompt string for the AI
    p_string = f"### Packet Analysis ###\n<PACKETS>\n{content}\n</PACKETS>"
    # Return both the prompt and the structured list
    return p_string, packets_data
