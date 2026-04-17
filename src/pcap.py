import argparse
import tokens
from scapy.all import PcapReader
from scapy.all import rdpcap, TCP, UDP, DNS, Raw
import streamlit as st
import re
import os

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


def extract_relevant_packets(packets_data, max_packets=200, sampling_limit=3):
    relevant = []
    seen_patterns = {}

    for p_dict in packets_data:
        pkt = p_dict["raw"]        
        
        # Immediate Noise Removal
        if not pkt.haslayer("IP") or pkt.haslayer("ICMP"):
            continue

        ptype = ""
        fingerprint = ""
        info = ""

        # DNS Logic
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            if dns.qr == 0 and dns.qd:  # Query
                qname = str(dns.qd.qname)
                ptype = "DNS_QUERY"
                fingerprint = f"DNS_Q:{qname}"
                info = f"Query: {qname}"
            else: # Response
                ptype = "DNS_RESPONSE"
                fingerprint = "DNS_R" 
                info = "Response Received"

        # TCP Logic
        elif pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            flags = str(tcp.flags)
            
            # Skip pure ACKs/Handshakes
            if flags in ["A", "S", "SA"]:
                continue
                
            ptype = "TCP_EVENT"
            fingerprint = f"TCP:{flags}:{tcp.dport}"
            info = f"Flags: {flags} | DPort: {tcp.dport}"

        # UDP Logic
        elif pkt.haslayer("UDP"):
            ptype = "UDP_PAYLOAD"
            fingerprint = f"UDP:{pkt['UDP'].dport}"
            # Check for Raw payload size
            size = len(pkt["Raw"].load) if pkt.haslayer("Raw") else 0
            info = f"Size: {size} bytes | DPort: {pkt['UDP'].dport}"

        if fingerprint:
            current_count = seen_patterns.get(fingerprint, 0)
            if current_count >= sampling_limit:
                continue
            seen_patterns[fingerprint] = current_count + 1

        if ptype:
            relevant.append({
                "id": p_dict["id"],
                "summary": p_dict["summary"],
                "timestamp": p_dict["timestamp"],
                "details": p_dict["details"],
                "protocol": get_protocol_name(pkt),
                "length": len(pkt),
                "type": ptype,
                "src": pkt["IP"].src,
                "dst": pkt["IP"].dst,
                "info": info
            })

        if len(relevant) >= max_packets:
            break
        print(f"timestamp: {p_dict['timestamp']}")
    return relevant
def pcap_analysis_tab():
    # Get the current session and diagram data
    curr_session = st.session_state["current"]
    diagram_raw = getattr(curr_session, "diagram_text", "")
    
    if not diagram_raw:
        st.info("No diagram generated yet. Please chat to create one.")
        return

    # Split the diagram code from the entities JSON
    if "|||" in diagram_raw:
        diagram_code, _ = diagram_raw.split("|||", 1)
    else:
        diagram_code = diagram_raw

    # Extract all assistant messages that contain packet data
    all_packets = []
    for m in curr_session.messages:
        if m.get("msg", {}).get("role") == "assistant":
            packets = m.get("metadata", {}).get("packets_data", [])
            if packets:
                all_packets = packets # Use the most recent packet list

    if not all_packets:
        st.warning("No PCAP data found for this diagram.")
        return

    st.subheader("🔍 Evidence by Diagram Step")

    # Parse the Mermaid code to find steps and their packet references
    # We look for lines like: "Note over VR: (Source: Packet #12)" or arrows with packet info
    lines = diagram_code.split('\n')
    step_counter = 1
    
    for line in lines:
        # Match lines that represent a step (arrows or notes)
        if "->" in line or "Note over" in line:
            # Try to find "Packet #ID" in the line
            packet_match = re.search(r"Packet #(\d+)", line)
            
            # Create a clean label for the step
            clean_label = line.replace("->>", " to ").replace("->", " to ").strip()
            clean_label = re.sub(r'rect\s+rgb\(.*?\)', '', clean_label) # Remove colors
            
            if packet_match:
                packet_id = int(packet_match.group(1))
                # Find the specific packet data by ID
                target_packet = next((p for p in all_packets if p.get("id") == packet_id), None)
                
                if target_packet:
                    with st.expander(f"Step {step_counter}: {target_packet['summary']}"):
                        st.code(target_packet['details'], language="text")
                        st.caption(f"Full Evidence from Packet #{packet_id}")
                    step_counter += 1
            elif "autonumber" not in line and "participant" not in line and "sequenceDiagram" not in line:
                # Display steps that don't have packet evidence as static info
                # st.text(f"Step: {line.strip()}")
                pass

    if step_counter == 1:
        st.info("No packet references (Packet #ID) found in the current diagram syntax.")
        
        
def parse_with_indices(pcap_file, mode=""):
    """_summary_

    Args:
        pcap_file (_type_): _description_
        mode (str, optional): _description_. Defaults to "".

    Returns:
        _type_: _description_
        
        takes a pcap file and mode, returns list of dicts with packet summaries or details with a unique id.
    """
    
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


# pcap.py - Update the prompt function
def prompt(pcap_file_name, pcap_file, mode=""):
    # Change: Use the version that includes IDs
    packets_data = parse_with_indices(pcap_file=pcap_file, mode=mode)
    # Extract text for the LLM prompt
    if mode == "full":
        packets_text = [p["details"] for p in packets_data]
    elif mode == "summary":
        packets_text = [p["summary"] for p in packets_data]
    elif mode == "extraction":
        # 1. Filter the data into a new variable to avoid overwriting the original list
        packets_data = extract_relevant_packets(packets_data, max_packets=200, sampling_limit=3)
        # 2. Format the text for the LLM using the correct keys ('pkt_index', 'type', 'info', etc.)
        # convert 
        packets_text = [f"Packet #{p['id']}: type: {p['type']}, src: {p['src']}, dst: {p['dst']}, info: {p['info']}, timestamp: {p['timestamp']}" for p in packets_data]
        
    content = "\n".join(packets_text)
    
    # Build the prompt string for the AI
    p_string = f"### Packet Analysis ###\n<PACKETS>\n{content}\n</PACKETS>"
    # Return both the prompt and the structured list
    return p_string, packets_data


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("pcap_path")
    args = p.parse_args()
    with open(args.pcap_path, "rb") as r:
        prompt(args.pcap_path, r)
