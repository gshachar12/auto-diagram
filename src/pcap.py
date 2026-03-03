import argparse
import tokens
from scapy.all import PcapReader
import streamlit as st
import re
import os

MAX_PCAP_TOKENS = 200_000
""" pcap.py - Functions to parse pcap files and generate prompts for LLMs. """


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
            packets = m.get("metadata", {}).get("packets_list", [])
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
    with PcapReader(pcap_file) as pcap_reader: # Use context manager to ensure proper file handling
        for idx, packet in enumerate(pcap_reader):
            summary = packet.summary()
            details = packet.show(dump=True) if mode == "full" else ""
            packets_data.append({
                "id": idx,
                "summary": summary,
                "details": details
            })
    return packets_data

def parse(pcap_file, mode=""):
    """_summary_

    Args:
        pcap_file (_type_): _description_
        mode (str, optional): _description_. Defaults to "".

    Returns:
        _type_: _description_
    returns List of packet summaries or detailed packet info based on mode.
    """
    packets = []
    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if mode == "full":
                packets.append(packet.show(dump=True))
            else:
                packets.append(packet.summary())
    return packets


# pcap.py - Update the prompt function
def prompt(pcap_file_name, pcap_file, mode=""):
    # Change: Use the version that includes IDs
    packets_data = parse_with_indices(pcap_file=pcap_file, mode=mode)
    
    # Extract text for the LLM prompt
    if mode == "full":
        packets_text = [p["details"] for p in packets_data]
    else:
        packets_text = [p["summary"] for p in packets_data]
        
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
