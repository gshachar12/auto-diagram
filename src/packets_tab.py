import argparse
import tokens
from scapy.all import PcapReader
from scapy.all import rdpcap, TCP, UDP, DNS, Raw
import streamlit as st
import re
import os


def display_packet_tab(steps_list, focus_step = True):
    st.subheader("🔍 Pcap Packet Evidence")
    packets = None
    diagram_text = ""
    
    # Extract packets from message history
    for msg in reversed(st.session_state["current"].messages):
        metadata = msg.get("metadata", {})
        # Skip if metadata is just a string or not a dict
        if not isinstance(metadata, dict):
            print("Skipping: Metadata is not a dictionary")
            continue
            
        # ONLY stop the loop if 'packets_data' is actually present
        if "packets_data" in metadata:
            packets = metadata["packets_data"]
            print(f"Found metadata with 'packets_data' key. Number of packets: {len(packets)}")
            print("✅ Found packet evidence!")
            break
    if packets is None:
        st.warning("⚠️ No structured PCAP data found. Ensure you uploaded a PCAP file.")
    else:
        selected_id = st.session_state.get("selected_packet_id")
        evidence_found = False
        if steps_list and any("EVIDENCE" in step for step in steps_list):
            st.info(f"✅ Found packet evidence! Total packets: {len(packets)}")
            evidence_found = True
        else:
            st.warning("⚠️ No packet evidence linked to diagram steps. Generate a new diagram with PCAP data to see evidence here.")
        
        if evidence_found:
            for item in steps_list:
                step_num = item.get("STEP", "?")
                is_focused = (step_num == str(focus_step))
                description = item.get("DESCRIPTION", "?")
            
                # Handle EVIDENCE correctly (whether it's a string or a list)
                raw_evidence = item.get('EVIDENCE', [])
                if isinstance(raw_evidence, str):
                    # If it's a string like "Pkt 3", wrap it in a list
                    evidence_list = [raw_evidence]
                else:
                    evidence_list = raw_evidence
                    
                # Extract the numbers from the list of strings
                target_ids = []
                for s in evidence_list:
                    match = re.search(r"(\d+)", str(s))
                    if match:
                        target_ids.append(int(match.group(1)))

                # Find the actual packet objects that match these IDs
                matched_packets = [p for p in packets if int(p.get("id", -1)) in target_ids]
                
                with st.expander(f"**Step {step_num}**: {description} ", expanded=is_focused):
                    if is_focused:
                        st.markdown("🎯 **Direct Link Focus**")
                    if item.get("INSIGHT"):
                        st.subheader(f"**Step Description:**")
                        st.info(f"{item['INSIGHT']}")
                        
                    st.subheader(f"**Linked Packet Evidence:**")
                    # Loop through the matched packets to display them
                    for packet_obj in matched_packets:
                        p_id = packet_obj.get("id")
                        is_selected = (str(p_id) == str(selected_id))
                        # Show the Wireshark-style timestamp we created earlier - 0
                        ts = packet_obj.get("timestamp", "0.000000")
                        
                        # Show the packet details
                        content = packet_obj.get("details") or packet_obj.get("summary") or "No details"
                        
                        with st.expander(f"**📦Packet-Number:`#{p_id}` | ⏱ Timestamp: `{ts}s`**"):
                            st.markdown(f"**Packet source: `{packet_obj.get('src', 'Unknown')}`**")
                            st.markdown(f"**Packet destination: `{packet_obj.get('dst', 'Unknown')}`**")
                            st.markdown(f"**Packet protocol: `{packet_obj.get('protocol', 'Unknown')}`**")
                            st.markdown (f"**Packet length: `{packet_obj.get('length', 'Unknown')}` bytes**")
                            st.markdown(f"**Packet info: 0 `{packet_obj.get('info', 'No info available')}`**")
                            with st.expander("**Full Packet Content**"):
                                st.code(content, language="text")
        if focus_step:
            st.components.v1.html(
                f"""
                <script>
                    setTimeout(() => {{
                        window.parent.document.querySelectorAll('[data-testid="stExpander"]').forEach(el => {{
                            // Look for the specific Step number in the expander header
                            if (el.innerText.includes("Step {focus_step}:") || el.innerText.includes("Step {focus_step} ")) {{
                                el.scrollIntoView({{behavior: "smooth", block: "start"}});
                            }}
                        }});
                    }}, 500); // Small delay to allow Streamlit to finish rendering the 'expanded' state
                </script>
                """,
                height=0,
            )
