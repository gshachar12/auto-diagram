import json
import re
import streamlit as st
import time
import streamlit.components.v1 as components
from core import generate_diagram
from messages import create_message_from_bytes
from animation import create_animation_section
from render import render_svg
from export import export_diagram
from files import display_session_attachments
from validator import validator_tab 
from packets_tab import display_packet_tab

def diagram_viewer():
    
    focus_step = st.query_params.get("focus_step")
    all_labels = ["Viewer", "Animation", "Entities", "PCAP Analysis", "Validation Report", "Export", "Files"]
    # If there is a focus_step, move "PCAP Analysis" to the front of the list
    if focus_step:
        # Remove it from its original spot and insert at index 0
        all_labels.insert(0, all_labels.pop(all_labels.index("PCAP Analysis")))

    tabs = st.tabs(all_labels)

    # We use a dictionary to map the labels back to their variables safely
    tab_map = {label: tabs[i] for i, label in enumerate(all_labels)}
    validation_tab = tab_map["Validation Report"] 
    viewer = tab_map["Viewer"]
    animation = tab_map["Animation"]
    entities_tab = tab_map["Entities"]
    pcap_analysis = tab_map["PCAP Analysis"]
    export = tab_map["Export"]
    files_tab = tab_map["Files"]
    code = st.session_state["current"].diagram_text
    entities_json = st.session_state["current"].entities_json
    steps_json = st.session_state["current"].steps_json
    has_code = bool(code)

    try: 
        steps_list = json.loads(steps_json)
    except:
        if steps_json: # Only show error if steps_json is not empty
            st.error(f"Error parsing steps JSON: {steps_json}")
        steps_list = []

    with viewer:
        #_render_d2(code, current_step=0, total_steps=0, title="Full Diagram View")
        render_svg(code, title="Full Diagram View")

    with entities_tab:
        st.subheader("Network Entities & Roles")
        try:
            ent_list = json.loads(entities_json)
        except json.JSONDecodeError:
            st.error("Error parsing entities JSON.")
            st.info("No entities identified yet. Generate a new diagram to see extracted roles.")
            ent_list = []
        if ent_list:
            st.table(ent_list)
        else:
            st.info("No entities identified yet. Generate a new diagram to see extracted roles.")
    with validation_tab:
        validator_tab()
    with export:
        export_diagram(code)

    with animation:
        st.subheader("Sequence Diagram Animation")  
        if has_code:
            create_animation_section(steps_list, ent_list, code)
        else:
            st.info("Generate a diagram first to see the animation.")

    with pcap_analysis:
        display_packet_tab(steps_list, focus_step)

    with files_tab:
        display_session_attachments()
