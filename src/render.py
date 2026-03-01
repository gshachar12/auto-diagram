import json
import os
import streamlit as st
from typing import List, Optional
from core import generate_diagram
import streamlit as st
import streamlit as st
import json
import os

def _render_mermaid(sliced_code: str, current_step: int, total_steps: int, title: str = "", container=None):
    """
    Renders an interactive Mermaid diagram by loading the template from render.html.
    """
    if not sliced_code:
        st.info("No diagram to view")
        return 

    # English comments: Retrieve packets list from session state
    packets_data = {}
    if "current" in st.session_state:
        for msg in reversed(st.session_state["current"].messages):
            metadata = msg.get("metadata", {})
            if isinstance(metadata, dict) and "packets_list" in metadata:
                packets_data = {str(p["id"]): p["summary"] for p in metadata["packets_list"]}
                break

    # English comments: Load the HTML template
    try:
        # Using utf-8 encoding to ensure emojis in the HTML file are read correctly
        template_path = os.path.join(os.path.dirname(__file__), "render.html")
        with open(template_path, "r", encoding="utf-8") as f:
            html_template = f.read()
            
        # English comments: Inject dynamic data into the template
        mermaid_html = html_template.replace("{{SLICED_CODE}}", sliced_code) \
                                   .replace("{{TITLE}}", title) \
                                   .replace("{{CURRENT_STEP}}", str(current_step)) \
                                   .replace("{{TOTAL_STEPS}}", str(total_steps)) \
                                   .replace("{{PACKETS_JSON}}", json.dumps(packets_data))
        
        dynamic_height = 800

        if container:
            with container:
                res = st.components.v1.html(mermaid_html, height=dynamic_height)
                if res:
                    st.session_state["selected_packet_id"] = res
        else:
            st.components.v1.html(mermaid_html, height=dynamic_height)

    except FileNotFoundError:
        st.error("Could not find render.html template file.")