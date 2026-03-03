import json
import os
import re
import streamlit as st

def _render_mermaid(sliced_code: str, current_step: int, total_steps: int, title: str = "", container=None):
    """
    Renders an interactive Mermaid diagram by loading the template from render.html.
    """
    if not sliced_code:
        st.info("No diagram to view")
        return 

    # Step 1: Replace '#' with bold Markdown to avoid Mermaid ID conflicts
    # This turns #123 into **123**
    sliced_code = re.sub(r"#(\d+)", r"<b>\1</b>", sliced_code) 

    # Step 2: Format the Source metadata



    packets_data = {} 
    if "current" in st.session_state:
        for msg in reversed(st.session_state["current"].messages):
            metadata = msg.get("metadata", {})
            if isinstance(metadata, dict) and "packets_list" in metadata:
                packets_data = {str(p["id"]): p["summary"] for p in metadata["packets_list"]}
                break

    try:
        template_path = os.path.join(os.path.dirname(__file__), "render.html")
        with open(template_path, "r", encoding="utf-8") as f:
            html_template = f.read()
            
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