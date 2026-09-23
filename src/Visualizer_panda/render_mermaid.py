import json
import os
import re
import streamlit as st


# --- Unicode bold translation map ---
_NORMAL = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
)

_BOLD = (
    "𝗔𝗕𝗖𝗗𝗘𝗙𝗚𝗛𝗜𝗝𝗞𝗟𝗠𝗡𝗢𝗣𝗤𝗥𝗦𝗧𝗨𝗩𝗪𝗫𝗬𝗭"
    "𝗮𝗯𝗰𝗱𝗲𝗳𝗴𝗵𝗶𝗷𝗸𝗹𝗺𝗻𝗼𝗽𝗾𝗿𝘀𝘁𝘂𝘃𝘄𝘅𝘆𝘇"
    "𝟬𝟭𝟮𝟯𝟰𝟱𝟲𝟳𝟴𝟵"
)

_BOLD_MAP = str.maketrans(_NORMAL, _BOLD)


def _convert_markdown_bold(text: str) -> str:
    """
    Converts **text** into Unicode bold so it works inside Mermaid sequence diagrams.
    """

    def replacer(match):
        inner = match.group(1)
        return inner.translate(_BOLD_MAP)

    return re.sub(r"\*\*([^*]+?)\*\*", replacer, text)


def _render_mermaid(sliced_code: str, current_step: int, total_steps: int, title: str = "", container=None):
    """
    Renders an interactive Mermaid diagram by loading the template from render.html.
    """
    if not sliced_code:
        st.info("No diagram to view")
        return

    # --- Convert **bold** syntax to Unicode bold ---
    sliced_code = _convert_markdown_bold(sliced_code)

    # --- Optional: convert #123 to bold 123 ---
    sliced_code = re.sub(
        r"#(\d+)",
        lambda m: m.group(1).translate(_BOLD_MAP),
        sliced_code
    )
    

    packets_data = {}
    if "current" in st.session_state:
        for msg in reversed(st.session_state["current"].messages):
            metadata = msg.get("metadata", {})
            if isinstance(metadata, dict) and "packets_data" in metadata:
                packets_data = {str(p["id"]): p["summary"] for p in metadata["packets_data"]}
                break

    try:
        template_path = os.path.join(os.path.dirname(__file__), "render_d2.html")
        with open(template_path, "r", encoding="utf-8") as f:
            html_template = f.read()

        mermaid_html = (
            html_template
            .replace("{{SLICED_CODE}}", sliced_code)
            .replace("{{TITLE}}", title)
            .replace("{{CURRENT_STEP}}", str(current_step))
            .replace("{{TOTAL_STEPS}}", str(total_steps))
            .replace("{{PACKETS_JSON}}", json.dumps(packets_data))
        )

        dynamic_height = 800

        if container:
            with container:
                res = st.components.v1.html(mermaid_html, height=dynamic_height)
                if res:
                    st.session_state["selected_packet_id"] = res
        else:
            st.components.v1.html(mermaid_html, height=dynamic_height)

    except FileNotFoundError:
        st.error("Could not find render_d2.html template file.")