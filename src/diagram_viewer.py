import base64
import html as _html
import json
import uuid
import re
import zlib
import streamlit as st
import time
import urllib
from typing import Dict, List, Optional
import streamlit.components.v1 as components
from core import generate_diagram
from messages import create_message_from_bytes
import streamlit.components.v1 as components 
from animation import _create_animation_section
from render import _render_mermaid


def _sanitize_mermaid(code: str) -> str:
    """
    Remove Markdown code fences if present and return the raw Mermaid definition.
    """
    if not code:
        return ""
    text = code.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop the opening fence (e.g., ``` or ```mermaid)
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        # Drop the closing fence if present
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text

def _mermaid_live_url(code: str) -> str:
    if not code:
        return ""
    code = _sanitize_mermaid(code)
    code_json = json.dumps({"code": code})
    compressed = zlib.compress(code_json.encode("utf-8"), level=9)
    encoded = base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")
    return f"https://mermaid.live/edit#pako:{encoded}"

def _copy_button(text: str, *, label: str, key: Optional[str] = None) -> None:
    if not text:
        return

    button_id = key or f"copy-btn-{uuid.uuid4().hex}"
    escaped_label = _html.escape(label)
    json_text = json.dumps(text)
    component_html = f"""
<div style=\"display:flex;gap:0.5rem;align-items:center;\">
  <button id=\"{button_id}\" style=\"padding:0.25rem 0.65rem;border:1px solid #6c757d;border-radius:4px;background:transparent;cursor:pointer;\">{escaped_label}</button>
  <span id=\"{button_id}-status\" style=\"font-size:0.85rem;color:#6c757d;\"></span>
</div>
<script>
(function() {{
  const btn = document.getElementById('{button_id}');
  const status = document.getElementById('{button_id}-status');
  if (!btn) {{ return; }}
  btn.addEventListener('click', async () => {{
    if (!navigator.clipboard || !navigator.clipboard.writeText) {{
      if (status) {{
        status.textContent = 'Clipboard unavailable';
        status.style.color = '#dc3545';
      }}
      return;
    }}
    try {{
      await navigator.clipboard.writeText({json_text});
      if (status) {{
        status.textContent = 'Copied!';
        status.style.color = '#198754';
        setTimeout(() => {{ status.textContent = ''; }}, 2000);
      }}
    }} catch (err) {{
      console.error(err);
      if (status) {{
        status.textContent = 'Copy failed';
        status.style.color = '#dc3545';
      }}
    }}
  }});
}})();
</script>
"""
    st.components.v1.html(component_html, height=60)


def _download_mermaid_svg(code: str):
    download_button_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
    </head>
    <body>
        <button id="download-svg-btn" style="padding: 10px 20px; font-size: 16px; cursor: pointer;">
            Download SVG
        </button>

        <script>
            // Must initialize mermaid to use the render function
            mermaid.initialize({{ startOnLoad: false }});

            document.getElementById('download-svg-btn').addEventListener('click', async function() {{
                // The mermaid code is passed from Python into this JS block
                const mermaidCode = `{code}`;

                try {{
                    const {{ svg }} = await mermaid.render('headless-diagram', mermaidCode);

                    // Create a Blob and trigger the download
                    const blob = new Blob([svg], {{ type: 'image/svg+xml;charset=utf-8' }});
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'diagram_{int(time.time())}.svg';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);

                }} catch (e) {{
                    console.error("Error rendering Mermaid diagram:", e);
                    alert("Could not render the Mermaid diagram. Check the console for errors and ensure the syntax is correct.");
                }}
            }});
        </script>
    </body>
    </html>
    """

    st.components.v1.html(download_button_html, height=500, scrolling=True)
    
    
def create_drawio_xml(mermaid_code):
    """
    Wraps the Mermaid code into a valid Draw.io XML format.
    This bypasses URL length limits and ensures a perfect import.
    """
    # Clean and escape the code for XML safety
    clean_code = mermaid_code.strip().replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    # Standard Draw.io XML structure for a Mermaid object
    xml_data = f"""<mxfile host="app.diagrams.net" modified="2026-01-25T00:00:00.000Z" agent="Gemini-App" version="21.0.0">
  <diagram id="dns_attack" name="Page-1">
    <mxGraphModel>
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
        <mxCell id="2" value="{clean_code}" style="text;html=1;align=center;verticalAlign=middle;resizable=0;points=[];autosize=1;strokeColor=none;fillColor=none;whitespace=wrap;editable=1;style=mermaid;" vertex="1" parent="1">
          <mxGeometry width="100" height="100" as="geometry" />
        </mxCell>
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>"""
    return xml_data


def _drawio_url(code: str) -> str:
    """
    FIXED: Removed JSON wrapping. Draw.io needs RAW Mermaid text.
    Uses English comments as requested.
    """
    if not code:
        return ""
    
    mermaid_text = code.strip()
    mermaid_text = _sanitize_mermaid(mermaid_text)
    payload = mermaid_text.encode("utf-8")
    compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
    compressed = compressor.compress(payload) + compressor.flush()
    
    encoded = base64.b64encode(compressed).decode("ascii")    
    return f"https://app.diagrams.net/?type=mermaid&data={urllib.parse.quote(encoded)}"


def diagram_viewer():
    viewer, animation, editor, entities_tab, pcap_analysis, export, files_tab= st.tabs(["Viewer", "Animation", "Editor", "Entities", "PCAP Analysis", "Export", "Files"])
    
    raw_content = st.session_state["current"].diagram_text
    

    if "|||" in raw_content:
        code, ent_json = raw_content.split("|||", 1)
        try:
            ent_list = json.loads(ent_json)
        except:
            ent_list = []
    else:
        code = raw_content
        ent_list = []

    with viewer:
        clean_code = _sanitize_mermaid(code)
        _render_mermaid(clean_code, current_step=0, total_steps=0, title="Full Diagram")

    with editor:
        if code:
            _copy_button(code, label="Copy to clipboard", key="clipboard-mermaid")

        st.text_area(
            "Mermaid definition (editable)",
            value=code,
            height=360,
            key="diagram_text",
        )

    with entities_tab:
        st.subheader("Network Entities & Roles")
        if ent_list:
            st.table(ent_list)
        else:
            st.info("No entities identified yet. Generate a new diagram to see extracted roles.")

    with export:
        mermaid_live, drawio, download = st.tabs(["mermaid.live", "draw.io", "download image"])
        has_code = bool(code)

        with mermaid_live:
            if not has_code:
                st.info("Generate a diagram to open it in mermaid.live.")
            else:
                mermaid_live_url = _mermaid_live_url(code)
                st.link_button("Open in mermaid.live", mermaid_live_url)

    with drawio:
        st.subheader("Quick Export to Draw.io")

        if not code or not code.strip():
            st.warning("No diagram content to export.")
        else:
            link = _drawio_url(code)

            col1, col2 = st.columns([1, 4])

            with col1:
                st.link_button(
                    "Open in Draw.io",
                    link,
                    use_container_width=True,
                )

            with col2:
                st.caption(
                    "Opens the diagram in diagrams.net using Mermaid import. "
                    "If the canvas is empty, try manual paste or a different export mode."
                )

            with st.expander("Advanced"):
                st.code(link, language="text")

        st.divider()

        st.markdown("""
            ### 📝 Manual Method (Recommended for Papers)
1. **Copy** the Mermaid code from the 'Code' tab.
2. Go to [app.diagrams.net](https://app.diagrams.net).
3. In the menu, go to: **Arrange** -> **Insert** -> **Advanced** -> **Mermaid...**
4. **Paste** the code and click **Insert**.

*See [full documentation](https://www.drawio.com/blog/mermaid-diagrams) for more details.*
            """)
            #st.markdown(f"[Click here to edit in Draw.io]({link})", unsafe_allow_html=True)
        with download:
            svg, png, jpg  = st.tabs(["SVG", "PNG", "JPG"])
            with svg:
                if not has_code:
                    st.info("Generate a diagram to download its image.")
                else:
                    _download_mermaid_svg(code)
            with png:
                st.info("PNG download not implemented yet.")
            with jpg:
                st.info("JPG download not implemented yet.")
    with animation:
        st.subheader("Sequence Diagram Animation")  
        clean_code = """sequenceDiagram
participant A as 😈 Attacker
participant B as 🛡️ Resolver
A->>B: 🔍 Visible Query
A-->>B: 🚩 Hidden Attack 
A->>B: 🕵️‍♂️ Stealthy Recon
B-->>A: 🧾 Response with TTL
A-->>B: 🧠 Analyze & Adapt
B-->>A: 🛑 Block or Allow
Note right of B: 🧠 Internal Logic
"""
        if has_code:
            _create_animation_section(clean_code)
        else:
            st.info("Generate a diagram first to see the animation.")
    # diagram_viewer.py

    with pcap_analysis:
            st.subheader("🔍 Pcap Packet Evidence")
            
            curr_session = st.session_state["current"]
            
            # 1. Safely retrieve the structured packets list and entities JSON
            packets = None
            entities_data = []
            diagram_code = ""
            
            # Extract packets from message history
            for msg in reversed(curr_session.messages):
                metadata = msg.get("metadata", {})
                if isinstance(metadata, dict) and "packets_list" in metadata:
                    packets = metadata["packets_list"]
                    break
                    
            # Split diagram and entities
            if "|||" in curr_session.diagram_text:
                diagram_code, ent_json = curr_session.diagram_text.split("|||", 1)
                try:
                    entities_data = json.loads(ent_json)
                except Exception:
                    entities_data = []
            else:
                diagram_code = curr_session.diagram_text

            if packets is None:
                st.warning("⚠️ No structured PCAP data found. Ensure you uploaded a PCAP file.")
            else:
                selected_id = st.session_state.get("selected_packet_id")
                evidence_found = False

                # 2. Strategy A: Use AI-provided ENTITIES mapping
                if entities_data and any("EVIDENCE" in e for e in entities_data):
                    st.info("Evidence organized by AI Step-Mapping")
                    evidence_found = True
                    for item in entities_data:
                        step_num = item.get("STEP", "?")
                        entity_name = item.get("ENTITY", "Action")
                        evidence_str = str(item.get("EVIDENCE", ""))
                        
                        p_id_match = re.search(r"(\d+)", evidence_str)
                        if p_id_match:
                            p_id = int(p_id_match.group(1))
                            p_data = next((p for p in packets if p["id"] == p_id), None)
                            if p_data:
                                is_selected = (str(p_id) == str(selected_id))
                                with st.expander(f"Step {step_num}: {entity_name} (Packet #{p_id})", expanded=is_selected):
                                    if item.get("INSIGHT"):
                                        st.markdown(f"**AI Insight:** {item['INSIGHT']}")
                                    st.code(p_data["details"] or p_data["summary"], language="text")

                # Strategy B: Manual extraction from diagram text
                lines = diagram_code.split('\n')
                for line in lines:
                    p_match = re.search(r"Packet #(\d+)", line)
                    if p_match:
                        evidence_found = True
                        p_id = p_match.group(1)
                        p_data = next((p for p in packets if str(p["id"]) == p_id), None)
                        
                        if p_data:
                            is_selected = (str(p_id) == str(selected_id))
                            
                            #  1. Remove Mermaid arrows and Source tags
                            clean_title = re.sub(r'\(Source:.*?\)', '', line)
                            clean_title = clean_title.replace("->>", " to ").replace("->", " to ")
                            
                            #  2. Remove any <br/> or other HTML tags from the title
                            clean_title = re.sub(r'<[^>]*>', ' ', clean_title).strip()
                            
                            #  3. Highlight the Packet ID in the label
                            # We add a 📦 icon and bold the ID for better visibility
                            display_label = f"📦 **Packet #{p_id}** | {clean_title}"
                            
                            if is_selected:
                                display_label = f"🎯 {display_label} (SELECTED)"
                            
                            with st.expander(display_label, expanded=is_selected):
                                st.code(p_data["details"] or p_data["summary"], language="text")

                # 4. Strategy C: Final Fallback - Show all packets if no evidence links found
                if not evidence_found:
                    st.write("Full packet list (No specific evidence links found):")
                    for p in packets:
                        p_id = str(p["id"])
                        is_selected = (p_id == str(selected_id))
                        with st.expander(f"Packet #{p_id}: {p['summary']}", expanded=is_selected):
                            st.code(p["details"], language="text")
    with files_tab:
        st.subheader("📂 Session Attachments")
        chat_history = st.session_state["current"].messages
        found_files = False
        
        for i, msg in enumerate(chat_history):
            metadata = msg.get("metadata", {})
            if metadata.get("type") == "chat_attachment":
                found_files = True
                file_name = metadata.get('name', 'Unknown')
                # Extract content from metadata (using .get to avoid KeyError)
                file_content = metadata.get('content', 'No content available.')
                
                with st.container(border=True):
                    c1, c2, c3 = st.columns([0.1, 0.7, 0.2])
                    c1.markdown("📄")
                    c2.markdown(f"**{file_name}**")
                    
                    # Unique key using filename and message index
                    if c3.button("View", key=f"view_{file_name}_{i}"):
                        st.session_state[f"show_content_{i}"] = not st.session_state.get(f"show_content_{i}", False)

                    # Show content if toggled
                    if st.session_state.get(f"show_content_{i}", False):
                        st.divider()
                        if file_name.endswith(('.py', '.txt', '.json', '.log')):
                            st.code(file_content, language='python' if file_name.endswith('.py') else 'text')
                        else:
                            st.text_area("File Content", file_content, height=300)
        
        if not found_files:
            st.info("No files have been uploaded in this session yet.")