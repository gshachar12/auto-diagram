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
from render_mermaid import _render_mermaid
from render_d2 import _render_d2
from datetime import datetime
def _sanitize_diagram_text(code: str) -> str:
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
    code = _sanitize_diagram_text(code)
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
    mermaid_text = _sanitize_diagram_text(mermaid_text)
    payload = mermaid_text.encode("utf-8")
    compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
    compressed = compressor.compress(payload) + compressor.flush()
    encoded = base64.b64encode(compressed).decode("ascii")    
    return f"https://app.diagrams.net/?type=mermaid&data={urllib.parse.quote(encoded)}"


def diagram_viewer():
    
    focus_step = st.query_params.get("focus_step")
    all_labels = ["Viewer", "Animation", "Editor", "Entities", "PCAP Analysis", "Export", "Files"]

    # If there is a focus_step, move "PCAP Analysis" to the front of the list
    if focus_step:
        # Remove it from its original spot and insert at index 0
        all_labels.insert(0, all_labels.pop(all_labels.index("PCAP Analysis")))

    tabs = st.tabs(all_labels)

    # We use a dictionary to map the labels back to their variables safely
    tab_map = {label: tabs[i] for i, label in enumerate(all_labels)}

    viewer = tab_map["Viewer"]
    animation = tab_map["Animation"]
    editor = tab_map["Editor"]
    entities_tab = tab_map["Entities"]
    pcap_analysis = tab_map["PCAP Analysis"]
    export = tab_map["Export"]
    files_tab = tab_map["Files"]
    code = st.session_state["current"].diagram_text
    entities_json = st.session_state["current"].entities_json
    steps_json = st.session_state["current"].steps_json

        
    with viewer:
        #clean_code = _sanitize_diagram_text(code)
        _render_d2(code, current_step=0, total_steps=0, title="Full Diagram View")

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

    with pcap_analysis:

            try: 
                steps_list = json.loads(steps_json)
            except:
                print("Error parsing steps JSON")
                steps_list = []
            st.subheader("🔍 Pcap Packet Evidence")
                        
            packets = None
            diagram_text = ""
            
            # Extract packets from message history
            for msg in reversed(st.session_state["current"].messages):
                metadata = msg.get("metadata", {})
                # 1. Skip if metadata is just a string or not a dict
                if not isinstance(metadata, dict):
                    print("Skipping: Metadata is not a dictionary")
                    continue
                    
                # 2. ONLY stop the loop if 'packets_data' is actually present
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
                                # Show the Wireshark-style timestamp we created earlier
                                ts = packet_obj.get("timestamp", "0.000000")
                               
                                # Show the packet details
                                content = packet_obj.get("details") or packet_obj.get("summary") or "No details"
                                
                                with st.expander(f"**📦Packet Number:`#{p_id}` | ⏱ Timestamp: `{ts}s`**"):
                                    st.markdown(f"**Packet source: `{packet_obj.get('src', 'Unknown')}`**")
                                    st.markdown(f"**Packet destination: `{packet_obj.get('dst', 'Unknown')}`**")
                                    st.markdown(f"**Packet protocol: `{packet_obj.get('protocol', 'Unknown')}`**")
                                    st.markdown (f"**Packet length: `{packet_obj.get('length', 'Unknown')}` bytes**")
                                    st.markdown(f"**Packet info: `{packet_obj.get('info', 'No info available')}`**")
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