import streamlit as st
import subprocess
import os
import re
import textwrap

def _render_d2(d2_code: str, current_step: int = 0, total_steps: int = 0, title: str = "Network Protocol Diagram", container=None):
    if not d2_code:
        st.warning("No code provided for rendering.")
        return

    # --- Tooltip Injection ---
    packets_data = {}
    if "current" in st.session_state:
        for msg in reversed(st.session_state["current"].messages):
            metadata = msg.get("metadata", {})
            if isinstance(metadata, dict) and "packets_data" in metadata:
                packets_data = {str(p["id"]): p["summary"] for p in metadata["packets_data"]}
                break

    for p_id, summary in packets_data.items():
        clean_summary = summary.replace('"', '\\"')
        d2_code = re.sub(
            rf"({p_id}\s*:\s*[^\{{]*\{{)", 
            rf'\1\n  tooltip: "{clean_summary}"', 
            d2_code
        )

    # --- Rendering Process ---
    svg_content = None
    d2_file = "temp_render.d2"
    svg_file = "temp_render.svg"
    executable = os.path.abspath("d2.exe")

    if not os.path.exists(executable):
        st.error(f"❌ D2 Executable not found at: {executable}")
        return

    try:
        final_code = textwrap.dedent(d2_code)
        with open(d2_file, "w", encoding="utf-8") as f:
            f.write(final_code)
        
        subprocess.run(
            [executable, "--layout=dagre", d2_file, svg_file],
            capture_output=True, text=True, encoding="utf-8", check=True
        )
        
        if os.path.exists(svg_file):
            with open(svg_file, "r", encoding="utf-8") as f:
                svg_content = f.read()

    except subprocess.CalledProcessError as e:
        st.error("❌ D2 Syntax Error")
        st.code(e.stderr, language="bash")
        return
    except Exception as e:
        st.error(f"Unexpected Error: {e}")
        return

    # --- UI Display with Zoom Logic ---
    if svg_content:
        def _display_output():
            st.markdown(f"### {title}")
            if total_steps > 0:
                st.caption(f"Step {current_step} of {total_steps}")
            
            try:
                with open("render_d2.html", "r", encoding="utf-8") as f:
                    html_template = f.read()
                
                full_html = html_template.replace("{{svg_content}}", svg_content)
                
                st.components.v1.html(full_html, height=800, scrolling=False)
            except FileNotFoundError:
                st.error("render_d2.html file not found!")

        if container is not None:
            with container: _display_output()
        else:
            _display_output()

    # --- 4. Cleanup ---
    for f in [d2_file, svg_file]:
        if os.path.exists(f):
            try: os.remove(f)
            except: pass