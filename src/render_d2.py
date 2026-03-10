import streamlit as st
import subprocess
import os
import re
import textwrap

def _render_d2(d2_code: str, current_step: int = 0, total_steps: int = 0, title: str = "Network Protocol Diagram", container=None):
    """
    Renders D2 code into an SVG using the local d2.exe and displays it in Streamlit.
    Includes support for packet tooltips and UTF-8 encoding for emojis/special characters.
    """
    if not d2_code:
        st.warning("No code provided for rendering.")
        return

    # --- 1. Tooltip Injection (Hover Logic) ---
    packets_data = {}
    if "current" in st.session_state:
        # Retrieve packet summaries from the most recent session state
        for msg in reversed(st.session_state["current"].messages):
            metadata = msg.get("metadata", {})
            if isinstance(metadata, dict) and "packets_list" in metadata:
                packets_data = {str(p["id"]): p["summary"] for p in metadata["packets_list"]}
                break

    # Inject tooltips into the D2 DSL for relevant packet IDs
    for p_id, summary in packets_data.items():
        clean_summary = summary.replace('"', '\\"')
        d2_code = re.sub(
            rf"({p_id}\s*:\s*[^\{{]*\{{)", 
            rf'\1\n  tooltip: "{clean_summary}"', 
            d2_code
        )

    # --- 2. Rendering Process ---
    svg_content = None
    d2_file = "temp_render.d2"
    svg_file = "temp_render.svg"
    
    # Use the local EXE you copied to the project directory
    executable = os.path.abspath("d2.exe")

    if not os.path.exists(executable):
        st.error(f"❌ D2 Executable not found at: {executable}")
        st.info("Please ensure d2.exe is in the root directory of your project.")
        return

    try:
        # Remove leading whitespace to prevent D2 block errors
        final_code = textwrap.dedent(d2_code)

        # Write the file in UTF-8 to preserve emojis/special characters
        with open(d2_file, "w", encoding="utf-8") as f:
            f.write(final_code)
        
        # Execute the local D2 compiler with the Dagre layout engine
        result = subprocess.run(
            [executable, "--layout=dagre", d2_file, svg_file],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True
        )
        
        if os.path.exists(svg_file):
            with open(svg_file, "r", encoding="utf-8") as f:
                svg_content = f.read()

    except subprocess.CalledProcessError as e:
        st.error("❌ D2 Syntax Error")
        st.code(e.stderr, language="bash") # Displays the specific D2 compiler error
        with st.expander("Inspect Generated D2 Source"):
            st.code(d2_code, language="d2")
        return
    except Exception as e:
        st.error(f"Unexpected Rendering Error: {e}")
        return

    # --- 3. UI Display ---
    if svg_content:
        def _display_output():
            st.markdown(f"### {title}")
            if total_steps > 0:
                st.caption(f"Step {current_step} of {total_steps}")
            
            # Embed the SVG in a white-background HTML container for visibility and tooltips
            html_payload = f"""
            <div style="display: flex; justify-content: center; background-color: white; padding: 20px; border-radius: 10px; border: 1px solid #eee;">
                {svg_content}
            </div>
            """
            st.components.v1.html(html_payload, height=800, scrolling=True)

        # Safely handle Streamlit containers (avoids TypeErrors)
        if container is not None:
            with container:
                _display_output()
        else:
            _display_output()

    # --- 4. Cleanup ---
    for f in [d2_file, svg_file]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass