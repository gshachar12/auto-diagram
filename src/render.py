import streamlit as st
import subprocess
import os
import re
import textwrap
import xml.etree.ElementTree as ET


def render_svg(svg_code: str, current_step: int = 0, total_steps: int = 0, title: str = "Network Protocol Diagram", container=None):
    if not svg_code:
        st.warning("No SVG code provided for rendering.")
        return

    # --- 1. Extract Packet Data from Session State ---
    packets_data = {}
    if "current" in st.session_state:
        for msg in reversed(st.session_state["current"].messages):
            metadata = msg.get("metadata", {})
            if isinstance(metadata, dict) and "packets_data" in metadata:
                # Key explicitly by string ID for safe matching
                packets_data = {str(p["id"]): p["summary"] for p in metadata["packets_data"]}
                break

    # --- 2. Safe SVG Clean & Parse ---
    try:
        # Strip potential markdown code blocks
        clean_svg = re.sub(r"^```xml\s*|^```html\s*|^```svg\s*|```$", "", svg_code.strip(), flags=re.IGNORECASE)
        
        # Pre-emptively escape bare ampersands that aren't valid XML entities
        clean_svg = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;)', '&amp;', clean_svg)

        # Register namespaces properly to suppress unwanted 'ns0:' prefixing
        ET.register_namespace('', "http://www.w3.org/2000/svg")
        ET.register_namespace('xlink', "http://www.w3.org/1999/xlink")
        
        root = ET.fromstring(clean_svg)

        # --- 3. Dynamic Tooltip Evaluation ---
        for a_element in root.findall(".//{http://www.w3.org/2000/svg}a"):
            href = a_element.get("href", "")
            
            # Extract step context from the link target
            step_match = re.search(r"focus_step=['\"]?(\d+)['\"]?", href)
            if not step_match:
                continue
                
            step_id = step_match.group(1)
            target_summary = None

            # Strategy A: Check if an inner <title> tag contains a hardcoded "Pkt #XYZ" reference
            title_element = a_element.find("{http://www.w3.org/2000/svg}title")
            if title_element is not None and title_element.text:
                pkt_match = re.search(r"Pkt\s*#\s*(\d+)", title_element.text, re.IGNORECASE)
                if pkt_match and pkt_match.group(1) in packets_data:
                    target_summary = packets_data[pkt_match.group(1)]

            # Strategy B: Fall back to cross-referencing your session state dictionary directly 
            if not target_summary and step_id in packets_data:
                target_summary = packets_data[step_id]

            # Inject the full live text if a telemetry match was established
            if target_summary:
                if title_element is None:
                    title_element = ET.Element("{http://www.w3.org/2000/svg}title")
                    a_element.insert(0, title_element)
                
                # ElementTree safely processes escaping under the hood
                title_element.text = target_summary

        svg_content = ET.tostring(root, encoding="utf-8").decode("utf-8")

    except ET.ParseError as e:
        st.error("❌ Invalid SVG Syntax Detected")
        st.caption("The XML parser failed to process the diagram asset due to a structure exception.")
        st.code(str(e), language="text")
        return
    except Exception as e:
        st.error(f"Unexpected Error during rendering: {e}")
        return

    # --- 4. UI Display Wrapper ---
    def _display_output():
        st.markdown(f"### {title}")
        if total_steps > 0:
            st.caption(f"Step {current_step} of {total_steps}")
        
        try:
            with open("src/render_svg.html", "r", encoding="utf-8") as f:
                html_template = f.read()
            
            full_html = html_template.replace("{{svg_content}}", svg_content)
            st.components.v1.html(full_html, height=800, scrolling=False)
            
        except FileNotFoundError:
            st.error("The template dependencies at 'src/render_svg.html' are missing.")

    if container is not None:
        with container:
            _display_output()
    else:
        _display_output()

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
    executable = os.path.abspath("src/d2.exe")

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
                with open("src/render_d2.html", "r", encoding="utf-8") as f:
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