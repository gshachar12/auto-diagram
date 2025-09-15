import os
import html as _html
from typing import List, Dict

import streamlit as st
from core import generate_diagram
from messages import create_message_from_bytes


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


def _render_mermaid(code: str, *, height: int = 500):
    """
    Render Mermaid code using an embedded HTML component.
    """
    if not code:
        st.info("No diagram to render yet. Generate or enter Mermaid text.")
        return

    escaped = _html.escape(code)
    html_doc = f"""
<!DOCTYPE html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <style>
      html, body {{ margin: 0; padding: 0; }}
      .mermaid {{ margin: 0; }}
    </style>
  </head>
  <body>
    <div class=\"mermaid\">{escaped}</div>
    <script src=\"https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js\"></script>
    <script>
      try {{
        // Try to follow Streamlit theme when possible
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        mermaid.initialize({{ startOnLoad: true, theme: prefersDark ? 'dark' : 'default' }});
      }} catch (e) {{ console.error(e); }}
    </script>
  </body>
</html>
"""
    st.components.v1.html(html_doc, height=height, scrolling=True)


def main():
    st.set_page_config(
        page_title="Auto Diagram (Streamlit)", page_icon="🗺️", layout="wide"
    )
    st.title("Auto Diagram")
    st.caption("Generate Mermaid diagrams from prompts and supporting files")

    with st.sidebar:
        st.subheader("Settings")
        api_key = st.text_input(
            "OpenAI API Key",
            type="password",
            help="If not set via environment, provide your key here.",
            value=os.environ.get("OPENAI_API_KEY", ""),
        )
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key

    prompt = st.text_area(
        "Prompt",
        placeholder="Describe the network flow or system to diagram...",
        height=160,
        key="prompt",
    )

    uploads = st.file_uploader(
        "Upload supporting files (text, code, images)",
        type=None,
        accept_multiple_files=True,
        help="Optional. Each file is provided to the model as a separate message.",
    )

    col1, col2 = st.columns([1, 2])
    with col1:
        generate = st.button("Generate Diagram", type="primary")
    with col2:
        clear = st.button("Clear Output")

    if clear:
        st.session_state["diagram_text"] = ""

    if generate:
        if not prompt.strip():
            st.warning("Please enter a prompt.")
        elif not os.environ.get("OPENAI_API_KEY"):
            st.error("OPENAI_API_KEY not set. Provide it in the sidebar.")
        else:
            # Build messages from uploads (if any)
            messages: List[Dict] = []
            unsupported: list[str] = []
            if uploads:
                for up in uploads:
                    try:
                        data = up.read()
                    finally:
                        up.seek(0)
                    msg = create_message_from_bytes(up.name, data)
                    if msg is None:
                        unsupported.append(up.name)
                    else:
                        messages.append(msg)

            # Append the main prompt last
            messages.append({"role": "user", "content": prompt})

            with st.spinner("Generating diagram..."):
                try:
                    diagram = generate_diagram(messages=messages)
                except Exception as e:
                    st.error(f"Generation failed: {e}")
                    return

            if unsupported:
                st.info("Unsupported files were skipped: " + ", ".join(unsupported))

            st.session_state["diagram_text"] = diagram

    tab_preview, tab_text = st.tabs(["Preview", "Mermaid Text"])

    with tab_text:
        st.text_area(
            "Diagram (editable)",
            value=st.session_state.get("diagram_text", ""),
            height=320,
            key="diagram_text",
        )

    with tab_preview:
        code = st.session_state.get("diagram_text", "").strip()
        code = _sanitize_mermaid(code)
        _render_mermaid(code, height=600)


if __name__ == "__main__":
    main()
