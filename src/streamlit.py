import os
from typing import List, Dict

import streamlit as st
from core import generate_diagram
from messages import create_message_from_bytes


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

    st.text_area(
        "Diagram (editable)",
        value=st.session_state.get("diagram_text", ""),
        height=300,
        key="diagram_text",
    )


if __name__ == "__main__":
    main()
