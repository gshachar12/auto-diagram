import base64
import html as _html
import json
import os
import uuid
import zlib

import streamlit as st

from typing import Dict, List, Optional
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


def diagram_viewer():
    viewer, editor, export = st.tabs(["Viewer", "Editor", "Export"])
    code = st.session_state.get("diagram_text", "").strip()
    with viewer:
        code = _sanitize_mermaid(code)
        _render_mermaid(code, height=520)
    with editor:
        if code:
            _copy_button(code, label="Copy to clipboard", key="clipboard-mermaid")

        st.text_area(
            "Mermaid definition (editable)",
            value=code,
            height=360,
            key="diagram_text",
        )
    with export:
        mermaid_live, drawio = st.tabs(["mermaid.live", "draw.io"])
        has_code = bool(code)

        with mermaid_live:
            if not has_code:
                st.info("Generate a diagram to open it in mermaid.live.")
            else:
                mermaid_live_url = _mermaid_live_url(code)
                st.link_button("Open in mermaid.live", mermaid_live_url)

        with drawio:
            st.markdown(
                """
See [documentation](https://www.drawio.com/blog/mermaid-diagrams)
### tl;dr
1. Go to: [app.diagrams.net](https://app.diagrams.net)
2. Arrange -> Insert -> Mermaid… (Copy mermaid text)
"""
            )


def show_history():
    st.write("Messages history")
    st.write("")
    user_messages = []
    for chat_msg in st.session_state["chat_history"]:
        metadata = chat_msg.get("metadata")
        if metadata["type"] == "chat_attachment":
            user_messages.append(f"Attachment: {metadata['name']}")
        elif metadata["type"] == "chat_text":
            msg = chat_msg.get("msg", None)
            content = msg.get("content", "")
            with st.chat_message("user"):
                st.text(content[:300] + "...")
                if len(user_messages) > 0:
                    with st.expander("Messages", expanded=False):
                        st.text("\n".join(user_messages))
                        st.text("---")
                        st.text(content)
                    user_messages = []
        else:
            if len(user_messages) > 0:
                with st.chat_message("..."):
                    with st.expander("user", expanded=False):
                        st.text("\n".join(user_messages))
                    user_messages = []
            with st.chat_message("ai"):
                msg = chat_msg.get("msg", None)
                content = msg.get("content", "")
                with st.expander("AI", expanded=False):
                    st.code(content, language="text")

    if len(user_messages) > 0:
        with st.chat_message("user"):
            with st.expander("...", expanded=False):
                st.text("\n".join(user_messages))
            user_messages = []


def create_turn_messages(turn_text, turn_attachments):
    turn_messages: List[Dict] = []
    unsupported: list[str] = []
    if turn_attachments:
        for up in turn_attachments:
            try:
                data = up.read()
            finally:
                try:
                    up.seek(0)
                except Exception:
                    pass
            name = getattr(up, "name", None) or "attachment"
            msg = create_message_from_bytes(
                name, data, st.session_state["pcap_parse_mode"]
            )

            if msg is None:
                unsupported.append(name)
            else:
                turn_messages.append(
                    {"msg": msg, "metadata": {"type": "chat_attachment", "name": name}}
                )

    if turn_text.strip():
        turn_messages.append(
            {
                "msg": {"role": "user", "content": turn_text},
                "metadata": {"type": "chat_text"},
            }
        )

    return turn_messages, unsupported


def to_openai_messages(msgs):
    result = []
    for chat_msg in msgs:
        msg = chat_msg.get("msg", None)
        if msg is None:
            print(f"illegal chat message:\n{chat_msg}")
        result.append(msg)
    return result


def main():
    st.set_page_config(page_title="Auto Diagram", page_icon="🗺️", layout="wide")

    # Session state
    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []  # list[Dict(role, content)]
    if "diagram_text" not in st.session_state:
        st.session_state["diagram_text"] = ""
    if "pcap_parse_mode" not in st.session_state:
        st.session_state["pcap_parse_mode"] = "full"

    with st.sidebar:
        st.title("Auto Diagram")
        st.subheader("Settings")
        api_key = st.text_input(
            "OpenAI API Key",
            type="password",
            help="If not set via environment, provide your key here.",
            value=os.environ.get("OPENAI_API_KEY", ""),
        )
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key

        pcap_mode_box_label = "Do full pcap analysis, if unchecked only send packet summaries to reduce request tokens"
        pcap_mode_box = st.checkbox(pcap_mode_box_label, value=True)
        if pcap_mode_box:
            st.session_state["pcap_parse_mode"] = "full"
        else:
            st.session_state["pcap_parse_mode"] = "summary"

        st.markdown("---")
        if st.button("Clear Conversation", help="Reset chat and diagram"):
            st.session_state["chat_history"] = []
            st.session_state["diagram_text"] = ""
            st.toast("Conversation cleared")

    with st.container(vertical_alignment="top"):
        st.caption(
            "Chat to generate and refine Mermaid diagrams with optional supporting files."
        )
        chat_value = st.chat_input(
            "Type a prompt or refinement and press Enter…",
            accept_file="multiple",
        )

        submitted = False
        turn_text = ""
        turn_attachments = []

        if chat_value is not None:
            # Extract text and files
            turn_text = chat_value.get("text", "")
            turn_attachments = chat_value.get("files", [])
            submitted = True

        if submitted:
            if not turn_text.strip() and not turn_attachments:
                st.warning("Enter a message or attach files.")
            elif not os.environ.get("OPENAI_API_KEY"):
                st.error("OPENAI_API_KEY not set. Provide it in the sidebar.")
            else:
                # If the diagram was edited, keep the last assistant message in sync
                if (
                    st.session_state["chat_history"]
                    and st.session_state["chat_history"][-1]["msg"]["role"] == "assistant"
                ):
                    st.session_state["chat_history"][-1]["msg"]["content"] = st.session_state[
                        "diagram_text"
                    ]

                turn_messages, unsupported = create_turn_messages(
                    turn_text, turn_attachments
                )
                # Build full message list: persistent + prior conversation + this turn's files + user text
                messages: List[Dict] = []
                messages.extend(
                    to_openai_messages(st.session_state["chat_history"])
                )  # persistent context
                messages.extend(to_openai_messages(turn_messages))

                with st.spinner("Generating diagram…"):
                    try:
                        diagram = generate_diagram(messages=messages)
                    except Exception as e:
                        st.error(f"Generation failed: {e}")
                    else:
                        if len(turn_messages) > 0:
                            st.session_state["chat_history"].extend(turn_messages)

                        # Reflect skipped files info to the UI
                        if unsupported:
                            st.info(
                                "Unsupported files were skipped: "
                                + ", ".join(unsupported)
                            )
                        st.session_state["chat_history"].append(
                            {
                                "msg": {"role": "assistant", "content": diagram},
                                "metadata": {"type": "response"},
                            }
                        )
                        st.session_state["diagram_text"] = diagram

                st.rerun()

    with st.container():
        chat_col, diagram_col = st.columns([0.3, 0.7], gap="medium", border=True)

        with chat_col:
            show_history()

        with diagram_col:
            diagram_viewer()


if __name__ == "__main__":
    main()
