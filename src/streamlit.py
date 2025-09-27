import base64
import html as _html
import json
import os
import uuid
import zlib
import streamlit as st
import time
import state
import datetime

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
    <script src=\"https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js\"></script>
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


def diagram_viewer():
    viewer, editor, export = st.tabs(["Viewer", "Editor", "Export"])
    code = st.session_state["current"].diagram_text
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
        mermaid_live, drawio, svg = st.tabs(["mermaid.live", "draw.io", "svg"])
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
        with svg:
            _download_mermaid_svg(code)


@st.dialog("User messages", width="large")
def show_messages(data_fnc):
    user_messages, content = data_fnc()
    if len(user_messages) > 0:
        st.code("\n".join(user_messages))
        st.code("---")
    st.code(content)


@st.dialog("AI diagram", width="large")
def show_ai_diagram(data_fnc):
    diagram_text = data_fnc()
    st.code(diagram_text)


def show_history():
    st.subheader("History")
    chat_history = st.session_state["current"].messages
    user_messages = []
    diagrams_counter = 1
    for msg_id, chat_msg in enumerate(chat_history):
        metadata = chat_msg.get("metadata")
        if metadata["type"] == "chat_attachment":
            user_messages.append(f"Attachment: {metadata['name']}")
        elif metadata["type"] == "chat_text":
            msg = chat_msg.get("msg", None)
            content = msg.get("content", "")
            with st.chat_message("user"):
                curr_messages = user_messages
                if st.button(
                    content[:25] + "...",
                    key=f"view_messages_{msg_id}",
                    icon=":material/expand_content:",
                    type="tertiary",
                ):
                    show_messages(lambda: (curr_messages, content))
                user_messages = []
        else:
            if len(user_messages) > 0:
                print("Got user messages instead out of order")
            with st.chat_message("ai", avatar=":material/flowchart:"):
                msg = chat_msg.get("msg", None)
                content = msg.get("content", "")
                model = metadata.get("model", "gpt-5")
                if st.button(
                    f"**{model}** generated [{diagrams_counter}]",
                    key=f"ai_diagram_{msg_id}",
                    icon=":material/expand_content:",
                    type="tertiary",
                ):
                    show_ai_diagram(lambda: content)
            diagrams_counter += 1

    if len(user_messages) > 0:
        print("got dangling user messages")


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


def update_state():
    curr = st.session_state["current"]
    sessions = st.session_state["sessions"]
    if curr.id not in sessions and len(curr.messages) > 0:
        sessions[curr.id] = curr
    state.write(sessions)


def model_config():
    return st.session_state["api_key"], st.session_state["model"]


def chatbox():
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
        curr_session = st.session_state["current"]
        if not turn_text.strip() and not turn_attachments:
            st.warning("Enter a message or attach files.")
        else:
            # If the diagram was edited, keep the last assistant message in sync
            if (
                len(curr_session.messages) > 0
                and curr_session.messages[-1]["msg"]["role"] == "assistant"
            ):
                curr_session.messages[-1]["msg"]["content"] = st.session_state[
                    "diagram_text"
                ]

            turn_messages, unsupported = create_turn_messages(
                turn_text, turn_attachments
            )
            # Build full message list: persistent + prior conversation + this turn's files + user text
            messages: List[Dict] = []
            messages.extend(
                to_openai_messages(curr_session.messages)
            )  # persistent context
            messages.extend(to_openai_messages(turn_messages))

            api_key, model = model_config()
            with st.spinner("Generating diagram…"):
                try:
                    diagram = generate_diagram(
                        messages=messages, api_key=api_key, model=model
                    )
                except Exception as e:
                    st.error(f"Generation failed: {e}")
                    time.sleep(15)
                else:
                    if len(turn_messages) > 0:
                        curr_session.messages.extend(turn_messages)

                    # Reflect skipped files info to the UI
                    if unsupported:
                        st.info(
                            "Unsupported files were skipped: " + ", ".join(unsupported)
                        )
                    curr_session.messages.append(
                        {
                            "msg": {"role": "assistant", "content": diagram},
                            "metadata": {"type": "response", "model": model},
                        }
                    )
                    curr_session.diagram_text = diagram
                    curr_session.updated = datetime.datetime.now().timestamp()

            update_state()
            st.rerun()


def app():
    with st.container(vertical_alignment="top"):
        chatbox()

    with st.container():
        chat_col, diagram_col = st.columns([0.32, 0.68], gap="small")

        with chat_col.container(height=600):
            show_history()

        with diagram_col.container(height=600):
            diagram_viewer()


def main():
    init()

    with st.sidebar:
        sidebar()

    app()


def sidebar():
    st.title("Auto Diagram")
    with st.popover("", icon=":material/settings:"):
        open_ai_api_key = st.text_input(
            "OpenAI API Key",
            type="password",
            help="If not set via environment, provide your key here.",
            value=os.environ.get("OPENAI_API_KEY", ""),
        )
        if open_ai_api_key:
            os.environ["OPENAI_API_KEY"] = open_ai_api_key

        gemini_api_key = st.text_input(
            "Gemini API Key",
            type="password",
            help="If not set via environment, provide your key here.",
            value=os.environ.get("GEMINI_API_KEY", ""),
        )
        if open_ai_api_key:
            os.environ["GEMINI_API_KEY"] = gemini_api_key

        pcap_mode_box_label = "Provide full .pcap trace if unchecked only send packet summaries to reduce request tokens"
        pcap_mode_box = st.checkbox(
            "Full pcap trace", help=pcap_mode_box_label, value=True
        )
        if pcap_mode_box:
            st.session_state["pcap_parse_mode"] = "full"
        else:
            st.session_state["pcap_parse_mode"] = "summary"

        model = st.radio(
            "Choose model",
            ["gpt-5", "gemini-2.5-flash", "gemini-2.5-pro"],
            captions=[
                "Open AI GPT-5 requires Open AI API Key",
                "Gemini 2.5 Flash requires Gemini API Key (Free tier)",
                "Gemini 2.5 Pro requires Gemini API Key",
            ],
        )

        st.session_state["model"] = model
        if model == "OpenAI GPT-5":
            st.session_state["api_key"] = open_ai_api_key
        else:
            st.session_state["api_key"] = gemini_api_key

    st.header("Sessions")
    if st.button("New", icon=":material/open_in_new:", type="primary"):
        curr = state.ChatSession()
        st.session_state["current"] = curr

    label_col, edit_col = st.columns([3, 1])
    for session in state.sorted_state(st.session_state["sessions"]):
        label = session.title
        if len(label) > 20:
            label = label[:17] + "..."
        icon = None
        if session.id == st.session_state["current"].id:
            label = f"__{label}__"
            icon = ":material/arrow_right:"

        if label_col.button(
            label, key=f"session_{session.id}", type="tertiary", icon=icon
        ):
            st.session_state["current"] = session
            st.rerun()

        icon = ":material/more_horiz:"
        col_pp = edit_col.popover("", icon=icon)
        name = col_pp.text_input(
            "Rename",
            key=f"session_rename_{session.id}",
            value=session.title,
        )
        if name != session.title:
            st.session_state["sessions"][session.id].title = name
            update_state()
            st.rerun()

        icon = ":material/delete:"
        if col_pp.button(
            "", key=f"session_del_{session.id}", type="tertiary", icon=icon
        ):
            del st.session_state["sessions"][session.id]
            update_state()
            st.rerun()


def init():
    st.set_page_config(page_title="Auto Diagram", page_icon="🗺️", layout="wide")
    if "sessions" not in st.session_state:
        st.session_state["sessions"] = state.load()

    if "current" not in st.session_state:
        st.session_state["current"] = state.ChatSession()

    # Session state
    if "pcap_parse_mode" not in st.session_state:
        st.session_state["pcap_parse_mode"] = "full"


if __name__ == "__main__":
    main()
