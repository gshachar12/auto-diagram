import base64
import html as _html
import json
import os
import uuid
import zlib
import streamlit as st
import time
from user_auth import authenticate
import state
import datetime
import re
from typing import Dict, List, Optional
from core import generate_diagram
from messages import create_message_from_bytes
from user_auth import authenticate
from diagram_viewer import diagram_viewer
from pcap import parse_with_indices, parse, prompt, extract_relevant_packets   


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
    st.subheader("Diagram Content")
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
                unsupported.append(name) # track unsupported files to inform the user
            else:  
                turn_messages.append(msg) # only add supported files to the messages for generation

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
            print(f"Using model: {model} with API key: {'set' if api_key else 'not set'}")

            # Create placeholders for dynamic UI updates
            progress_placeholder = st.empty()
            status_placeholder = st.empty()

            with progress_placeholder:
                # Initialize the progress bar at 0%
                progress_bar = st.progress(0)

            try:
                # Step 1: Preparation
                status_placeholder.markdown("🔍 **Step 1/3:** Preparing context and files...")
                progress_bar.progress(15)
                
                # Step 2: Generation with Spinner
                #  Wrap the core API call in a spinner for visual feedback
                model_string = "Gemini" if model.startswith("gemini") else "ChatGPT"
                with st.spinner(f" {model_string} is analyzing data..."):
                    status_placeholder.markdown(f"🧠 **Step 2/3:** {model_string} is generating the diagram...")
                    progress_bar.progress(40)
                    
                    response = generate_diagram(
                        messages=messages, api_key=api_key, model=model
                    )
                    
                                        
                    print(f"Length of response: {len(response) if response else 0}")  # Check if response is empty or None
                
                # Step 3: Finalizing
                progress_bar.progress(90)
                status_placeholder.markdown("📝 **Step 3/3:** Finalizing response...")

            except Exception as e:
                #  Clean up UI on error
                progress_placeholder.empty()
                status_placeholder.empty()
                st.error(f"Generation failed: {e}")
                time.sleep(5)
            else:
                # Success cleanup
                progress_bar.progress(100)
                time.sleep(0.4)
                progress_placeholder.empty()
                status_placeholder.empty()

                if len(turn_messages) > 0:
                    curr_session.messages.extend(turn_messages)

                # Save to history
                curr_session.messages.append(
                    {
                        "msg": {"role": "assistant", "content": response},
                        "metadata": {"type": "response", "model": model},
                    }
                )

            diag_match = re.search(r"<DIAGRAM>(.*?)</DIAGRAM>", response, re.DOTALL)
            ent_match = re.search(r"<ENTITIES>(.*?)</ENTITIES>", response, re.DOTALL)

            if diag_match:
                diagram_code = diag_match.group(1).strip()
                
                # If the LLM wrapped it in markdown code blocks inside the tags, clean it
                if "```" in diagram_code:
                    diagram_code = re.sub(r"```[a-z0-9]*\n", "", diagram_code)
                    diagram_code = diagram_code.replace("```", "").strip()
                    
            elif st.session_state["diagram_format"] == "Mermaid" and "sequenceDiagram" in response:
                diagram_code = response.strip()
            elif st.session_state["diagram_format"] == "D2" and ("shape:" in response or "direction:" in response):
                diagram_code = response.strip()
                # Clean up markdown if present
                match = re.search(r"```d2(.*?)```", diagram_code, re.DOTALL | re.IGNORECASE)
                if match:
                    diagram_code = match.group(1).strip()
            else:
                # Generic error based on format
                if st.session_state.get("diagram_format") == "D2":
                    diagram_code = 'shape: sequence_diagram\nERROR: "Failed to generate valid D2 code."'
                else:
                    diagram_code = "sequenceDiagram\n Note over AI: Error: Failed to generate valid Mermaid code."
                            
                entities_json = ent_match.group(1).strip() if ent_match else "[]"
                
                # Store with the separator for the renderer
                combined_content = f"{diagram_code}|||{entities_json}"

                curr_session.diagram_text = combined_content
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
    
    print("--------------------------------------------------------------------------")
    init() # cite: app.py
    
    #logged_in = authenticate() 
    
    # with st.sidebar:
    #     if logged_in:
    #         # This is your original sessions history
    #         sidebar() 
    #     else:
    #         # This shows ONLY if not logged in
    #         st.info("Log in to see history")

    with st.sidebar:
        sidebar()
    app() # cite: app.py
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
        if gemini_api_key:
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
            [ "gemini-2.5-flash", "gemini-2.5-pro", "gpt-5"],
            captions=[
                "Gemini 2.5 Flash requires Gemini API Key (Free tier)",
                "Gemini 2.5 Pro requires Gemini API Key",
                "Open AI GPT-5 requires Open AI API Key",

            ],
        )

        st.session_state["model"] = model
        if model == "gpt-5":
            st.session_state["api_key"] = open_ai_api_key
        else:
            st.session_state["api_key"] = gemini_api_key

        # In sidebar() function, after the model selection:
        st.divider()
        diagram_format = st.radio(
            "Diagram Engine",
            ["D2", "Mermaid"],
            index=0,
            help="D2 supports advanced styling and icons; Mermaid is faster for simple flows."
        )
        st.session_state["diagram_format"] = diagram_format
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

    # Default to D2
    if "diagram_format" not in st.session_state:
        st.session_state["diagram_format"] = "D2"

    if "pcap_parse_mode" not in st.session_state:
        st.session_state["pcap_parse_mode"] = "full"

if __name__ == "__main__":
    main()
