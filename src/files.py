import streamlit as st
import re

""" 
    This module provides functionality to display session attachments in a Streamlit application.
    It iterates through the chat history, identifies messages with attachments, and displays them
    in a user-friendly format. Users can view the content of the attachments by clicking a button.
"""
def display_session_attachments():
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
        return 