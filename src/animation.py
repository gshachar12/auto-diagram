import base64
import html as _html
import streamlit as st
import time
import re
from typing import Dict, List, Optional
from core import generate_diagram
from messages import create_message_from_bytes
import streamlit.components.v1 as components 
from render import _render_mermaid


def build_frame(header, steps, index):
    """
    Ensures Mermaid syntax is valid by closing all open blocks (rect, loop, etc.).
    This prevents the "Syntax Error" at step 1.
    """
    current_steps = steps[:index]
    block_starters = ["rect", "loop", "alt", "opt", "critical", "break"]
    
    open_count = 0
    for line in current_steps:
        clean_line = line.strip()
        tokens = clean_line.split()
        if tokens and tokens[0] in block_starters:
            open_count += 1
        if clean_line == "end":
            open_count -= 1
            
    needed_ends = max(0, open_count)
    return "\n".join(header) + "\n" + "\n".join(current_steps + (["end"] * needed_ends))


def _create_animation_section(full_code: str):
    # 1. Parse diagram components
    lines = [l.strip() for l in full_code.split('\n') if l.strip()]
    header_keywords = ["sequenceDiagram", "autonumber", "participant", "title"]
    
    header = [l for l in lines if any(l.startswith(k) for k in header_keywords) and ":" not in l]
    steps = [l for l in lines if l not in header]
    total_steps = len(steps)

    if "step_idx" not in st.session_state: st.session_state.step_idx = 1
    if "playing" not in st.session_state: st.session_state.playing = False
    
    # 2. Control Interface
    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        if st.button("Stop" if st.session_state.playing else "Start", use_container_width=True):
            st.session_state.playing = not st.session_state.playing
            
            if st.session_state.step_idx == total_steps:
                st.session_state.step_idx = 1
            if st.session_state.playing:
                st.info("Playing animation... Click 'Stop' to pause.")
            st.rerun()


    with c2:
        if st.button("Reset", use_container_width=True):
            st.session_state.step_idx = 1
            st.session_state.playing = False
            st.rerun()
    with c3:
        speed = st.slider("Animation Speed (steps/sec)", 0.0, 5.0, 1.0, step=0.5, help="Adjust the speed of the animation.")

    # 3. Step Slider
    st.session_state.step_idx = st.slider("Navigate", 1, total_steps, st.session_state.step_idx)

    # 4. Create the persistent UI slot
    chart_placeholder = st.empty()

    # 5. Build Sliced Code
    current_idx = st.session_state.step_idx
    sliced_code = build_frame(header, steps, current_idx)
    
    current_line = steps[current_idx - 1]
    title = current_line.split(':')[-1].strip() if ':' in current_line else "Action"

    # 6. Render into the placeholder using the fixed 'with' logic
    _render_mermaid(sliced_code, current_idx, total_steps, title=title, container=chart_placeholder)

    # 7. Animation timing
    if st.session_state.playing:
        if st.session_state.step_idx < total_steps:
            time.sleep(1/speed)
            st.session_state.step_idx += 1
            st.rerun()
        else:
            st.session_state.playing = False
            st.rerun()


def play_as_gif(frames_text: str):
    frames = re.findall(r'<FRAME>(.*?)</FRAME>', frames_text, re.DOTALL)
    placeholder = st.empty()
    
    while True:
        for frame in frames:
            with placeholder:
                _render_mermaid(frame)
            time.sleep(0.5) 
            
def play_as_SVG(frames_text: str):
    frames = re.findall(r'<FRAME>(.*?)</FRAME>', frames_text, re.DOTALL)
    placeholder = st.empty()
    
    while True:
        for frame in frames:
            with placeholder:
                _render_mermaid(frame)
            time.sleep(0.5) 