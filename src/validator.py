# English comments only
import os
import json
import re
import streamlit as st
from typing import List, Dict, Set, Tuple
# Importing the LLM generation connection from your core engine
from core import generate_diagram 


"""
This module provides functionality to validate the generated D2 diagram against the original PCAP data and the extracted entities.
It includes both algorithmic checks (like node and path alignment) and qualitative checks using an LLM agent.
The validation process is designed to be comprehensive, ensuring that the generated diagram accurately represents the underlying network
""" 

def xml_correction_parser(diagram: str) -> str:
    """
    Ensures that the XML tags in the response are properly closed and formatted.
    This function corrects any unclosed or malformed XML tags to prevent parsing errors.
    """
    pass

def validate_diagram_openai(messages: List, api_key: str, model: str = "gpt-5") -> str:
    """
    Validate a Mermaid diagram from a prompt and optional supporting files directory.
    Each supporting file is sent as a separate message for clearer source boundaries.
    """
    client = OpenAI(api_key=api_key)

    response = client.responses.create(
        model=model,
        instructions=INSTRUCTIONS,
        input=messages,
        tools=[{"type": "web_search"}],
        #temperature=0.1,
    )
    return response.text.strip()

def validate_diagram_gemini(messages: List, api_key: str, model: str = "gemini-1") -> str:
    """
    Validate a Mermaid diagram from a prompt and optional supporting files directory.
    Each supporting file is sent as a separate message for clearer source boundaries.
    """
    client = genai.Client(api_key=api_key)

    response = client.responses.create(
        model=model,
        instructions=INSTRUCTIONS,
        input=messages,
        tools=[{"type": "web_search"}],
        #temperature=0.1,
    )

def load_validator_instructions(file_path: str = "src/prompts/validator.txt") -> str:
    """
    Loads the qualitative criteria guidelines for the LLM validator agent.
    """
    if not os.path.exists(file_path):
        return "You are a strict validator. Ensure the diagram elements match all rules."
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read().strip()


def run_llm_agent_validation(diagram_code: str, entities_json_str: str, model: str, api_key: str) -> str:
    """
    Spawns an LLM judge agent to assess qualitative aspects of the D2 output 
    based on the rules stored inside validator.txt.
    """
    validator_prompt = load_validator_instructions("validator.txt")

    if model == "gpt-5":
        print("Validate with ChatGPT")
        return validate_diagram_openai(messages=messages, api_key=api_key, model=model)
    else:
        print("Validate with Gemini")
        return validate_diagram_gemini(messages=messages, api_key=api_key, model=model)

    try: 
        validate_diagram(
            messages=[  validator_prompt, diagram_code, entities_json_str ],
            api_key=st.session_state["api_key"],)
    except Exception as e:
        return f"LLM Agent Validation Failed due to an API Error: {e}"
def run_algorithmic_checks(diagram_code: str, entities_json_str: str) -> Dict:
    pass
def full_validator(diagram_code: str, entities_json_str: str, steps_json_str: str, api_key: str, model: str) -> Dict:
    """
    Validates the generated diagram against the original PCAP data and extracted entities.
    Returns a dictionary containing validation results, including pass/fail status and detailed feedback.
    """
    #syntax validation
    xml_corrected_diagram = xml_correction_parser(diagram_code)

    # Run algorithmic checks
    algorithmic_results = run_algorithmic_checks(xml_corrected_diagram, entities_json_str)
    
    # Run LLM qualitative checks
    llm_feedback = run_llm_agent_validation(xml_corrected_diagram, entities_json_str, steps_json_str, api_key, model)
    
    # Combine results
    validation_result = {
        "algorithmic": algorithmic_results,
        "llm_feedback": llm_feedback,
        "passed": algorithmic_results["passed"] and not llm_feedback.get("errors")
    }
    
    return validation_result
def validator_tab():
    """
    Renders the Validator tab in the Streamlit application.
    This tab assesses the generated SVG diagram against the original PCAP data and extracted entities.
    It performs both algorithmic checks (like node and path alignment) and qualitative checks using an LLM agent.
    """
    st.subheader("🧪 Validator")
    st.markdown(
        """
        The Validator tab assesses the generated SVG diagram against the original PCAP data and extracted entities.
        It performs both algorithmic checks (like entity alignment) and qualitative checks using an LLM agent.
        """
    )
    
    # Mock data for demonstration purposes. 
    # Replace these with real data from your session state (e.g., st.session_state.validation_result)
    validation_passed = False  
    error_count = 3
    detailed_feedback = [
        "Arrow 3 (DNS Q) and Arrow 4 (DNS R) both use Y=180. Change Arrow 4 to Y=240 to prevent overlapping.",
        "The dashed vertical lifeline for 10.0.2.30 is rendered after the Phase 1 info card, causing a visual line to cut through the text. Move the info card to the bottom of the SVG DOM.",
        "The phase background block for 'Phase 2' is missing an opacity attribute. Change it to opacity='0.05' for glassmorphism compliance."
    ]
    
    # ---------------------------------------------------------
    # PART 1: High-Level Status Metrics
    # ---------------------------------------------------------
    col1, col2, col3 = st.columns(3)
    with col1:
        if validation_passed:
            st.success("🟢 STATUS: APPROVED")
        else:
            st.error("🔴 STATUS: REJECTED")
            
    with col2:
        st.metric(label="Total Errors Found", value=error_count)
        
    with col3:
        # Pull the number of packets processed directly from your parser logic
        st.metric(label="Parsed Packets Audited", value=434) 
        
    st.divider()
    
    # ---------------------------------------------------------
    # PART 2: Algorithmic Asset Checks (Deterministic Python Logic)
    # ---------------------------------------------------------
    st.markdown("### 🧬 1. Algorithmic Asset Checks")
    
    with st.expander("📋 Entity & IP Mapping Consistency", expanded=True):
        # Use automated checks to toggle these checkmarks natively
        st.checkbox("Verify all unique IPs from PCAP exist as Lifelines in SVG", value=True, disabled=True)
        st.checkbox("Check for XML-breaking characters (raw '&' handling)", value=True, disabled=True)
        st.checkbox("Validate basic SVG tags symmetry and closure", value=True, disabled=True)

    # ---------------------------------------------------------
    # PART 3: LLM Qualitative & Visual Review (The Agent Report)
    # ---------------------------------------------------------
    st.markdown("### 🧠 2. AI Qualitative & Visual Review")
    
    if validation_passed:
        st.balloons()
        st.info("✨ Excellent! The AI Validator found 0 geometric or structural violations. The diagram matches production standards.")
    else:
        st.warning("⚠️ The diagram requires adjustments before it can be finalized. Review the specific AI feedback below:")
        
        # Iterating over the structured feedback array parsed from the Validator JSON
        for idx, issue in enumerate(detailed_feedback, 1):
            st.markdown(f"**{idx}.** `{issue}`")
            
        # Optional manual override button allowing the user to trigger the loop on-demand
        if st.button("🔄 Force Self-Correction Loop"):
            with st.spinner("Generator Agent is fixing the SVG coordinates based on feedback..."):
                # Call your backend pipeline function here:
                # e.g., run_self_correction(current_svg, detailed_feedback)
                pass
