import os
import streamlit as st
from google import genai
from typing import List, Optional, Dict
from messages import build_messages_from_dir
import base64
import re
from openai import OpenAI

""" This module provides functions to generate network diagrams using either OpenAI's GPT models or Google's Gemini models. It includes functionality to handle supporting files, convert messages between formats, and manage assets such as icons for the diagrams.
The main functions are: 
- generate_diagram: Determines which model to use for diagram generation.
- generate_diagram_openai: Generates a diagram using OpenAI's GPT models.   
"""

with open("src/prompts/instructions_svg2.txt", "r", encoding="utf-8") as f: 
    INSTRUCTIONS = f.read() 

def context_caching():
    """
    Context caching is a mechanism to store and retrieve context information for a session.
    This function checks if the context is already cached in the session state. If not, it initializes an empty dictionary for caching.
    """
    cache = client.caches.create(
        model=model,
        system_instruction=instructions,
        ttl=datetime.timedelta(minutes=60) 
    )

def generate_diagram(messages: List, api_key: str, model: str = "gpt-5", context_caching: bool = True) -> str:
    # if context_caching:
    #     context_caching()
    #     cache_key = f"{model}_{hash(str(messages))}"
    #     if cache_key in st.session_state.context_cache:
    #         print("Using cached context")
    #         return st.session_state.context_cache[cache_key]

    if model == "gpt-5":
        print("Generate with ChatGPT")
        return generate_diagram_openai(messages=messages, api_key=api_key, model=model)
    else:
        print("Generate with Gemini")
        return generate_diagram_gemini(messages=messages, api_key=api_key, model=model)


def generate_diagram_openai(messages: List, api_key: str, model: str = "gpt-5") -> str:
    """
    Generate a Mermaid diagram from a prompt and optional supporting files directory.
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

    diagram = response.output_text.strip()
    return diagram


def convert_openai_to_gemini(msg: Dict) -> genai.types.Part | None:
    if isinstance(msg["content"], str):
        return genai.types.Part(text=msg["content"])
    elif isinstance(msg["content"], list):
        for p in msg["content"]:
            if p["type"] == "text_input":
                return genai.types.Part(text=p["content"])
            elif p["type"] == "input_image":
                # f"data:image/{fmt};base64,{b64}"
                s = p["content"].split(";base64,")
                mime = s[0][11:]
                if mime == "jpg":
                    mime = "jpeg"
                data = base64.b64decode(s[1])
                return genai.types.Part(
                    inline_data=genai.types.Blob(mime_type=f"image/{mime}", data=data)
                )
    else:
        raise ValueError(f"Unsupported message content format: {msg['content']}")

def generate_diagram_gemini(
    messages: List, api_key: str, model: str = "gemini-2.0-flash" # Note: version check
) -> str:
    client = genai.Client(api_key=api_key)
    contents = []

    # English comments as requested: Simplify history building
    for msg in messages:
        role = "user" if msg["role"] == "user" else "model"
        
        # Ensure content is string and not too large
        content_text = msg.get("content", "")
        
        # Create a clean content object for Gemini
        contents.append(
            genai.types.Content(
                parts=[genai.types.Part(text=content_text)], 
                role=role
            )
        )

        config = genai.types.GenerateContentConfig(
            system_instruction=INSTRUCTIONS,
            max_output_tokens=8192,
            temperature=0.1,
        )
    try:
        response = client.models.generate_content(
            model=model, 
            contents=contents, 
            config=config
        )
        
        if not response or not response.text:
            raise Exception("Got empty response from Gemini")
        
        print(f"DEBUG: Finish Reason Code = {response.candidates[0].finish_reason}")

        # Extract the finish reason from the first candidate
        # 1 = SUCCESS, 2 = MAX_TOKENS, 3 = SAFETY, 4 = RECITATION, 5 = OTHER
        finish_reason = response.candidates[0].finish_reason

        print(f"Finish reason: {finish_reason}")
        if finish_reason != 1:
            print(f"Finish reason: {finish_reason}")
            if finish_reason == 3:
                print("Reason 3 (SAFETY): A filter was triggered. Check your packet payloads.")
            elif finish_reason == 2:
                print("Reason 2 (MAX_TOKENS): The diagram is too long for the 8k token limit.")
            
        return response.text
        
    except Exception as e:
        print(f"Gemini Error: {e}")
        raise e


def create_diagram(
    prompt: str,
    supporting_files_dir: Optional[str] = None,
    output_path: str = "mermaid.txt",
):
    """
    Create and save a Mermaid diagram using the prompt and (optionally) a directory
    of supporting files (each sent as its own message).
    """
    messages = build_messages_from_dir(supporting_files_dir)
    print(f"added {len(messages)} supporting files")

    # Main prompt last, so it’s freshest in context.
    messages.append({"role": "user", "content": prompt})

    response = generate_diagram(
        messages=messages, api_key=os.environ.get("OPENAI_API_KEY")
    )
    
    resp = response.text
    diag_match = re.search(r"<DIAGRAM>(.*?)</DIAGRAM>", resp, re.DOTALL)
    ent_match = re.search(r"<ENTITIES>(.*?)</ENTITIES>", resp, re.DOTALL)

    diagram_code = diag_match.group(1).strip() if diag_match else resp
    entities_json = ent_match.group(1).strip() if ent_match else "[]"
    
    print("Generated diagram")

    # Save as UTF-8 plain text
    with open(output_path, "w+", encoding="utf-8") as w:
        w.write(diagram_code)

    diagram_code = diag_match.group(1).strip() if diag_match else resp
    
    return f"{diagram_code}|||{entities_json}"