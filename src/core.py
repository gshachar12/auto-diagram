import os

from google import genai
from typing import List, Optional, Dict
from messages import build_messages_from_dir
import base64
from openai import OpenAI


# ---- Configuration / prompt guardrails ----
INSTRUCTIONS = """
You are a networking and Mermaid diagram syntax expert.
Your job is to generate a Mermaid diagram that explains the network flow
described in the user’s input (and any supporting files, if provided).

If the user specifies a diagram type (e.g., "ZenUML", "flowchart"), you MUST use that type.
Otherwise, choose the diagram type that best represents the described network flow, defaulting to "sequenceDiagram" if you are uncertain.

STRICT RULES:
- Output ONLY a single valid Mermaid definition.
- Do NOT wrap the output in backticks or quotes.
- Do NOT add explanations, comments, or prose.
- All node/edge labels MUST be wrapped in double quotes ("...").
  - This ensures special characters such as (), [], {}, :, -, and spaces are handled safely.
  - Do not use " inside labels (replace or omit if present).
- The output must be syntactically correct Mermaid that renders without modification.
"""

# Create client (uses OPENAI_API_KEY env var if not provided)


def generate_diagram(messages: List, api_key: str, model: str = "gpt-5") -> str:
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
        # You can force plain text (no tool calls) if you want:
        # temperature=0.1,
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
        raise Exception("invalid msg type")


def generate_diagram_gemini(
    messages: List, api_key: str, model: str = "gemini-2.5-flash"
) -> str:
    client = genai.Client(api_key=api_key)

    parts = []
    contents = []
    for msg in messages:
        if msg["role"] == "user":
            parts.append(convert_openai_to_gemini(msg))
        else:  # This is AI response
            contents.append(genai.types.Content(parts=parts, role="user"))
            parts = []
            contents.append(
                genai.types.Content(
                    parts=[genai.types.Part(text=msg["content"])], role="model"
                )
            )
    if len(parts) > 0:
        contents.append(genai.types.Content(parts=parts, role="user"))

    config = genai.types.GenerateContentConfig(system_instruction=INSTRUCTIONS)
    response = client.models.generate_content(
        model=model, contents=contents, config=config
    )
    """Generate a Mermaid diagram using Google Gemini."""

    resp = response.text
    if resp is None:
        raise Exception("Got empty reponse from Gemini")
    return resp


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

    diagram = generate_diagram(
        messages=messages, api_key=os.environ.get("OPENAI_API_KEY")
    )

    print("Generated diagram")

    # Save as UTF-8 plain text
    with open(output_path, "w+", encoding="utf-8") as w:
        w.write(diagram)

    print(f"diagram saved to {output_path}")
