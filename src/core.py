import os
from typing import List, Dict, Optional

from openai import OpenAI

# ---- Configuration / prompt guardrails ----
INSTRUCTIONS = """
You are a networking and mermaid diagram syntax expert.
Your job is to generate a mermaid diagram that explains the network flow
described in the prompt and any supporting files.
STRICT RULES:
- ONLY output a single valid Mermaid definition (no backticks, no prose).
- Do not include explanations or comments.
- If a diagram type is ambiguous, default to a flowchart: `flowchart TD`.
"""

# Create client (uses OPENAI_API_KEY env var if not provided)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# ---- Helpers ----
from messages import build_messages_from_dir


def generate_diagram(messages: List, model: str = "gpt-5") -> str:
    """
    Generate a Mermaid diagram from a prompt and optional supporting files directory.
    Each supporting file is sent as a separate message for clearer source boundaries.
    """

    response = client.responses.create(
        model=model,
        instructions=INSTRUCTIONS,
        input=messages,
        # You can force plain text (no tool calls) if you want:
        # temperature=0.1,
    )

    diagram = response.output_text.strip()
    return diagram


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

    diagram = generate_diagram(messages=messages)
    print("Generated diagram")

    # Save as UTF-8 plain text
    with open(output_path, "w+", encoding="utf-8") as w:
        w.write(diagram)

    print(f"diagram saved to {output_path}")
