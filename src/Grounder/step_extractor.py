"""
PAnGEA — Step Extractor.

Responsibility: extract a list of traffic-observable behavioral steps
from a free-text description.

Design constraints:
  - Each step must describe something directly observable in a packet
    capture: protocol, direction, volume, rate, port, flags.
  - Steps about attacker intent, system impact, or non-traffic behavior
    are excluded.
  - Output is structured (Step dataclass), not free text.
  - LLM is used with temperature=0 and a fixed prompt for maximum
    determinism. Model version must be pinned by the caller.
  - Outputs are saved to disk as static JSON files (extracted/ directory)
    so downstream evaluation never requires re-running the LLM.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Callable, Optional

from Grounder.schemas import Step

logger = logging.getLogger(__name__)

LLMClient = Callable[[str], str]


class StepExtractionError(RuntimeError):
    """LLM call failed or its response could not be parsed into steps."""

_EXTRACTION_PROMPT = """You are extracting observable network traffic steps from a description.

Rules:
- Each step must describe something directly observable in a packet capture.
- Include: protocol, packet type, source/destination direction, port numbers,
  flags, volume, rate, payload content if mentioned.
- Exclude: attacker intent ("the attacker wanted to..."), system impact
  ("the server crashed"), anything not visible as packets.
- One step = one observable traffic pattern. Do not merge distinct patterns.
- If the text describes a response to traffic, that is a separate step.

Output ONLY a JSON array of objects with these exact keys:
  "step_id"     : integer starting at 1
  "text"        : the extracted step in traffic-observable language
  "source_text" : the original sentence(s) this step was drawn from

No explanation, no markdown, no preamble. Only the JSON array.

Description:
{description}

JSON:"""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract_steps(
    description: str,
    llm_client: LLMClient,
    save_path: Optional[str] = None,
) -> list[Step]:
    """
    Extract traffic-observable steps from a free-text description.

    Args:
        description:  input text describing network traffic or an attack.
        llm_client:   LLM callable (prompt -> response text).
                      Must be called with temperature=0 by the caller.
        save_path:    if provided, saves extracted steps as JSON to this path.
                      Required for reproducibility — always provide in
                      production use so outputs can be versioned.

    Returns:
        list[Step] in step_id order.

    Raises:
        StepExtractionError: the LLM call failed or returned unparseable output.
            Nothing is saved in that case, so a failed run never leaves an
            empty extracted_*.json behind.
    """
    if not description or not description.strip():
        return []

    prompt = _EXTRACTION_PROMPT.format(description=description.strip())

    try:
        raw = llm_client(prompt)
    except Exception as exc:
        raise StepExtractionError(f"Step extractor LLM call failed: {exc}") from exc

    steps = _parse_response(raw)

    if save_path:
        _save_steps(steps, save_path)

    return steps


def load_steps(path: str) -> list[Step]:
    """
    Load previously extracted steps from a saved JSON file.
    Use this in evaluation to avoid re-running the LLM.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return steps_from_records(data)


def steps_from_records(data: list[dict]) -> list[Step]:
    """Build Steps from the saved JSON form (list of step dicts)."""
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array of steps, got {type(data).__name__}")
    steps = [
        Step(
            step_id=int(item["step_id"]),
            text=str(item["text"]).strip(),
            source_text=str(item.get("source_text", "")).strip(),
            mitre_tag=item.get("mitre_tag"),
        )
        for item in data
    ]
    steps.sort(key=lambda s: s.step_id)
    return steps


# ---------------------------------------------------------------------------
# Parsing and saving
# ---------------------------------------------------------------------------

def _parse_response(raw: str) -> list[Step]:
    cleaned = raw.strip().strip("```").strip()
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise StepExtractionError(
            f"Failed to parse LLM response as JSON: {exc}; raw={raw[:300]!r}"
        ) from exc

    if not isinstance(data, list):
        raise StepExtractionError(f"Expected a JSON array, got {type(data).__name__}")

    steps = []
    for item in data:
        try:
            steps.append(Step(
                step_id=int(item["step_id"]),
                text=str(item["text"]).strip(),
                source_text=str(item.get("source_text", "")).strip(),
                mitre_tag=item.get("mitre_tag"),
            ))
        except (KeyError, ValueError) as exc:
            logger.warning("Step extractor: skipping malformed step %r: %s", item, exc)
            continue

    steps.sort(key=lambda s: s.step_id)
    return steps


def _save_steps(steps: list[Step], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    data = [
        {
            "step_id":    s.step_id,
            "text":       s.text,
            "source_text":s.source_text,
            "mitre_tag":  s.mitre_tag,
        }
        for s in steps
    ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info("Saved %d steps to %s", len(steps), path)
