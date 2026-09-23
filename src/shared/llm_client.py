"""
PAnGEA — shared LLM client abstraction.

Promoted out of grounder/llm_client.py: this is a generic (prompt -> JSON)
interface with no Grounder-specific logic, and now multiple components
(Step Extractor, Evidence Matcher, Validator) need it. Keeping one
canonical definition here avoids three components depending on one
another's internals just to share a type.
"""
from __future__ import annotations

from typing import Protocol


class LLMClient(Protocol):
    def complete_json(self, system_prompt: str, user_prompt: str) -> dict:
        """Send a system+user prompt, return a parsed JSON dict response."""
        ...


def parse_and_repair_json(raw_text: str, max_repairs: int = 5) -> dict:
    """
    Attempts to parse JSON, fixing common minor formatting issues.

    Moved here from grounder/steps_extractor.py so any component's
    OpenAIClient (or other backend) can reuse it without importing
    steps_extractor.py just for this helper.
    """
    import json
    import logging
    import re

    logger = logging.getLogger(__name__)

    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    repairs_applied = 0
    repaired_text = cleaned

    python_literals = [(r"\bTrue\b", "true"), (r"\bFalse\b", "false"), (r"\bNone\b", "null")]
    for pattern, replacement in python_literals:
        new_text, n = re.subn(pattern, replacement, repaired_text)
        if n:
            repaired_text = new_text
            repairs_applied += n

    repaired_text, n = re.subn(r",\s*([}\]])", r"\1", repaired_text)
    repairs_applied += n

    single_count = repaired_text.count("'")
    double_count = repaired_text.count('"')
    if single_count > double_count * 2:
        repaired_text, n = re.subn(r"'([^'\\]*(?:\\.[^'\\]*)*)'", r'"\1"', repaired_text)
        repairs_applied += n

    def _escape_newlines(match: "re.Match") -> str:
        return match.group(1).replace("\n", "\\n").replace("\r", "\\r")

    fixed_control, n = re.subn(r'(".*?")', _escape_newlines, repaired_text, flags=re.DOTALL)
    if n:
        repaired_text = fixed_control
        repairs_applied += n

    if repairs_applied > max_repairs:
        raise ValueError(
            f"JSON payload required {repairs_applied} repairs, exceeding "
            f"max_repairs={max_repairs}; treating as too malformed to trust."
        )

    try:
        parsed = json.loads(repaired_text)
        logger.info("Successfully auto-repaired JSON (%d fixes applied).", repairs_applied)
        return parsed
    except json.JSONDecodeError as err:
        raise ValueError(
            f"Failed to parse or repair JSON payload: {err}\n"
            f"Raw text sample: {raw_text[:200]}..."
        ) from err


class OpenAIClient:
    """LLMClient implementation backed by OpenAI ChatCompletions JSON mode."""

    def __init__(
        self, api_key: str, model: str = "gpt-4o", temperature: float = 0.0,
        max_tokens: int = 8000,
    ):
        from openai import OpenAI

        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        # NOTE on max_tokens: previously never set explicitly, meaning the
        # API's own default applied -- which is NOT the same as "as much
        # as the model can produce". Confirmed via a real failure: a
        # content-rich extraction (many steps, verbose technical detail
        # per step, as the prompt instructs) got cut off mid-JSON, which
        # surfaced as a confusing "Unterminated string" / "invalid JSON"
        # error rather than anything indicating truncation was the actual
        # cause. 8000 is a generous default for this pipeline's typical
        # output size, not a hard guarantee for every possible input --
        # raise it further via this parameter if a description is large
        # enough to need more.

    def complete_json(self, system_prompt: str, user_prompt: str) -> dict:
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        choice = response.choices[0]
        if choice.finish_reason == "length":
            # Detected directly from the API, not inferred from a parse
            # failure -- this is exactly the failure mode above, caught
            # at the source with an actionable message instead of a
            # generic "invalid JSON" error that doesn't point at the
            # real cause.
            raise ValueError(
                f"OpenAI response was truncated (finish_reason='length') "
                f"before completing -- max_tokens={self.max_tokens} was not "
                f"enough for this input. Raise max_tokens (e.g. construct "
                f"OpenAIClient(..., max_tokens=16000)) and retry. Partial "
                f"output was {len(choice.message.content or '')} characters."
            )
        content = choice.message.content or "{}"
        return parse_and_repair_json(content)