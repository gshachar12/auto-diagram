"""
The model interface, and how an answer is parsed.

  Responsibility: one shape of request and result for every provider, and
  one place that decides whether an answer was well formed.

  Parsing policy, which matters for the operational metrics: a response is
  parsed strictly first. If strict parsing fails we still try to repair it
  (reusing the repo's shared repair helper), but the record keeps
  `format_error = True` either way. Repairing an answer and then calling it
  well formed would erase exactly the signal the format-error rate is
  supposed to measure.

  A refusal, a tool failure and an empty answer are results, not exceptions.
  The runner stores them; nothing is dropped.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..schemas import ModelSpec, SolverAnswer

# The JSON repair helper already exists in this repo (src/shared/llm_client.py)
# and is used by the Grounder; reusing it keeps one definition of "repaired".
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from shared.llm_client import parse_and_repair_json  # noqa: E402


@dataclass(frozen=True)
class ModelRequest:
    """
    One call to a model.

    `call_key` identifies the (run, pair, model, prompt, repeat) slot. It is
    carried so adapters can be idempotent and so the MockModel can look up
    its script -- it is never part of the prompt text.
    """

    system_prompt: str
    user_prompt: str
    call_key: str = ""
    temperature: float = 0.0
    max_output_tokens: int = 2048
    tools_enabled: bool = True


@dataclass(frozen=True)
class ModelResult:
    """What came back. `error` set means the call failed; it is still stored."""

    raw_text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    error: str | None = None


class ModelAdapter(Protocol):
    """Provider-agnostic. Implemented by MockModel and, later, real APIs."""

    spec: ModelSpec

    def generate(self, request: ModelRequest) -> ModelResult:
        ...


@dataclass(frozen=True)
class ParsedAnswer:
    """
    Outcome of parsing one raw response.

    `format_error` is true for anything that was not valid, schema-correct
    JSON on the first attempt -- including answers that a repair rescued.
    """

    answer: SolverAnswer | None
    payload: dict[str, Any] | None
    format_error: bool
    detail: str = ""
    repaired: bool = False


def parse_answer(raw_text: str) -> ParsedAnswer:
    """Parse a solver response into the 8.3 schema, recording how it went."""
    if not raw_text.strip():
        return ParsedAnswer(None, None, True, "empty response")

    repaired = False
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        try:
            payload = parse_and_repair_json(raw_text)
            repaired = True
        except Exception as exc:  # the repair helper raises plain exceptions
            return ParsedAnswer(None, None, True, f"unparseable: {exc}")

    if not isinstance(payload, dict):
        return ParsedAnswer(None, None, True, f"expected an object, got {type(payload).__name__}")

    try:
        answer = SolverAnswer(**payload)
    except Exception as exc:
        # Valid JSON, wrong shape: still a format error, and the payload is
        # kept so the dashboard can show what the model actually said.
        return ParsedAnswer(None, payload, True, f"schema: {exc}", repaired)

    return ParsedAnswer(answer, payload, repaired, "repaired JSON" if repaired else "", repaired)
