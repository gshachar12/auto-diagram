"""
LLM client abstraction used by both Grounder sub-components:

  - Step Extractor: "necessarily LLM-based" (per spec) for the full extraction pass.
  - Evidence Matcher: LLM escalation only, reserved for ambiguous / non-structured
    cases (multiple competing actor matches, multiple competing fingerprint matches,
    or Steps with no usable structured indicators). Per spec this must receive only
    the relevant slice of data, never the full Reduced PCAP.

Two implementations are provided:
  - AnthropicLLMClient: calls the real Claude API (requires `anthropic` package + key).
  - MockLLMClient: deterministic, offline stand-in used by the demo/tests so the
    pipeline is runnable and testable without network access or an API key.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any


class LLMClient(ABC):
    """Minimal interface the Grounder needs from an LLM backend."""

    @abstractmethod
    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Send a prompt and get back a parsed JSON object.

        Implementations are responsible for instructing the model to return JSON
        only, and for stripping any code-fence wrapping before parsing.
        """
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text")
        return _parse_json_response(text)

class AnthropicLLMClient(LLMClient):
    """Thin wrapper around the Anthropic Messages API.

    Usage:
        client = AnthropicLLMClient(model="claude-sonnet-4-6")
        result = client.complete_json(system_prompt, user_prompt)
    """

    def __init__(self, model: str = "claude-sonnet-4-6", max_tokens: int = 2000, api_key: str | None = None):
        try:
            import anthropic  # imported lazily so the package is optional for demo/mock use
        except ImportError as e:
            raise ImportError(
                "The 'anthropic' package is required for AnthropicLLMClient. "
                "Install it with `pip install anthropic`, or use MockLLMClient instead."
            ) from e
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text")
        return _parse_json_response(text)

class OpenAIClient(LLMClient):
    """Thin wrapper around the OpenAI Chat Completions API.

    Usage:
        client = OpenAIClient(model="gpt-4o")
        result = client.complete_json(system_prompt, user_prompt)
    """

    def __init__(self, model: str = "gpt-4o", max_tokens: int = 2000, api_key: str | None = None):
        try:
            import openai  # imported lazily so the package is optional for demo/mock use
        except ImportError as e:
            raise ImportError(
                "The 'openai' package is required for OpenAIClient. "
                "Install it with `pip install openai`, or use MockLLMClient instead."
            ) from e
        self._openai = openai
        self.client = openai.ChatCompletion(api_key=api_key) if api_key else openai.ChatCompletion()
        self.model = model
        self.max_tokens = max_tokens

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        response = self.client.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = response.choices[0].message.content
        return _parse_json_response(text)
    

class MockLLMClient(LLMClient):
    """Deterministic offline client for demos/tests.

    Register canned responses keyed by a substring of the user prompt, or supply a
    callback for full control. Falls back to a generic empty response if nothing
    matches, so the pipeline degrades gracefully instead of crashing.
    """

    def __init__(self):
        self._responses: list[tuple[str, dict[str, Any]]] = []

    def register(self, prompt_contains: str, response: dict[str, Any]) -> None:
        self._responses.append((prompt_contains, response))

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        for needle, response in self._responses:
            if needle in user:
                return response
        # Safe default: matches the "no confident answer" shape callers expect.
        return {}


def _parse_json_response(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM did not return valid JSON. Raw output:\n{text}") from e
