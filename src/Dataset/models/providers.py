"""
Real model adapters, over the providers' HTTP APIs.

  Responsibility: give three different providers the same interface the
  MockModel already satisfies -- one request in, one ModelResult out, with
  the tool-calling loop handled here so the runner never learns which
  provider it is talking to.

  Plain httpx rather than three vendor SDKs. The dataset only needs one
  endpoint per provider, the request shapes are stable and small, and three
  SDK dependency trees would be the largest thing in this project by far.
  It also keeps the pinned model string the only thing that decides what
  ran -- an SDK upgrade cannot quietly change behaviour.

  Rules these adapters keep:

    The key is read per call from the environment and never stored. It is
      not written to a config, a manifest, a result row or a log line, and
      the error raised when it is missing names the variable, not a value.
    A failure is a result, not an exception. HTTP errors, refusals, tool
      errors and unparseable answers come back as a ModelResult with
      `error` set, so the runner stores them and the operational metrics
      can count them.
    Retries are bounded and respect Retry-After. A 429 is the provider
      asking for less, not an invitation to spin.
    Tool calls are capped. A model that loops asking the same question
      stops at `max_tool_calls` and the transcript says so.
"""
from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from ..schemas import ModelSpec
from .base import ModelRequest, ModelResult

#: What the solver may call. One tool, one shape, across every provider.
PCAP_TOOL_NAME = "pcap_query"
PCAP_TOOL_DESCRIPTION = (
    "Run a tshark display filter against the capture under examination. "
    "Returns how many packets match and the first few matching packets."
)
PCAP_TOOL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "filter": {"type": "string", "description": "A tshark display filter, e.g. tcp.flags.syn == 1"},
        "limit": {"type": "integer", "description": "How many matching packets to return (max 50)"},
    },
    "required": ["filter"],
}

#: Status codes worth trying again. 408/409 are transient too, but these
#: are the ones providers actually use for "later, please".
RETRYABLE = frozenset({429, 500, 502, 503, 504, 529})


class ProviderError(RuntimeError):
    """Configuration that makes a call impossible (missing key, unset model)."""


ToolExecutor = Callable[[str, dict[str, Any]], dict[str, Any]]


@dataclass
class HttpModelAdapter:
    """
    Shared behaviour: retries, timeouts, the tool loop, token accounting.

    Subclasses translate one request and one response; everything that is
    the same for every provider lives here so it cannot drift between them.
    """

    spec: ModelSpec
    api_key_env: str
    model_name: str
    tool_executor: ToolExecutor | None = None
    timeout_seconds: float = 120.0
    max_attempts: int = 3
    backoff_seconds: float = 2.0
    max_tool_calls: int = 6
    client: httpx.Client | None = None
    price_per_mtok_in: float | None = None
    price_per_mtok_out: float | None = None
    _usage: dict[str, int] = field(default_factory=lambda: {"tokens_in": 0, "tokens_out": 0})

    # -- configuration -----------------------------------------------------

    def api_key(self) -> str:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise ProviderError(f"${self.api_key_env} is not set")
        return key

    def check_ready(self) -> None:
        """Raise if this adapter could not possibly make a call."""
        if not self.model_name or self.model_name == "UNSET":
            raise ProviderError(
                f"model name for {self.spec.model_id!r} is UNSET; set it in config/models.yaml "
                "(never an alias such as 'latest')"
            )
        self.api_key()

    def cost(self, tokens_in: int, tokens_out: int) -> float | None:
        """None when no price is configured -- a made-up cost is worse than none."""
        if self.price_per_mtok_in is None or self.price_per_mtok_out is None:
            return None
        return tokens_in / 1e6 * self.price_per_mtok_in + tokens_out / 1e6 * self.price_per_mtok_out

    # -- the HTTP layer ----------------------------------------------------

    def _post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        client = self.client or httpx.Client(timeout=self.timeout_seconds)
        last: httpx.Response | None = None
        for attempt in range(self.max_attempts):
            response = client.post(url, json=payload, headers=headers)
            if response.status_code not in RETRYABLE:
                return response
            last = response
            if attempt == self.max_attempts - 1:
                break
            # Respect the provider's own answer to "when?" before guessing.
            retry_after = response.headers.get("retry-after")
            try:
                delay = float(retry_after) if retry_after else self.backoff_seconds * (2 ** attempt)
            except ValueError:
                delay = self.backoff_seconds * (2 ** attempt)
            time.sleep(min(delay, 60) + random.uniform(0, 0.5))
        return last if last is not None else response

    # -- the loop ----------------------------------------------------------

    def generate(self, request: ModelRequest) -> ModelResult:
        started = time.monotonic()
        self._usage = {"tokens_in": 0, "tokens_out": 0}
        tool_calls: list[dict[str, Any]] = []
        try:
            self.check_ready()
            text = self._converse(request, tool_calls)
            error = None
        except ProviderError as exc:
            text, error = "", str(exc)
        except httpx.HTTPError as exc:
            # The class name, not the exception text: some clients put the
            # full URL, and a URL can carry a key as a query parameter.
            text, error = "", f"transport error: {type(exc).__name__}"
        return ModelResult(
            raw_text=text,
            tool_calls=tool_calls,
            tokens_in=self._usage["tokens_in"],
            tokens_out=self._usage["tokens_out"],
            latency_ms=int((time.monotonic() - started) * 1000),
            error=error,
        )

    def _run_tool(self, name: str, arguments: dict[str, Any], tool_calls: list[dict[str, Any]]) -> dict[str, Any]:
        record: dict[str, Any] = {"tool": name, "arguments": arguments}
        if self.tool_executor is None:
            record["error"] = "no tool executor configured"
        else:
            try:
                record["result"] = self.tool_executor(name, arguments)
            except Exception as exc:
                # A tool failure is the model's problem to handle and our
                # data to keep; it does not end the call.
                record["error"] = str(exc)
        tool_calls.append(record)
        return record

    def _converse(self, request: ModelRequest, tool_calls: list[dict[str, Any]]) -> str:
        raise NotImplementedError


class AnthropicAdapter(HttpModelAdapter):
    url = "https://api.anthropic.com/v1/messages"
    api_version = "2023-06-01"

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key(),
            "anthropic-version": self.api_version,
            "content-type": "application/json",
        }

    def _converse(self, request: ModelRequest, tool_calls: list[dict[str, Any]]) -> str:
        messages: list[dict[str, Any]] = [{"role": "user", "content": request.user_prompt}]
        tools = (
            [{"name": PCAP_TOOL_NAME, "description": PCAP_TOOL_DESCRIPTION, "input_schema": PCAP_TOOL_SCHEMA}]
            if request.tools_enabled
            else []
        )
        for _ in range(self.max_tool_calls + 1):
            payload: dict[str, Any] = {
                "model": self.model_name,
                "max_tokens": request.max_output_tokens,
                "temperature": request.temperature,
                "system": request.system_prompt,
                "messages": messages,
            }
            if tools:
                payload["tools"] = tools
            response = self._post(self.url, payload, self._headers())
            if response.status_code >= 400:
                raise ProviderError(f"HTTP {response.status_code}: {response.text[:200]}")
            body = response.json()
            usage = body.get("usage") or {}
            self._usage["tokens_in"] += int(usage.get("input_tokens", 0))
            self._usage["tokens_out"] += int(usage.get("output_tokens", 0))

            blocks = body.get("content") or []
            requests_ = [b for b in blocks if b.get("type") == "tool_use"]
            if not requests_:
                return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")

            messages.append({"role": "assistant", "content": blocks})
            results = []
            for block in requests_:
                record = self._run_tool(block.get("name", ""), block.get("input") or {}, tool_calls)
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.get("id"),
                        "content": json.dumps(record.get("result", {"error": record.get("error")})),
                        **({"is_error": True} if "error" in record else {}),
                    }
                )
            messages.append({"role": "user", "content": results})
        return "(tool-call limit reached before the model answered)"


class OpenAIAdapter(HttpModelAdapter):
    url = "https://api.openai.com/v1/chat/completions"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key()}", "content-type": "application/json"}

    def _converse(self, request: ModelRequest, tool_calls: list[dict[str, Any]]) -> str:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.user_prompt},
        ]
        tools = (
            [{"type": "function", "function": {
                "name": PCAP_TOOL_NAME, "description": PCAP_TOOL_DESCRIPTION, "parameters": PCAP_TOOL_SCHEMA}}]
            if request.tools_enabled
            else []
        )
        for _ in range(self.max_tool_calls + 1):
            payload: dict[str, Any] = {
                "model": self.model_name,
                "messages": messages,
                "temperature": request.temperature,
                "max_completion_tokens": request.max_output_tokens,
            }
            if tools:
                payload["tools"] = tools
            response = self._post(self.url, payload, self._headers())
            if response.status_code >= 400:
                raise ProviderError(f"HTTP {response.status_code}: {response.text[:200]}")
            body = response.json()
            usage = body.get("usage") or {}
            self._usage["tokens_in"] += int(usage.get("prompt_tokens", 0))
            self._usage["tokens_out"] += int(usage.get("completion_tokens", 0))

            message = (body.get("choices") or [{}])[0].get("message") or {}
            requested = message.get("tool_calls") or []
            if not requested:
                return message.get("content") or ""

            messages.append(message)
            for call in requested:
                function = call.get("function") or {}
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                record = self._run_tool(function.get("name", ""), arguments, tool_calls)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id"),
                        "content": json.dumps(record.get("result", {"error": record.get("error")})),
                    }
                )
        return "(tool-call limit reached before the model answered)"


class GoogleAdapter(HttpModelAdapter):
    base_url = "https://generativelanguage.googleapis.com/v1beta/models"

    def _headers(self) -> dict[str, str]:
        # The key goes in a header, not the query string, so it cannot end
        # up in a proxy log or an exception's URL.
        return {"x-goog-api-key": self.api_key(), "content-type": "application/json"}

    def _converse(self, request: ModelRequest, tool_calls: list[dict[str, Any]]) -> str:
        url = f"{self.base_url}/{self.model_name}:generateContent"
        contents: list[dict[str, Any]] = [{"role": "user", "parts": [{"text": request.user_prompt}]}]
        tools = (
            [{"function_declarations": [
                {"name": PCAP_TOOL_NAME, "description": PCAP_TOOL_DESCRIPTION, "parameters": PCAP_TOOL_SCHEMA}]}]
            if request.tools_enabled
            else []
        )
        for _ in range(self.max_tool_calls + 1):
            payload: dict[str, Any] = {
                "contents": contents,
                "systemInstruction": {"parts": [{"text": request.system_prompt}]},
                "generationConfig": {
                    "temperature": request.temperature,
                    "maxOutputTokens": request.max_output_tokens,
                },
            }
            if tools:
                payload["tools"] = tools
            response = self._post(url, payload, self._headers())
            if response.status_code >= 400:
                raise ProviderError(f"HTTP {response.status_code}: {response.text[:200]}")
            body = response.json()
            usage = body.get("usageMetadata") or {}
            self._usage["tokens_in"] += int(usage.get("promptTokenCount", 0))
            self._usage["tokens_out"] += int(usage.get("candidatesTokenCount", 0))

            parts = ((body.get("candidates") or [{}])[0].get("content") or {}).get("parts") or []
            requested = [p["functionCall"] for p in parts if p.get("functionCall")]
            if not requested:
                return "".join(p.get("text", "") for p in parts)

            contents.append({"role": "model", "parts": parts})
            responses = []
            for call in requested:
                record = self._run_tool(call.get("name", ""), call.get("args") or {}, tool_calls)
                responses.append(
                    {"functionResponse": {
                        "name": call.get("name"),
                        "response": record.get("result", {"error": record.get("error")}),
                    }}
                )
            contents.append({"role": "user", "parts": responses})
        return "(tool-call limit reached before the model answered)"


ADAPTERS: dict[str, type[HttpModelAdapter]] = {
    "anthropic": AnthropicAdapter,
    "openai": OpenAIAdapter,
    "google": GoogleAdapter,
}


def build_adapter(
    spec: ModelSpec,
    raw: dict[str, Any],
    *,
    tool_executor: ToolExecutor | None = None,
    client: httpx.Client | None = None,
    **overrides: Any,
) -> HttpModelAdapter:
    cls = ADAPTERS.get(spec.adapter)
    if cls is None:
        raise ProviderError(f"no adapter {spec.adapter!r}; known: {', '.join(sorted(ADAPTERS))}")
    return cls(
        spec=spec,
        api_key_env=raw.get("api_key_env") or "",
        model_name=raw.get("model_name") or "UNSET",
        tool_executor=tool_executor,
        client=client,
        price_per_mtok_in=raw.get("price_per_mtok_in"),
        price_per_mtok_out=raw.get("price_per_mtok_out"),
        **overrides,
    )
