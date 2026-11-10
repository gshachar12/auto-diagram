"""
The provider adapters.

Every test here runs against a fake transport -- no network, no key, no
cost. What is being checked is the part that is easy to get wrong and
expensive to discover live: that a key never escapes into stored text, that
a failure comes back as a result rather than an exception, that retries are
bounded and respect Retry-After, and that the tool loop terminates.
"""
from __future__ import annotations

import json

import httpx
import pytest

from Dataset.models.base import ModelRequest
from Dataset.models.providers import (
    AnthropicAdapter,
    GoogleAdapter,
    OpenAIAdapter,
    ProviderError,
    build_adapter,
)
from Dataset.schemas import ModelSpec

ANSWER = {"verdict": "SUPPORTED", "condition": "tcp", "cited_packets": [1],
          "criteria_checks": {}, "survey": {"confidence": 4}}


def _spec(adapter: str) -> ModelSpec:
    return ModelSpec(
        model_id=f"{adapter}-test", family=adapter, version="v1", adapter=adapter,
        supports_tools=True, temperature=0.0,
    )


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _request() -> ModelRequest:
    return ModelRequest(system_prompt="system", user_prompt="user", call_key="k")


# -- configuration ---------------------------------------------------------

def test_a_missing_key_is_a_result_not_a_crash(monkeypatch):
    monkeypatch.delenv("TEST_KEY", raising=False)
    adapter = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m")
    result = adapter.generate(_request())
    assert result.error and "TEST_KEY" in result.error
    assert result.raw_text == ""


def test_an_unset_model_name_refuses_before_calling(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    adapter = OpenAIAdapter(spec=_spec("openai"), api_key_env="TEST_KEY", model_name="UNSET")
    result = adapter.generate(_request())
    # An aliased or invented model name makes a run unreproducible, so the
    # adapter will not call until a real one is configured.
    assert result.error and "UNSET" in result.error


def test_an_unknown_adapter_is_refused():
    with pytest.raises(ProviderError, match="no adapter"):
        build_adapter(_spec("telepathy"), {})


def test_cost_is_none_without_a_configured_price(monkeypatch):
    adapter = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="K", model_name="m")
    assert adapter.cost(1000, 1000) is None
    adapter.price_per_mtok_in = 3.0
    adapter.price_per_mtok_out = 15.0
    assert adapter.cost(1_000_000, 1_000_000) == pytest.approx(18.0)


# -- the happy path, per provider -----------------------------------------

def test_anthropic_returns_text_and_counts_tokens(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "content": [{"type": "text", "text": json.dumps(ANSWER)}],
            "usage": {"input_tokens": 120, "output_tokens": 30},
        })

    adapter = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                               client=_client(handler))
    result = adapter.generate(_request())
    assert json.loads(result.raw_text)["verdict"] == "SUPPORTED"
    assert (result.tokens_in, result.tokens_out) == (120, 30)
    assert seen["body"]["model"] == "m" and seen["body"]["system"] == "system"
    assert seen["headers"]["x-api-key"] == "secret"


def test_openai_returns_text_and_counts_tokens(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": json.dumps(ANSWER)}}],
            "usage": {"prompt_tokens": 90, "completion_tokens": 20},
        })

    result = OpenAIAdapter(spec=_spec("openai"), api_key_env="TEST_KEY", model_name="m",
                           client=_client(handler)).generate(_request())
    assert result.tokens_in == 90 and result.error is None


def test_google_sends_the_key_in_a_header_not_the_url(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": json.dumps(ANSWER)}]}}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5},
        })

    GoogleAdapter(spec=_spec("google"), api_key_env="TEST_KEY", model_name="m",
                  client=_client(handler)).generate(_request())
    # A key in a query string ends up in proxy logs and exception messages.
    assert "secret" not in seen["url"]
    assert seen["headers"]["x-goog-api-key"] == "secret"


# -- the tool loop ---------------------------------------------------------

def test_anthropic_runs_a_tool_call_and_feeds_the_result_back(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    turns = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        turns.append(body)
        if len(turns) == 1:
            return httpx.Response(200, json={
                "content": [{"type": "tool_use", "id": "t1", "name": "pcap_query",
                             "input": {"filter": "tcp", "limit": 5}}],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            })
        return httpx.Response(200, json={
            "content": [{"type": "text", "text": json.dumps(ANSWER)}],
            "usage": {"input_tokens": 20, "output_tokens": 5},
        })

    calls = []

    def execute(name, arguments):
        calls.append((name, arguments))
        return {"match_count": 7, "packets": []}

    adapter = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                               client=_client(handler), tool_executor=execute)
    result = adapter.generate(_request())
    assert calls == [("pcap_query", {"filter": "tcp", "limit": 5})]
    assert result.tool_calls[0]["result"] == {"match_count": 7, "packets": []}
    # Tokens accumulate across the whole exchange, not just the last turn.
    assert result.tokens_in == 30
    assert "tool_result" in json.dumps(turns[1])


def test_a_tool_failure_is_recorded_and_the_call_continues(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    turns = []

    def handler(request: httpx.Request) -> httpx.Response:
        turns.append(1)
        if len(turns) == 1:
            return httpx.Response(200, json={"content": [
                {"type": "tool_use", "id": "t1", "name": "pcap_query", "input": {"filter": "nonsense"}}]})
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(ANSWER)}]})

    def explode(name, arguments):
        raise RuntimeError("invalid display filter")

    result = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                              client=_client(handler), tool_executor=explode).generate(_request())
    assert result.tool_calls[0]["error"] == "invalid display filter"
    assert result.raw_text  # the model still got to answer


def test_the_tool_loop_is_capped(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        # A model that never stops asking.
        return httpx.Response(200, json={"content": [
            {"type": "tool_use", "id": "t", "name": "pcap_query", "input": {"filter": "tcp"}}]})

    adapter = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                               client=_client(handler), tool_executor=lambda n, a: {"match_count": 0},
                               max_tool_calls=3)
    result = adapter.generate(_request())
    assert len(result.tool_calls) == 4  # the cap, then it gives up and says so
    assert "limit reached" in result.raw_text


# -- failures and retries --------------------------------------------------

def test_an_http_error_becomes_an_error_result(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    adapter = AnthropicAdapter(
        spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
        client=_client(lambda r: httpx.Response(400, text="bad request")),
    )
    result = adapter.generate(_request())
    assert result.error and "400" in result.error


def test_rate_limits_are_retried_then_reported(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    monkeypatch.setattr("Dataset.models.providers.time.sleep", lambda s: None)
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(429, headers={"retry-after": "0"}, text="slow down")

    adapter = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                               client=_client(handler), max_attempts=3)
    result = adapter.generate(_request())
    assert len(attempts) == 3  # bounded, not a spin
    assert result.error and "429" in result.error


def test_a_retry_succeeds_on_the_second_attempt(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    monkeypatch.setattr("Dataset.models.providers.time.sleep", lambda s: None)
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(503, text="unavailable")
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(ANSWER)}]})

    result = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                              client=_client(handler)).generate(_request())
    assert result.error is None and len(attempts) == 2


def test_a_transport_error_never_echoes_the_url(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("failed connecting to https://api.example/?key=secret")

    result = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                              client=_client(handler)).generate(_request())
    # A URL can carry a key; only the exception class is reported.
    assert result.error == "transport error: ConnectError"
    assert "secret" not in result.error


def test_the_key_never_appears_in_the_stored_result(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "super-secret-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(ANSWER)}]})

    result = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                              client=_client(handler)).generate(_request())
    assert "super-secret-value" not in json.dumps(result.__dict__, default=str)


def test_tools_are_omitted_for_a_model_without_tool_support(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "secret")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"content": [{"type": "text", "text": "{}"}]})

    adapter = AnthropicAdapter(spec=_spec("anthropic"), api_key_env="TEST_KEY", model_name="m",
                               client=_client(handler))
    adapter.generate(ModelRequest(system_prompt="s", user_prompt="u", tools_enabled=False))
    assert "tools" not in seen
