"""
The MockModel and the answer parser.

What is being pinned down here is the failure handling: a malformed answer,
a refusal and a tool error must each come back as a stored, classified
result, because the operational metrics (format-error rate, abstention rate,
tool-call failures) are computed from exactly these.
"""
from __future__ import annotations

import json

import pytest

from Dataset.models.base import ModelRequest, parse_answer
from Dataset.models.mock import CallPlan, MockModel, ScriptedBehaviour, _weighted_pick
from Dataset.schemas import ModelSpec, ReasonCode, Verdict


def _run(spec: ModelSpec, behaviour: ScriptedBehaviour, verdict: Verdict = Verdict.SUPPORTED):
    model = MockModel(spec, plans={"k": CallPlan(behaviour=behaviour, verdict=verdict)})
    result = model.generate(ModelRequest("system", "user", call_key="k"))
    return result, parse_answer(result.raw_text)


def test_correct_behaviour_returns_the_planned_verdict(mock_spec):
    _, parsed = _run(mock_spec, ScriptedBehaviour.CORRECT, Verdict.REFUTED)
    assert parsed.format_error is False
    assert parsed.answer.verdict is Verdict.REFUTED


def test_wrong_behaviour_returns_a_different_verdict(mock_spec):
    _, parsed = _run(mock_spec, ScriptedBehaviour.WRONG, Verdict.REFUTED)
    assert parsed.answer.verdict is not Verdict.REFUTED


def test_abstention_always_carries_a_reason_code(mock_spec):
    _, parsed = _run(mock_spec, ScriptedBehaviour.ABSTAIN)
    assert parsed.answer.verdict is Verdict.NOT_VERIFIABLE
    assert parsed.answer.reason_code in set(ReasonCode)


def test_malformed_output_is_a_format_error_not_an_exception(mock_spec):
    result, parsed = _run(mock_spec, ScriptedBehaviour.MALFORMED)
    assert parsed.format_error is True
    assert parsed.answer is None
    assert result.raw_text  # the raw text is still there to be stored


def test_refusal_is_recorded_as_data(mock_spec):
    result, parsed = _run(mock_spec, ScriptedBehaviour.REFUSAL)
    assert parsed.format_error is True
    assert "cannot" in result.raw_text


def test_tool_failure_is_visible_in_the_result_and_the_tool_calls(mock_spec):
    result, parsed = _run(mock_spec, ScriptedBehaviour.TOOL_FAILURE)
    assert result.error is not None
    assert any("error" in call for call in result.tool_calls)
    assert parsed.answer.verdict is Verdict.NOT_VERIFIABLE


def test_fabricated_packets_cite_numbers_beyond_the_capture(mock_spec):
    _, parsed = _run(mock_spec, ScriptedBehaviour.FABRICATED_PACKETS)
    assert max(parsed.answer.cited_packets) > 100


def test_a_model_without_tool_support_records_no_tool_calls():
    spec = ModelSpec(
        model_id="mock-c", family="mock-gamma", version="v1", adapter="mock",
        supports_tools=False, temperature=0.0,
    )
    result, _ = _run(spec, ScriptedBehaviour.CORRECT)
    assert result.tool_calls == []


def test_behaviour_is_deterministic_for_a_key_and_seed():
    first = [_weighted_pick(f"call-{i}", seed=11) for i in range(50)]
    second = [_weighted_pick(f"call-{i}", seed=11) for i in range(50)]
    assert first == second
    assert [_weighted_pick(f"call-{i}", seed=12) for i in range(50)] != first


def test_default_mix_exercises_every_failure_path(mock_spec):
    model = MockModel(mock_spec, seed=3)
    seen = {
        _weighted_pick(f"{mock_spec.model_id}:call-{i}", 3)
        for i in range(400)
    }
    assert seen == set(ScriptedBehaviour)


# -- the parser ----------------------------------------------------------

def test_empty_response_is_a_format_error():
    parsed = parse_answer("   ")
    assert parsed.format_error and "empty" in parsed.detail


def test_repaired_json_is_still_counted_as_a_format_error():
    # Trailing comma: recoverable, but the model did not follow the schema,
    # and the format-error rate is supposed to show that.
    parsed = parse_answer('{"verdict": "SUPPORTED", "cited_packets": [1],}')
    assert parsed.repaired is True
    assert parsed.format_error is True
    assert parsed.answer.verdict is Verdict.SUPPORTED


def test_valid_json_with_the_wrong_shape_keeps_the_payload():
    parsed = parse_answer(json.dumps({"verdict": "MAYBE"}))
    assert parsed.format_error is True
    assert parsed.answer is None
    assert parsed.payload == {"verdict": "MAYBE"}


def test_not_verifiable_without_a_reason_code_is_rejected():
    parsed = parse_answer(json.dumps({"verdict": "NOT_VERIFIABLE"}))
    assert parsed.format_error is True
    assert "reason code" in parsed.detail


def test_a_json_array_is_not_an_answer():
    parsed = parse_answer("[1, 2, 3]")
    assert parsed.format_error and "object" in parsed.detail
