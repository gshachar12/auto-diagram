"""
MockModel: a scripted panel member.

  Responsibility: make every other component runnable and testable without
  an API key, a network call or a cost. All tests and the demo dataset run
  on it.

  It is not a stub that always succeeds. The failure modes the analysis has
  to survive are exactly the ones a real panel produces, so they are in the
  script: malformed output, abstentions, fabricated packet numbers, tool
  failures and flat refusals. A harness that has only ever seen well-formed
  answers is a harness whose error paths are untested.

  Where the planned verdict comes from, and why that is not leakage: the
  MockModel is a simulator, so the seeder hands it a plan keyed by
  `call_key`. The plan travels beside the request, never inside the prompt,
  which is what a solver would see. The leak test at the prompt-rendering
  stage checks that separation independently.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..ids import sha256_hex
from ..schemas import ModelSpec, ReasonCode, Verdict
from .base import ModelRequest, ModelResult


class ScriptedBehaviour(StrEnum):
    """What the mock does for one call."""

    CORRECT = "correct"
    WRONG = "wrong"
    ABSTAIN = "abstain"
    MALFORMED = "malformed"
    FABRICATED_PACKETS = "fabricated_packets"
    TOOL_FAILURE = "tool_failure"
    REFUSAL = "refusal"


#: Default mix when the seeder does not script a call explicitly. Weighted so
#: that well-formed answers dominate but every failure path is exercised.
DEFAULT_MIX: tuple[tuple[ScriptedBehaviour, int], ...] = (
    (ScriptedBehaviour.CORRECT, 60),
    (ScriptedBehaviour.WRONG, 12),
    (ScriptedBehaviour.ABSTAIN, 12),
    (ScriptedBehaviour.FABRICATED_PACKETS, 6),
    (ScriptedBehaviour.MALFORMED, 5),
    (ScriptedBehaviour.TOOL_FAILURE, 3),
    (ScriptedBehaviour.REFUSAL, 2),
)


@dataclass(frozen=True)
class CallPlan:
    """What the simulator should do for one (run, pair, model, prompt, repeat)."""

    behaviour: ScriptedBehaviour
    verdict: Verdict = Verdict.SUPPORTED
    reason_code: ReasonCode | None = None
    condition: str = "tcp.flags.syn == 1 && tcp.flags.ack == 0"
    packets: tuple[int, ...] = (1, 2)
    packet_count: int = 100


def _weighted_pick(key: str, seed: int, mix=DEFAULT_MIX) -> ScriptedBehaviour:
    """Deterministic pick: same key and seed always give the same behaviour."""
    total = sum(weight for _, weight in mix)
    draw = int(sha256_hex(f"{seed}:{key}")[:8], 16) % total
    for behaviour, weight in mix:
        if draw < weight:
            return behaviour
        draw -= weight
    return mix[-1][0]


class MockModel:
    """A ModelAdapter that answers from a script instead of an API."""

    def __init__(
        self,
        spec: ModelSpec,
        *,
        plans: dict[str, CallPlan] | None = None,
        seed: int = 0,
        latency_ms: int = 5,
    ) -> None:
        self.spec = spec
        self.plans = plans or {}
        self.seed = seed
        self.latency_ms = latency_ms

    # -- the adapter interface -------------------------------------------

    def generate(self, request: ModelRequest) -> ModelResult:
        plan = self.plans.get(request.call_key)
        if plan is None:
            plan = CallPlan(behaviour=_weighted_pick(f"{self.spec.model_id}:{request.call_key}", self.seed))

        builder = {
            ScriptedBehaviour.CORRECT: self._correct,
            ScriptedBehaviour.WRONG: self._wrong,
            ScriptedBehaviour.ABSTAIN: self._abstain,
            ScriptedBehaviour.MALFORMED: self._malformed,
            ScriptedBehaviour.FABRICATED_PACKETS: self._fabricated,
            ScriptedBehaviour.TOOL_FAILURE: self._tool_failure,
            ScriptedBehaviour.REFUSAL: self._refusal,
        }[plan.behaviour]
        return builder(request, plan)

    # -- behaviours -------------------------------------------------------

    def _answer(self, plan: CallPlan, *, verdict: Verdict, packets: list[int], confidence: int) -> str:
        payload: dict[str, Any] = {
            "verdict": str(verdict),
            "condition": plan.condition,
            "cited_packets": packets,
            "criteria_checks": {
                "executable": True,
                "sufficient": verdict is not Verdict.NOT_VERIFIABLE,
                "minimal": True,
                "in_window": True,
                "conflict_flagged": False,
            },
            "survey": {"confidence": confidence, "uncertainty_source": "other"},
        }
        if verdict is Verdict.NOT_VERIFIABLE:
            payload["reason_code"] = str(plan.reason_code or ReasonCode.INCOMPLETE_CAPTURE)
            payload["survey"]["uncertainty_source"] = "partial_capture"
        return json.dumps(payload)

    def _tool_call(self, plan: CallPlan, *, failed: bool = False) -> list[dict[str, Any]]:
        """A model with no tool support records no tool call at all."""
        if not self.spec.supports_tools:
            return []
        call: dict[str, Any] = {"tool": "pcap_query", "arguments": {"filter": plan.condition, "limit": 50}}
        call["error" if failed else "result"] = (
            "tool error: query timed out" if failed else {"match_count": len(plan.packets), "packets": list(plan.packets)}
        )
        return [call]

    def _result(self, raw: str, plan: CallPlan, *, failed_tool: bool = False, error: str | None = None) -> ModelResult:
        return ModelResult(
            raw_text=raw,
            tool_calls=self._tool_call(plan, failed=failed_tool),
            tokens_in=len(raw) // 4 + 200,
            tokens_out=max(len(raw) // 4, 1),
            latency_ms=self.latency_ms,
            error=error,
        )

    def _correct(self, request: ModelRequest, plan: CallPlan) -> ModelResult:
        return self._result(self._answer(plan, verdict=plan.verdict, packets=list(plan.packets), confidence=4), plan)

    def _wrong(self, request: ModelRequest, plan: CallPlan) -> ModelResult:
        alternatives = [v for v in Verdict if v is not plan.verdict]
        choice = alternatives[int(sha256_hex(request.call_key)[:4], 16) % len(alternatives)]
        return self._result(self._answer(plan, verdict=choice, packets=list(plan.packets), confidence=3), plan)

    def _abstain(self, request: ModelRequest, plan: CallPlan) -> ModelResult:
        return self._result(self._answer(plan, verdict=Verdict.NOT_VERIFIABLE, packets=[], confidence=2), plan)

    def _fabricated(self, request: ModelRequest, plan: CallPlan) -> ModelResult:
        """Cites packet numbers beyond the end of the capture."""
        invented = [plan.packet_count + 17, plan.packet_count + 404]
        packets = list(plan.packets) + invented
        return self._result(self._answer(plan, verdict=plan.verdict, packets=packets, confidence=5), plan)

    def _malformed(self, request: ModelRequest, plan: CallPlan) -> ModelResult:
        """Truncated JSON wrapped in prose -- the commonest real failure."""
        raw = 'Here is my analysis:\n```json\n{"verdict": "SUPPORTED", "cited_packets": [1, 2'
        return self._result(raw, plan)

    def _tool_failure(self, request: ModelRequest, plan: CallPlan) -> ModelResult:
        raw = self._answer(
            CallPlan(plan.behaviour, plan.verdict, ReasonCode.INCOMPLETE_CAPTURE, plan.condition, plan.packets),
            verdict=Verdict.NOT_VERIFIABLE,
            packets=[],
            confidence=1,
        )
        return self._result(raw, plan, failed_tool=True, error="pcap_query failed: timeout after 30s")

    def _refusal(self, request: ModelRequest, plan: CallPlan) -> ModelResult:
        raw = "I cannot analyse network capture data for potential attack traffic."
        return self._result(raw, plan)
