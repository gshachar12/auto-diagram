"""
Every metric in spec section 9, computed from stored rows only.

  Responsibility: turn the calls of one run -- plus the derived facts the
  capture supplied in evidence.py -- into rows of `analysis_metrics`. No
  model is called here, nothing is re-asked, and every number traces back
  to call ids a reader can open.

  Rules that shaped this module:

    A family is one unit.  Two sizes of one model are not independent
      votes. Verdicts are reduced per unit (the unit is a parameter, and it
      is `family`) before any majority, agreement or correlation.
    Every rate carries n and an interval.  `MetricRow` has no shape that
      lets a bare proportion through: a value always travels with its n and
      its CI, and the accuracy figures carry a bootstrap interval that
      resamples PCAPs rather than items.
    Nothing is called correct.  The only comparison made is against an
      expected verdict fixed by construction, and it is named
      "matches expected" everywhere it surfaces.
    A number that cannot be computed is NULL with a reason.  Not 0.0, not
      an omitted row: a row with `value = None` and a `detail.reason`, so
      the dashboard can say what is missing and why.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Hashable, Sequence

from ..schemas import Verdict
from .stats import (
    cluster_bootstrap,
    double_fault,
    effective_votes,
    entropy_bits,
    eta_squared,
    fleiss_kappa,
    gwet_ac1,
    jaccard,
    majority,
    newcombe_difference,
    phi_coefficient,
    proportion,
    raw_agreement,
    wilson_interval,
)

VERDICTS: tuple[str, ...] = (str(Verdict.SUPPORTED), str(Verdict.REFUTED), str(Verdict.NOT_VERIFIABLE))


@dataclass(frozen=True)
class MetricRow:
    """One row of analysis_metrics. A value without an n is not allowed through."""

    scope: str
    scope_id: str
    metric: str
    value: float | None
    n: int | None = None
    ci_low: float | None = None
    ci_high: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def as_row(self, analysis_id: str) -> dict[str, Any]:
        return {
            "analysis_id": analysis_id,
            "scope": self.scope,
            "scope_id": self.scope_id,
            "metric": self.metric,
            "value": self.value,
            "n": self.n,
            "ci_low": self.ci_low,
            "ci_high": self.ci_high,
            "detail": json.dumps(self.detail, sort_keys=True, default=str),
        }

    def key(self) -> tuple[str, str, str]:
        return (self.scope, self.scope_id, self.metric)


def _row(scope: str, scope_id: str, metric: str, stat: dict[str, Any], **extra: Any) -> MetricRow:
    """Build a row from one of the stats helpers' dicts."""
    detail = dict(stat.get("detail") or {})
    detail.update(extra)
    if "successes" in stat:
        detail.setdefault("successes", stat["successes"])
    return MetricRow(
        scope=scope, scope_id=scope_id, metric=metric,
        value=stat.get("value"), n=stat.get("n"),
        ci_low=stat.get("ci_low"), ci_high=stat.get("ci_high"), detail=detail,
    )


def _pending(scope: str, scope_id: str, metric: str, reason: str, **extra: Any) -> MetricRow:
    """A metric that was not computed, saying so and saying why."""
    return MetricRow(scope, scope_id, metric, None, None, None, None, {"status": "pending", "reason": reason, **extra})


# -- the views the metrics are computed over -------------------------------

@dataclass(frozen=True)
class CallView:
    call_id: str
    pair_id: str
    model_id: str
    family: str
    prompt_id: str
    prompt_label: str
    dimension: str
    repeat: int
    verdict: str | None
    confidence: int | None
    format_error: bool
    tool_error: bool
    condition: str
    cited: list[int]


@dataclass(frozen=True)
class ItemView:
    pair_id: str
    pcap_id: str | None
    pair_type: str
    expected: str | None
    expected_basis: str
    level: int

    @property
    def cluster(self) -> str:
        """The bootstrap cluster: the capture, or the one no_pcap group."""
        return self.pcap_id or "no_pcap"


def expected_outcome(item: ItemView, verdict: str | None) -> bool | None:
    """
    Whether a verdict matches what construction fixed for this item.

    The one comparison this project makes, and the only place a verdict is
    judged at all. A swap is scored as "not SUPPORTED" rather than REFUTED,
    because REFUTED would assume a closed world on a capture the claim
    never came from. Anything resting on an author's claim is not a control
    and returns None, so it is never counted.
    """
    if verdict is None:
        return None
    if item.pair_type == "swap":
        return verdict != str(Verdict.SUPPORTED)
    if item.expected_basis != "construction" or not item.expected:
        return None
    return verdict == item.expected


def _mode(votes: Sequence[str]) -> str | None:
    """Deterministic modal verdict: count first, then name, so ties are stable."""
    if not votes:
        return None
    counts: dict[str, int] = defaultdict(int)
    for vote in votes:
        counts[vote] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


class MetricSet:
    """Holds one run's rows and computes everything over them."""

    def __init__(
        self,
        *,
        run_id: str,
        calls: list[CallView],
        items: dict[str, ItemView],
        facts: dict[str, Any],
        params: Any,
        reference_prompt: str | None = None,
        fact_status_counts: dict[str, int] | None = None,
    ) -> None:
        self.run_id = run_id
        self.calls = calls
        self.items = items
        self.facts = facts
        self.params = params
        self.fact_status_counts = fact_status_counts or {}
        self.unit_field = "family" if str(getattr(params, "unit", "family")) == "family" else "model_id"
        self.reference_prompt = reference_prompt

        self.by_item: dict[str, list[CallView]] = defaultdict(list)
        for call in calls:
            self.by_item[call.pair_id].append(call)

        self.unit_votes: dict[str, dict[str, str]] = {}
        for pair_id, rows in self.by_item.items():
            per_unit: dict[str, list[str]] = defaultdict(list)
            for call in rows:
                if call.verdict:
                    per_unit[self._unit(call)].append(call.verdict)
            self.unit_votes[pair_id] = {
                unit: _mode(votes) for unit, votes in sorted(per_unit.items()) if votes
            }

        self.panel: dict[str, tuple[str | None, float]] = {
            pair_id: majority(list(votes.values()), float(params.majority_threshold))
            for pair_id, votes in self.unit_votes.items()
        }
        self.units = sorted({self._unit(call) for call in calls})

    # -- helpers -----------------------------------------------------------

    def _unit(self, call: CallView) -> str:
        return call.family if self.unit_field == "family" else call.model_id

    def _z(self) -> float:
        return float(self.params.ci_z)

    def _bootstrap(self, clusters: dict[Hashable, list[bool]]) -> dict[str, Any]:
        return cluster_bootstrap(
            clusters,
            lambda rows: (sum(1 for r in rows if r) / len(rows)) if rows else None,
            resamples=int(self.params.bootstrap_resamples),
            seed=int(self.params.bootstrap_seed),
        )

    def _scored_calls(self) -> list[tuple[CallView, bool]]:
        out = []
        for call in self.calls:
            item = self.items.get(call.pair_id)
            if item is None:
                continue
            outcome = expected_outcome(item, call.verdict)
            if outcome is not None:
                out.append((call, outcome))
        return out

    # -- the metric groups --------------------------------------------------

    def compute(self) -> list[MetricRow]:
        rows: list[MetricRow] = []
        rows += self.agreement()
        rows += self.majority_metrics()
        rows += self.accuracy()
        rows += self.operational()
        rows += self.error_correlation()
        rows += self.leave_one_out()
        rows += self.prompt_effect()
        rows += self.calibration()
        rows += self.leakage()
        rows += self.evidence_metrics()
        rows += self.variance_decomposition()
        return rows

    # -- agreement ---------------------------------------------------------

    def agreement(self) -> list[MetricRow]:
        """Raw agreement, Fleiss' kappa and Gwet's AC1 over unit-level votes."""
        items = [sorted(votes.values()) for votes in self.unit_votes.values()]
        rows = [
            _row("run", self.run_id, "raw_agreement", raw_agreement(items, VERDICTS),
                 unit=self.unit_field, definition="mean share of agreeing voter pairs per item"),
            _row("run", self.run_id, "fleiss_kappa", fleiss_kappa(items, VERDICTS), unit=self.unit_field),
            _row("run", self.run_id, "gwet_ac1", gwet_ac1(items, VERDICTS), unit=self.unit_field,
                 why="reported beside kappa because kappa collapses when one verdict dominates"),
        ]
        # Pairwise agreement between units, on the items where both voted.
        for i, left in enumerate(self.units):
            for right in self.units[i + 1:]:
                both = [v for v in self.unit_votes.values() if left in v and right in v]
                same = sum(1 for v in both if v[left] == v[right])
                rows.append(
                    _row("unit_pair", f"{left}|{right}", "agreement",
                         proportion(same, len(both), self._z()), a=left, b=right)
                )
        return rows

    def majority_metrics(self) -> list[MetricRow]:
        """Majority share, the no-majority rate, and per-item vote entropy."""
        rows: list[MetricRow] = []
        shares, no_majority = [], 0
        entropies = []
        for pair_id, (verdict, share) in sorted(self.panel.items()):
            votes = self.unit_votes[pair_id]
            counts: dict[str, int] = defaultdict(int)
            for vote in votes.values():
                counts[vote] += 1
            bits = entropy_bits(counts.values())
            entropies.append(bits)
            shares.append(share)
            no_majority += int(verdict is None)
            rows.append(
                MetricRow("pair", pair_id, "vote_entropy_bits", bits, len(votes), None, None,
                          {"votes": dict(sorted(counts.items())), "panel_verdict": verdict,
                           "majority_share": share, "unit": self.unit_field})
            )
            rows.append(
                MetricRow("pair", pair_id, "majority_share", share, len(votes), None, None,
                          {"panel_verdict": verdict})
            )
        n = len(shares)
        rows.append(
            MetricRow("run", self.run_id, "majority_share_mean",
                      (sum(shares) / n) if n else None, n, None, None,
                      {"definition": "mean share of the leading verdict among unit-level votes"})
        )
        rows.append(_row("run", self.run_id, "no_majority_rate", proportion(no_majority, n, self._z()),
                         threshold=float(self.params.majority_threshold)))
        rows.append(
            MetricRow("run", self.run_id, "mean_vote_entropy_bits",
                      (sum(entropies) / len(entropies)) if entropies else None, len(entropies))
        )
        return rows

    # -- accuracy on controls ----------------------------------------------

    def accuracy(self) -> list[MetricRow]:
        """
        Matches-expected rates on construction-based items, per model, per
        family and for the majority, each with a bootstrap CI by PCAP.
        """
        rows: list[MetricRow] = []
        scored = self._scored_calls()

        def clusters_for(filter_fn) -> dict[Hashable, list[bool]]:
            buckets: dict[Hashable, list[bool]] = defaultdict(list)
            for call, outcome in scored:
                if filter_fn(call):
                    buckets[self.items[call.pair_id].cluster].append(outcome)
            return buckets

        for scope, key in (("model", lambda c: c.model_id), ("family", lambda c: c.family)):
            names = sorted({key(call) for call, _ in scored})
            for name in names:
                buckets = clusters_for(lambda c, n=name, k=key: k(c) == n)
                stat = self._bootstrap(buckets)
                rows.append(
                    _row(scope, name, "matches_expected_rate", stat,
                         low_n=stat["n"] < int(self.params.min_items_for_rate),
                         wording="matches an expected verdict fixed by construction; not an accuracy against truth")
                )

        # The majority's own rate: one outcome per item, not per call.
        item_buckets: dict[Hashable, list[bool]] = defaultdict(list)
        for pair_id, (verdict, _) in sorted(self.panel.items()):
            item = self.items.get(pair_id)
            if item is None:
                continue
            outcome = expected_outcome(item, verdict)
            if outcome is not None:
                item_buckets[item.cluster].append(outcome)
        rows.append(
            _row("run", self.run_id, "majority_matches_expected_rate", self._bootstrap(item_buckets),
                 unit=self.unit_field)
        )

        # And by pair type, which is how the controls view reads it.
        by_type: dict[str, dict[Hashable, list[bool]]] = defaultdict(lambda: defaultdict(list))
        for pair_id, (verdict, _) in sorted(self.panel.items()):
            item = self.items.get(pair_id)
            if item is None:
                continue
            outcome = expected_outcome(item, verdict)
            if outcome is not None:
                by_type[item.pair_type][item.cluster].append(outcome)
        for pair_type, buckets in sorted(by_type.items()):
            rows.append(_row("pair_type", pair_type, "majority_matches_expected_rate", self._bootstrap(buckets)))
        return rows

    # -- operational --------------------------------------------------------

    def operational(self) -> list[MetricRow]:
        """Format errors, abstentions, tool failures and self-consistency."""
        rows: list[MetricRow] = []

        def block(scope: str, scope_id: str, calls: list[CallView]) -> list[MetricRow]:
            total = len(calls)
            out = [
                _row(scope, scope_id, "format_error_rate",
                     proportion(sum(1 for c in calls if c.format_error), total, self._z())),
                _row(scope, scope_id, "not_verifiable_rate",
                     proportion(sum(1 for c in calls if c.verdict == str(Verdict.NOT_VERIFIABLE)), total, self._z()),
                     definition="share of all calls, including those that failed to answer"),
                _row(scope, scope_id, "tool_failure_rate",
                     proportion(sum(1 for c in calls if c.tool_error), total, self._z())),
            ]
            # Self-consistency: the repeats of one (item, model, prompt).
            groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
            for call in calls:
                if call.verdict:
                    groups[(call.pair_id, call.model_id, call.prompt_id)].append(call.verdict)
            comparable = [g for g in groups.values() if len(g) > 1]
            consistent = sum(1 for g in comparable if len(set(g)) == 1)
            out.append(
                _row(scope, scope_id, "self_consistency", proportion(consistent, len(comparable), self._z()),
                     definition="repeats of the same item, model and prompt giving the same verdict")
            )
            return out

        rows += block("run", self.run_id, self.calls)
        by_model: dict[str, list[CallView]] = defaultdict(list)
        by_family: dict[str, list[CallView]] = defaultdict(list)
        for call in self.calls:
            by_model[call.model_id].append(call)
            by_family[call.family].append(call)
        for model_id, calls in sorted(by_model.items()):
            rows += block("model", model_id, calls)
        for family, calls in sorted(by_family.items()):
            rows += block("family", family, calls)
        return rows

    # -- error correlation --------------------------------------------------

    def error_correlation(self) -> list[MetricRow]:
        """
        Phi and double-fault between every pair of units, and the effective
        number of votes that follows from their mean correlation.
        """
        rows: list[MetricRow] = []
        # One error indicator per (unit, scored item): did its vote differ
        # from the expected verdict? Reduced per unit first, as everywhere.
        errors: dict[str, dict[str, bool]] = defaultdict(dict)
        for pair_id, votes in sorted(self.unit_votes.items()):
            item = self.items.get(pair_id)
            if item is None:
                continue
            for unit, verdict in votes.items():
                outcome = expected_outcome(item, verdict)
                if outcome is not None:
                    errors[unit][pair_id] = not outcome

        phis: list[float] = []
        for i, left in enumerate(self.units):
            for right in self.units[i + 1:]:
                shared = sorted(set(errors.get(left, {})) & set(errors.get(right, {})))
                pairs = [(errors[left][p], errors[right][p]) for p in shared]
                phi = phi_coefficient(pairs)
                rows.append(_row("unit_pair", f"{left}|{right}", "error_phi", phi, a=left, b=right))
                rows.append(_row("unit_pair", f"{left}|{right}", "double_fault", double_fault(pairs), a=left, b=right))
                if phi["value"] is not None:
                    phis.append(phi["value"])

        mean_phi = (sum(phis) / len(phis)) if phis else None
        rows.append(
            MetricRow("run", self.run_id, "mean_error_correlation", mean_phi, len(phis), None, None,
                      {"definition": "mean phi over unit pairs where it is defined",
                       "undefined_pairs": (len(self.units) * (len(self.units) - 1)) // 2 - len(phis)})
        )
        rows.append(
            _row("run", self.run_id, "effective_votes", effective_votes(len(self.units), mean_phi),
                 unit=self.unit_field, voters=len(self.units))
        )
        return rows

    def leave_one_out(self) -> list[MetricRow]:
        """How often the majority changes when one unit is taken out."""
        rows: list[MetricRow] = []
        threshold = float(self.params.majority_threshold)
        for unit in self.units:
            changed = n = 0
            examples: list[str] = []
            for pair_id, votes in sorted(self.unit_votes.items()):
                if unit not in votes:
                    continue
                n += 1
                without = majority([v for u, v in votes.items() if u != unit], threshold)[0]
                if without != self.panel[pair_id][0]:
                    changed += 1
                    if len(examples) < 5:
                        examples.append(pair_id)
            rows.append(
                _row("unit", unit, "leave_one_out_majority_change_rate", proportion(changed, n, self._z()),
                     examples=examples,
                     definition="items whose majority verdict differs once this unit's vote is removed")
            )
        return rows

    # -- prompts -------------------------------------------------------------

    def prompt_effect(self) -> list[MetricRow]:
        """Flip rates, the per-dimension effect, and the position-bias gap."""
        rows: list[MetricRow] = []

        # Flip between repeats (the sampling-noise floor) and between prompts.
        repeat_groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        prompt_groups: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for call in self.calls:
            if not call.verdict:
                continue
            repeat_groups[(call.pair_id, call.model_id, call.prompt_id)].append(call.verdict)
            prompt_groups[(call.pair_id, call.model_id)][call.prompt_id].append(call.verdict)

        repeat_comparable = [g for g in repeat_groups.values() if len(g) > 1]
        repeat_flips = sum(1 for g in repeat_comparable if len(set(g)) > 1)
        prompt_comparable = prompt_flips = 0
        for prompts in prompt_groups.values():
            modal = [_mode(v) for v in prompts.values() if v]
            if len(modal) > 1:
                prompt_comparable += 1
                prompt_flips += int(len(set(modal)) > 1)

        rows.append(_row("run", self.run_id, "repeat_flip_rate",
                         proportion(repeat_flips, len(repeat_comparable), self._z()),
                         definition="same item, model and prompt, different repeats"))
        rows.append(_row("run", self.run_id, "prompt_flip_rate",
                         proportion(prompt_flips, prompt_comparable, self._z()),
                         definition="same item and model, different prompt variants"))
        rows.append(
            _row("run", self.run_id, "prompt_flip_rate_excess",
                 newcombe_difference(prompt_flips, prompt_comparable, repeat_flips, len(repeat_comparable), self._z()),
                 definition="prompt flip rate minus the repeat flip rate (the noise floor)",
                 method="Newcombe hybrid-score interval for a difference of proportions")
        )

        # The equivalence judgement, which is only possible with a margin
        # that was fixed before the run.
        margin = self.params.equivalence_margin_flip_rate
        excess = (prompt_flips / prompt_comparable - (repeat_flips / len(repeat_comparable))
                  if prompt_comparable and repeat_comparable else None)
        if margin is None or excess is None:
            rows.append(
                _pending("run", self.run_id, "prompt_effect_within_margin",
                         "the equivalence margin is still UNSET in the configuration; it has to be fixed "
                         "before a run, because choosing it afterwards decides the conclusion"
                         if margin is None else "not enough comparable items to judge equivalence")
            )
        else:
            rows.append(
                MetricRow("run", self.run_id, "prompt_effect_within_margin", float(excess <= margin),
                          prompt_comparable, None, None,
                          {"margin": margin, "excess_flip_rate": excess,
                           "caveat": "a 'no prompt effect' claim cannot be proved; this only says the "
                                     "measured excess is within the pre-registered margin"})
            )

        # Per variant and per dimension, against a reference variant.
        by_prompt: dict[str, list[CallView]] = defaultdict(list)
        for call in self.calls:
            by_prompt[call.prompt_id].append(call)
        reference = self.reference_prompt
        for prompt_id, calls in sorted(by_prompt.items()):
            answered = [c for c in calls if c.verdict]
            label = calls[0].prompt_label
            dimension = calls[0].dimension
            rows.append(
                _row("prompt", prompt_id, "supported_rate",
                     proportion(sum(1 for c in answered if c.verdict == str(Verdict.SUPPORTED)),
                                len(answered), self._z()),
                     label=label, dimension=dimension)
            )
            rows.append(
                _row("prompt", prompt_id, "not_verifiable_rate",
                     proportion(sum(1 for c in answered if c.verdict == str(Verdict.NOT_VERIFIABLE)),
                                len(answered), self._z()),
                     label=label, dimension=dimension)
            )
            rows.append(
                _row("prompt", prompt_id, "format_error_rate",
                     proportion(sum(1 for c in calls if c.format_error), len(calls), self._z()),
                     label=label, dimension=dimension)
            )

        rows += self._dimension_effects(prompt_groups, by_prompt, reference)
        return rows

    def _dimension_effects(
        self,
        prompt_groups: dict[tuple[str, str], dict[str, list[str]]],
        by_prompt: dict[str, list[CallView]],
        reference: str | None,
    ) -> list[MetricRow]:
        """Flip rate against the reference variant, per variant and per dimension."""
        rows: list[MetricRow] = []
        if reference is None or reference not in by_prompt:
            return [
                _pending("run", self.run_id, "prompt_dimension_effect",
                         "this run has no reference prompt variant to compare the others against")
            ]
        reference_label = by_prompt[reference][0].prompt_label

        per_dimension: dict[str, list[bool]] = defaultdict(list)
        per_prompt: dict[str, list[bool]] = defaultdict(list)
        for prompts in prompt_groups.values():
            base_votes = prompts.get(reference)
            if not base_votes:
                continue
            base = _mode(base_votes)
            for prompt_id, votes in prompts.items():
                if prompt_id == reference or not votes:
                    continue
                flipped = _mode(votes) != base
                per_prompt[prompt_id].append(flipped)
                per_dimension[by_prompt[prompt_id][0].dimension].append(flipped)

        for prompt_id, flips in sorted(per_prompt.items()):
            rows.append(
                _row("prompt", prompt_id, "flip_rate_vs_reference",
                     proportion(sum(flips), len(flips), self._z()),
                     reference=reference_label, label=by_prompt[prompt_id][0].prompt_label,
                     dimension=by_prompt[prompt_id][0].dimension)
            )
        for dimension, flips in sorted(per_dimension.items()):
            rows.append(
                _row("dimension", dimension, "flip_rate_vs_reference",
                     proportion(sum(flips), len(flips), self._z()), reference=reference_label)
            )

        # Position bias: the label-order variant against the reference, on
        # the share of SUPPORTED answers. The dimension's whole purpose.
        order_prompts = [p for p, calls in by_prompt.items() if calls[0].dimension == "label_order"]
        if not order_prompts:
            rows.append(
                _pending("run", self.run_id, "position_bias_gap",
                         "no variant in this run changes the order of the verdict labels, so position "
                         "bias cannot be measured from it")
            )
            return rows
        base_answered = [c for c in by_prompt[reference] if c.verdict]
        for prompt_id in sorted(order_prompts):
            answered = [c for c in by_prompt[prompt_id] if c.verdict]
            rows.append(
                _row("run", self.run_id, "position_bias_gap",
                     newcombe_difference(
                         sum(1 for c in answered if c.verdict == str(Verdict.SUPPORTED)), len(answered),
                         sum(1 for c in base_answered if c.verdict == str(Verdict.SUPPORTED)), len(base_answered),
                         self._z()),
                     variant=by_prompt[prompt_id][0].prompt_label, reference=reference_label,
                     definition="SUPPORTED rate with the labels reordered, minus the reference variant's")
            )
        return rows

    # -- calibration and leakage --------------------------------------------

    def calibration(self) -> list[MetricRow]:
        """Reported confidence against matches-expected, on control items."""
        rows: list[MetricRow] = []
        buckets: dict[int, list[bool]] = defaultdict(list)
        for call, outcome in self._scored_calls():
            if call.confidence is not None:
                buckets[int(call.confidence)].append(outcome)
        levels = range(1, int(self.params.confidence_levels) + 1)
        for level in levels:
            outcomes = buckets.get(level, [])
            rows.append(
                _row("confidence_bin", str(level), "matches_expected_rate",
                     proportion(sum(1 for o in outcomes if o), len(outcomes), self._z()),
                     confidence=level, scale=f"1..{int(self.params.confidence_levels)}",
                     low_n=len(outcomes) < int(self.params.min_items_for_rate))
            )
        return rows

    def leakage(self) -> list[MetricRow]:
        """SUPPORTED on an item with no capture at all."""
        no_pcap = [pair_id for pair_id, item in self.items.items() if item.pair_type == "no_pcap"]
        supported = sum(1 for pair_id in no_pcap
                        if self.panel.get(pair_id, (None, 0.0))[0] == str(Verdict.SUPPORTED))
        call_level = [c for c in self.calls if self.items.get(c.pair_id) and
                      self.items[c.pair_id].pair_type == "no_pcap" and c.verdict]
        return [
            _row("run", self.run_id, "no_pcap_supported_rate",
                 proportion(supported, len(no_pcap), self._z()),
                 unit="panel majority over items",
                 definition="SUPPORTED without a capture indicates the claim was recognised, not verified"),
            _row("run", self.run_id, "no_pcap_supported_rate_by_call",
                 proportion(sum(1 for c in call_level if c.verdict == str(Verdict.SUPPORTED)),
                            len(call_level), self._z())),
        ]

    # -- evidence quality ----------------------------------------------------

    def evidence_metrics(self) -> list[MetricRow]:
        """
        Everything that needed the capture: fabrication, verification,
        sufficiency, necessity, and the Jaccard of re-executed packet sets.
        """
        rows: list[MetricRow] = []
        facts = self.facts
        usable = [f for f in facts.values() if f.status == "ok"]
        rows.append(
            _row("run", self.run_id, "reexecution_coverage",
                 proportion(len(usable), len(facts), self._z()),
                 by_status=dict(sorted(self.fact_status_counts.items())),
                 definition="calls whose condition was actually re-executed against the capture")
        )
        if not facts:
            return rows + [
                _pending("run", self.run_id, "evidence_quality",
                         "no call facts were computed for this run")
            ]

        with_citation = [f for f in facts.values() if f.fabricated_count is not None
                         and (f.cited_verified or f.cited_unverified or f.fabricated_count)]
        cited_total = sum(len(f.cited_verified) + len(f.cited_unverified) for f in usable)
        verified_total = sum(len(f.cited_verified) for f in usable)
        fabricated_packets = sum(f.fabricated_count or 0 for f in facts.values() if f.fabricated_count is not None)
        countable = [f for f in facts.values() if f.fabricated_count is not None]
        cited_any = [f for f in countable if f.fabricated_count or f.cited_verified or f.cited_unverified]

        rows.append(
            _row("run", self.run_id, "fabricated_packet_call_rate",
                 proportion(sum(1 for f in countable if (f.fabricated_count or 0) > 0), len(countable), self._z()),
                 definition="calls citing at least one packet number beyond the end of the capture",
                 fabricated_packets=fabricated_packets, calls_citing_packets=len(cited_any))
        )
        rows.append(
            _row("run", self.run_id, "cited_and_verified_rate",
                 proportion(verified_total, cited_total, self._z()),
                 definition="cited packets that satisfy the model's own condition, per packet",
                 note="counted only over calls whose condition was re-executed")
        )
        rows.append(
            _row("run", self.run_id, "cited_unverified_rate",
                 proportion(cited_total - verified_total, cited_total, self._z()),
                 definition="cited packets that do not satisfy the model's own condition")
        )
        for name, attribute in (("sufficiency_pass_rate", "sufficiency_ok"), ("necessity_pass_rate", "necessity_ok")):
            judged = [getattr(f, attribute) for f in facts.values() if getattr(f, attribute) is not None]
            rows.append(
                _row("run", self.run_id, name, proportion(sum(1 for v in judged if v), len(judged), self._z()),
                     definition=("the cited packets alone give the same verdict"
                                 if attribute == "sufficiency_ok"
                                 else "removing the cited packets flips the verdict"),
                     not_applicable=len(facts) - len(judged))
            )

        rows += self._evidence_jaccard()
        return rows

    def _evidence_jaccard(self) -> list[MetricRow]:
        """Jaccard of the re-executed packet sets between pairs of models."""
        rows: list[MetricRow] = []
        sets: dict[str, dict[str, set[int]]] = defaultdict(dict)  # item -> model -> packets
        for call in self.calls:
            fact = self.facts.get(call.call_id)
            if fact is None or fact.status != "ok" or fact.reexecuted_count is None:
                continue
            sets[call.pair_id].setdefault(call.model_id, set()).update(fact.reexecuted_packets)

        models = sorted({m for per_item in sets.values() for m in per_item})
        all_scores: list[float] = []
        for i, left in enumerate(models):
            for right in models[i + 1:]:
                scores = [
                    value for per_item in sets.values()
                    if left in per_item and right in per_item
                    for value in [jaccard(per_item[left], per_item[right])]
                    if value is not None
                ]
                all_scores += scores
                rows.append(
                    MetricRow("model_pair", f"{left}|{right}", "evidence_jaccard",
                              (sum(scores) / len(scores)) if scores else None, len(scores), None, None,
                              {"a": left, "b": right,
                               "definition": "mean Jaccard of the packet sets their conditions actually match",
                               "truncation_note": "packet sets are capped by the analysis re-execution limit"})
                )
        rows.append(
            MetricRow("run", self.run_id, "evidence_jaccard_mean",
                      (sum(all_scores) / len(all_scores)) if all_scores else None, len(all_scores), None, None,
                      {"definition": "mean over all model pairs and items where both re-executions succeeded"})
        )
        return rows

    # -- variance ------------------------------------------------------------

    def variance_decomposition(self) -> list[MetricRow]:
        """
        Where the variation in the answers sits.

        An honest, dependency-free version of what the spec asks for: the
        share of the total variance of one binary outcome -- "answered
        SUPPORTED" -- that lies between the groups of each factor. It is
        eta-squared from a one-way split, not a mixed-effects fit, so the
        shares do not add to one and an item carries its PCAP's effect
        inside it. Both caveats are stored with every row. A verdict with
        three unordered categories has no numeric scale, which is why the
        decomposition is of an indicator rather than of "the verdict".
        """
        answered = [c for c in self.calls if c.verdict]
        if len(answered) < 2:
            return [_pending("factor", "all", "variance_explained_eta2", "too few answered calls")]
        values = [1.0 if c.verdict == str(Verdict.SUPPORTED) else 0.0 for c in answered]
        factors: dict[str, list[Hashable]] = {
            "item": [c.pair_id for c in answered],
            "pcap": [self.items[c.pair_id].cluster if c.pair_id in self.items else "?" for c in answered],
            "model": [c.model_id for c in answered],
            "family": [c.family for c in answered],
            "prompt": [c.prompt_id for c in answered],
            "prompt_dimension": [c.dimension for c in answered],
            "model_x_prompt": [(c.model_id, c.prompt_id) for c in answered],
            "repeat": [c.repeat for c in answered],
        }
        rows = []
        for name, groups in factors.items():
            rows.append(
                _row("factor", name, "variance_explained_eta2", eta_squared(values, groups),
                     outcome="answered SUPPORTED (1/0)",
                     caveat="eta-squared per factor, not a mixed-effects variance component; crossed "
                            "factors overlap and the shares do not sum to one")
            )
        return rows


def fragile_items(run_id: str, calls: list[CallView], params: Any) -> list[MetricRow]:
    """
    Items whose majority verdict changes across prompt variants.

    Separated from MetricSet because it is a property of an item rather
    than of the panel, and because it is what the dashboard's FRAGILE flag
    is: a label that must not be relied on, however confident the models
    sounded.
    """
    by_item_prompt: dict[str, dict[str, dict[str, list[str]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    unit = "family" if str(getattr(params, "unit", "family")) == "family" else "model_id"
    for call in calls:
        if call.verdict:
            key = call.family if unit == "family" else call.model_id
            by_item_prompt[call.pair_id][call.prompt_id][key].append(call.verdict)

    rows: list[MetricRow] = []
    fragile = 0
    for pair_id, per_prompt in sorted(by_item_prompt.items()):
        verdicts = set()
        for votes in per_prompt.values():
            per_unit = [_mode(v) for v in votes.values() if v]
            verdict = majority(per_unit, float(params.majority_threshold))[0]
            if verdict is not None:
                verdicts.add(verdict)
        is_fragile = len(verdicts) > 1
        fragile += int(is_fragile)
        rows.append(
            MetricRow("pair", pair_id, "fragile", float(is_fragile), len(per_prompt), None, None,
                      {"majority_by_prompt": sorted(verdicts),
                       "meaning": "the majority verdict changes with the prompt, so this label is not reliable"})
        )
    low, high = wilson_interval(fragile, len(by_item_prompt), float(params.ci_z))
    rows.append(
        MetricRow("run", run_id, "fragile_item_rate",
                  (fragile / len(by_item_prompt)) if by_item_prompt else None,
                  len(by_item_prompt), low if by_item_prompt else None, high if by_item_prompt else None,
                  {"definition": "items whose majority verdict changes between prompt variants"})
    )
    return rows
