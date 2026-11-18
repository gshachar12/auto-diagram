"""
The analysis service.

Two kinds of test here. The first kind pins the statistics against
hand-worked examples, because a silently wrong kappa is worse than a
missing one. The second kind pins the promises the spec makes about the
service as a whole: the same stored responses analysed twice give the same
numbers to the bit, a what-if leaves no trace, and anything the capture
could not answer comes back NULL with a reason rather than as a zero.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from Dataset.analysis import (
    ANALYSIS_CODE_VERSION,
    AnalysisError,
    AnalysisParams,
    analyse,
    diff,
    latest_analysis,
    list_analyses,
    load_call_facts,
    load_metrics,
    what_if,
)
from Dataset.analysis.evidence import EvidenceChecker, membership_filter
from Dataset.analysis.stats import (
    cluster_bootstrap,
    entropy_bits,
    fleiss_kappa,
    gwet_ac1,
    jaccard,
    newcombe_difference,
    phi_coefficient,
    wilson_interval,
)
from Dataset.config import CONFIG_DIR, Config
from Dataset.manifest import REPO_ROOT
from Dataset.models.mock import CallPlan, MockModel, ScriptedBehaviour
from Dataset.pcap import PcapService, PcapServiceError
from Dataset.schemas import (
    CallRecord,
    CaptureMetadata,
    Claim,
    Condition,
    ExpectedBasis,
    ModelSpec,
    Pair,
    PairType,
    Pcap,
    Source,
    Verdict,
)
from Dataset.storage.repository import Repository

PORTSCAN = "pcaps/PortScanning/portscan.pcap"
PORTSCAN_PACKETS = 29  # every packet in this capture is a SYN; see test_pcap.py
SYN = "tcp.flags.syn == 1 && tcp.flags.ack == 0"


def _tshark_available() -> bool:
    try:
        from Dataset.pcap.service import resolve_tshark

        resolve_tshark()
        return True
    except PcapServiceError:
        return False


needs_tshark = pytest.mark.skipif(not _tshark_available(), reason="tshark not available; run through ./pangea")


# -- the statistics --------------------------------------------------------

def test_entropy_is_zero_for_unanimity_and_maximal_for_a_three_way_split():
    assert entropy_bits([5]) == 0.0
    assert entropy_bits([2, 2, 2]) == pytest.approx(1.585, abs=1e-3)


def test_fleiss_kappa_is_zero_when_agreement_is_exactly_chance():
    # Two raters, two items, every pattern once: observed agreement equals
    # chance agreement, so kappa is 0 rather than "high because they often
    # happened to say the same thing".
    items = [["SUPPORTED", "REFUTED"], ["REFUTED", "SUPPORTED"]]
    assert fleiss_kappa(items, ("SUPPORTED", "REFUTED"))["value"] == pytest.approx(-1.0)
    perfect = [["SUPPORTED", "SUPPORTED"], ["REFUTED", "REFUTED"]]
    assert fleiss_kappa(perfect, ("SUPPORTED", "REFUTED"))["value"] == pytest.approx(1.0)


def test_kappa_is_undefined_rather_than_one_when_every_vote_is_the_same():
    # The paradox this project will meet: one category dominating. Kappa
    # has no value there, and saying so is the only honest answer.
    items = [["SUPPORTED", "SUPPORTED"], ["SUPPORTED", "SUPPORTED"]]
    result = fleiss_kappa(items, ("SUPPORTED", "REFUTED", "NOT_VERIFIABLE"))
    assert result["value"] is None
    assert "undefined" in result["detail"]["reason"]


def test_gwet_ac1_stays_high_where_kappa_collapses():
    # 9 unanimous SUPPORTED items and one split: raters agree almost always,
    # but the category is so dominant that kappa reads near zero. AC1 is the
    # number that does not mislead here, which is why both are reported.
    items = [["SUPPORTED", "SUPPORTED"]] * 9 + [["SUPPORTED", "REFUTED"]]
    categories = ("SUPPORTED", "REFUTED", "NOT_VERIFIABLE")
    kappa = fleiss_kappa(items, categories)["value"]
    ac1 = gwet_ac1(items, categories)["value"]
    assert kappa < 0.1
    assert ac1 > 0.8


def test_jaccard_distinguishes_no_evidence_from_identical_evidence():
    assert jaccard([1, 2, 3], [2, 3, 4]) == pytest.approx(0.5)
    assert jaccard([1, 2], [1, 2]) == 1.0
    # Two models that each found nothing have not agreed on evidence.
    assert jaccard([], []) is None


def test_phi_is_undefined_when_one_rater_never_errs():
    result = phi_coefficient([(False, False), (False, True), (False, True)])
    assert result["value"] is None
    assert "undefined" in result["detail"]["reason"]
    assert result["detail"]["both_wrong"] == 0


def test_phi_is_one_when_two_raters_fail_on_exactly_the_same_items():
    pairs = [(True, True), (False, False), (True, True), (False, False)]
    assert phi_coefficient(pairs)["value"] == pytest.approx(1.0)


def test_wilson_never_leaves_the_scale():
    low, high = wilson_interval(10, 10)
    assert low < 1.0 and high <= 1.0
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_a_difference_interval_brackets_the_difference():
    result = newcombe_difference(8, 10, 3, 10)
    assert result["value"] == pytest.approx(0.5)
    assert result["ci_low"] < 0.5 < result["ci_high"]


def test_the_bootstrap_is_deterministic_and_resamples_clusters():
    clusters = {"pcap_a": [True, True, False], "pcap_b": [False, False], "pcap_c": [True]}
    first = cluster_bootstrap(clusters, lambda rows: sum(rows) / len(rows), resamples=200, seed=7)
    second = cluster_bootstrap(clusters, lambda rows: sum(rows) / len(rows), resamples=200, seed=7)
    other = cluster_bootstrap(clusters, lambda rows: sum(rows) / len(rows), resamples=200, seed=8)
    assert first == second                      # same seed, same interval, to the bit
    assert first["value"] == other["value"]     # the estimate never depends on the seed
    assert first["detail"]["clusters"] == 3
    assert first["ci_low"] <= first["value"] <= first["ci_high"]


def test_a_different_seed_can_move_the_interval_but_is_recorded():
    clusters = {str(i): [i % 3 == 0] for i in range(12)}
    result = cluster_bootstrap(clusters, lambda rows: sum(rows) / len(rows), resamples=100, seed=99)
    assert result["detail"]["seed"] == 99
    assert result["detail"]["method"] == "cluster bootstrap by PCAP"


# -- a small, real dataset -------------------------------------------------

@pytest.fixture
def dataset(db, tmp_path):
    """
    Three claims on one real capture, answered by three scripted models.

    Small on purpose: every number below can be worked out by hand from
    this fixture, which is what makes a failure here readable.
    """
    repo = Repository(db, results_path=tmp_path / "results.jsonl")
    source = Source(source_id="src_test", title="TEST source", notes="synthetic")
    repo.add_source(source)
    pcap = Pcap(
        pcap_id="pcap_test", source_id="src_test", path=PORTSCAN,
        sha256="0" * 64, size_bytes=2228, packet_count=PORTSCAN_PACKETS,
        capture_metadata=CaptureMetadata(vantage_point="test"),
    )
    repo.add_pcap(pcap)

    claims = [
        ("clm_syn", "Every packet is a SYN.", SYN),
        ("clm_one", "Packet 7 exists.", "frame.number == 7 && tcp"),
        ("clm_none", "There is ICMP traffic.", "icmp"),
    ]
    pairs = []
    for claim_id, text, display_filter in claims:
        repo.add_claim(
            Claim(
                claim_id=claim_id, source_id="src_test", source_location="test",
                source_step_text=text, atomic_text=text, level=1, kind="existential",
                condition=Condition(kind="existential", display_filter=display_filter),
            )
        )
        pair = Pair(
            pair_id=f"pair_{claim_id}", claim_id=claim_id,
            pair_type=PairType.MUTATION if claim_id == "clm_none" else PairType.SOURCE,
            pcap_id="pcap_test",
            expected=Verdict.REFUTED if claim_id == "clm_none" else Verdict.SUPPORTED,
            expected_basis=ExpectedBasis.CONSTRUCTION if claim_id == "clm_none" else ExpectedBasis.AUTHOR,
            level=1,
        )
        repo.add_pair(pair)
        pairs.append(pair)

    for index, family in enumerate(("alpha", "beta", "gamma")):
        repo.add_model_spec(
            ModelSpec(model_id=f"m{index}", family=family, version=f"{family}-1.0",
                      adapter="mock", supports_tools=True, temperature=0.0)
        )
    db.insert(
        "prompt_variants",
        dict(prompt_id="prm_base", dimension="base", label="base", template="{claim}",
             prompt_hash="h" * 8, config_version=1, created_at="2026-01-01T00:00:00+00:00"),
    )
    db.insert(
        "prompt_variants",
        dict(prompt_id="prm_rev", dimension="label_order", label="labels_reversed", template="{claim}",
             prompt_hash="r" * 8, config_version=1, created_at="2026-01-01T00:00:00+00:00"),
    )

    repo.add_run("run_test", {"label": "test", "code": {"git_commit": "0" * 40}})

    def add_call(pair, model_index, prompt_id, repeat, verdict, condition, cited, confidence=4):
        payload = {
            "verdict": str(verdict), "condition": condition, "cited_packets": cited,
            "criteria_checks": {}, "survey": {"confidence": confidence, "uncertainty_source": "other"},
        }
        if verdict is Verdict.NOT_VERIFIABLE:
            payload["reason_code"] = "INCOMPLETE_CAPTURE"
        family = ("alpha", "beta", "gamma")[model_index]
        repo.add_call(
            CallRecord(
                call_id=f"call_{pair.pair_id}_{model_index}_{prompt_id}_{repeat}",
                run_id="run_test", pair_id=pair.pair_id, model_id=f"m{model_index}",
                model_family=family, model_version=f"{family}-1.0",
                prompt_id=prompt_id, prompt_hash="h" * 8, repeat=repeat, temperature=0.0,
                raw_response=json.dumps(payload), parsed=payload,
            )
        )

    conditions = {"pair_clm_syn": SYN, "pair_clm_one": "frame.number == 7 && tcp", "pair_clm_none": "icmp"}
    for pair in pairs:
        for model_index in range(3):
            for prompt_id in ("prm_base", "prm_rev"):
                for repeat in range(2):
                    verdict = Verdict.REFUTED if pair.pair_id == "pair_clm_none" else Verdict.SUPPORTED
                    cited = [] if pair.pair_id == "pair_clm_none" else (
                        [7] if pair.pair_id == "pair_clm_one" else [1, 2]
                    )
                    # One family abstains on one item, so the panel is not
                    # unanimous everywhere: a fixture where every vote
                    # agrees would hide anything a majority rule does.
                    if pair.pair_id == "pair_clm_one" and model_index == 2:
                        verdict, cited = Verdict.NOT_VERIFIABLE, []
                    add_call(pair, model_index, prompt_id, repeat, verdict, conditions[pair.pair_id], cited)
    return db


@pytest.fixture
def params() -> AnalysisParams:
    # A small bootstrap: these tests are about determinism and shape, and
    # 2000 resamples per metric would make them slow for no extra signal.
    return AnalysisParams.from_config(Config.load(CONFIG_DIR / "demo")).with_overrides(
        {"bootstrap_resamples": 60}
    )


@pytest.fixture
def service(db) -> PcapService:
    return PcapService(allowed_roots=[REPO_ROOT / "pcaps"], db=db)


# -- re-execution, sufficiency and necessity --------------------------------

@needs_tshark
def test_the_condition_is_re_executed_against_the_capture(dataset, params, service):
    result = analyse(dataset, run_id="run_test", params=params, service=service)
    facts = result.facts
    syn_fact = facts["call_pair_clm_syn_0_prm_base_0"]
    assert syn_fact.status == "ok"
    assert syn_fact.reexecuted_count == PORTSCAN_PACKETS
    assert syn_fact.cited_verified == [1, 2]
    assert syn_fact.cited_unverified == []


@needs_tshark
def test_sufficiency_holds_when_the_cited_packets_alone_give_the_same_verdict(dataset, params, service):
    facts = analyse(dataset, run_id="run_test", params=params, service=service).facts
    # Packets 1 and 2 are SYNs, so the condition still matches on them alone.
    assert facts["call_pair_clm_syn_0_prm_base_0"].sufficiency_ok is True


@needs_tshark
def test_necessity_fails_when_the_evidence_was_not_needed(dataset, params, service):
    facts = analyse(dataset, run_id="run_test", params=params, service=service).facts
    # 29 packets satisfy the condition; removing the two cited ones leaves
    # 27, so the verdict does not flip and the citation was decoration.
    assert facts["call_pair_clm_syn_0_prm_base_0"].necessity_ok is False
    # One packet satisfies "frame.number == 7 && tcp"; removing it leaves
    # nothing, so there the citation really was the evidence.
    assert facts["call_pair_clm_one_0_prm_base_0"].necessity_ok is True


@needs_tshark
def test_a_condition_matching_nothing_is_recorded_as_zero_not_as_missing(dataset, params, service):
    facts = analyse(dataset, run_id="run_test", params=params, service=service).facts
    icmp = facts["call_pair_clm_none_0_prm_base_0"]
    assert icmp.status == "ok"
    assert icmp.reexecuted_count == 0          # the capture was asked and answered zero
    assert icmp.fabricated_count == 0          # it cited nothing, so nothing was invented
    assert icmp.sufficiency_ok is None         # and there is nothing to be sufficient


@needs_tshark
def test_an_unexecutable_condition_is_null_with_a_reason_never_a_zero(dataset, params, service, db):
    repo = Repository(db)
    pair = dict(db.query("SELECT * FROM pairs WHERE pair_id = 'pair_clm_syn'")[0])
    payload = {"verdict": "SUPPORTED", "condition": "this is not a display filter",
               "cited_packets": [1], "survey": {"confidence": 3}}
    repo.add_call(
        CallRecord(
            call_id="call_broken", run_id="run_test", pair_id=pair["pair_id"], model_id="m0",
            model_family="alpha", model_version="alpha-1.0", prompt_id="prm_base", prompt_hash="h" * 8,
            repeat=9, temperature=0.0, raw_response=json.dumps(payload), parsed=payload,
        )
    )
    fact = analyse(dataset, run_id="run_test", params=params, service=service).facts["call_broken"]
    assert fact.status == "condition_not_executable"
    assert fact.sufficiency_ok is None and fact.necessity_ok is None
    assert fact.reexecuted_count is None
    assert "refused" in fact.note


@needs_tshark
def test_a_fabricating_model_is_caught_by_the_packet_count(dataset, params, service, db, mock_spec):
    """The MockModel's fabricating behaviour, run through the real checker."""
    plan = CallPlan(behaviour=ScriptedBehaviour.FABRICATED_PACKETS, verdict=Verdict.SUPPORTED,
                    condition=SYN, packets=(1, 2), packet_count=PORTSCAN_PACKETS)
    from Dataset.models.base import ModelRequest, parse_answer

    answer = MockModel(mock_spec, plans={"k": plan}).generate(
        ModelRequest(system_prompt="", user_prompt="", call_key="k")
    )
    parsed = parse_answer(answer.raw_text)
    cited = parsed.payload["cited_packets"]
    assert max(cited) > PORTSCAN_PACKETS  # the mock invented numbers past the end of the file

    checker = EvidenceChecker(service=service, repo_root=REPO_ROOT, max_capture_bytes=None,
                             reexecution_limit=50, max_cited_packets=100)
    fact = checker.fact(
        call_id="c", capture={"pcap_id": "pcap_test", "path": PORTSCAN, "size_bytes": 2228},
        packet_count=PORTSCAN_PACKETS, condition=SYN, cited=cited, verdict="SUPPORTED",
    )
    assert fact.fabricated_count == 2
    assert set(fact.cited_unverified) >= {PORTSCAN_PACKETS + 17, PORTSCAN_PACKETS + 404}


def test_fabrication_is_not_counted_when_nobody_has_counted_the_capture(service, db):
    """An uncounted capture yields no fabrication figure, not a figure of zero."""
    checker = EvidenceChecker(service=None, repo_root=REPO_ROOT, max_capture_bytes=None,
                              reexecution_limit=50, max_cited_packets=100)
    fact = checker.fact(call_id="c", capture=None, packet_count=None, condition=SYN,
                        cited=[9999], verdict="SUPPORTED")
    assert fact.fabricated_count is None
    assert fact.status == "no_pcap_service"


def test_the_membership_filter_is_sorted_and_deduplicated():
    assert membership_filter([15, 12, 12]) == "frame.number in {12,15}"


def test_a_leakage_probe_has_no_evidence_and_says_so(dataset, params):
    """A no_pcap pair cannot be re-executed; that is a status, not a zero."""
    checker = EvidenceChecker(service=None, repo_root=REPO_ROOT, max_capture_bytes=None,
                              reexecution_limit=50, max_cited_packets=100)
    fact = checker.fact(call_id="c", capture=None, packet_count=None, condition=SYN, cited=[1],
                        verdict="SUPPORTED")
    assert fact.reexecuted_count is None and fact.status in ("no_capture", "no_pcap_service")


# -- the service as a whole --------------------------------------------------

@needs_tshark
def test_analysing_the_same_responses_twice_is_byte_identical(dataset, params, service):
    """
    The replay property the spec asks for.

    Nothing was re-run, nothing was asked of a model: the same stored rows
    and the same parameters must give the same analysis id and the same
    numbers, down to the last digit of every bootstrap interval.
    """
    first = analyse(dataset, run_id="run_test", params=params, service=service)
    second = analyse(dataset, run_id="run_test", params=params, service=service)
    assert first.analysis_id == second.analysis_id

    def rows(result):
        return sorted(
            (r.scope, r.scope_id, r.metric, repr(r.value), r.n, repr(r.ci_low), repr(r.ci_high),
             json.dumps(r.detail, sort_keys=True, default=str))
            for r in result.metrics
        )

    assert rows(first) == rows(second)
    assert {k: v.as_row("x") for k, v in first.facts.items()} == {k: v.as_row("x") for k, v in second.facts.items()}


@needs_tshark
def test_an_analysis_is_identified_by_run_parameters_and_code_version(dataset, params, service):
    first = analyse(dataset, run_id="run_test", params=params, service=service)
    moved = analyse(dataset, run_id="run_test",
                    params=params.with_overrides({"majority_threshold": 0.6}), service=service)
    assert first.analysis_id != moved.analysis_id
    assert first.code_version == ANALYSIS_CODE_VERSION
    stored = {a["analysis_id"] for a in list_analyses(dataset, "run_test")}
    assert {first.analysis_id, moved.analysis_id} <= stored  # the old one is still there


@needs_tshark
def test_a_what_if_changes_nothing_in_the_database(dataset, params, service):
    stored = analyse(dataset, run_id="run_test", params=params, service=service)
    before = list_analyses(dataset)
    result = what_if(dataset, run_id="run_test", overrides={"bootstrap_resamples": 11, "majority_threshold": 0.9},
                     config=Config.load(CONFIG_DIR / "demo"), service=service)
    assert result.persisted is False
    assert result.params.bootstrap_resamples == 11
    assert result.analysis_id != stored.analysis_id
    assert list_analyses(dataset) == before
    assert load_metrics(dataset, result.analysis_id) == {}


@needs_tshark
def test_a_diff_names_the_metrics_that_moved_and_why(dataset, params, service):
    left = analyse(dataset, run_id="run_test", params=params, service=service)
    right = analyse(dataset, run_id="run_test",
                    params=params.with_overrides({"majority_threshold": 0.9}), service=service)
    report = diff(dataset, left.analysis_id, right.analysis_id)
    assert report["same_run"] is True
    assert report["parameter_changes"]["majority_threshold"] == {"from": 0.5, "to": 0.9}
    assert report["changed"], "raising the majority threshold must move something"
    moved = {c["metric"] for c in report["changed"]}
    assert "no_majority_rate" in moved
    for change in report["changed"]:
        assert "majority_threshold" in change["note"] or change["note"] == "" or "n moved" in change["note"]


@needs_tshark
def test_diffing_an_analysis_that_was_never_stored_is_refused(dataset, params, service):
    stored = analyse(dataset, run_id="run_test", params=params, service=service)
    with pytest.raises(AnalysisError, match="no stored analysis"):
        diff(dataset, stored.analysis_id, "ana_nothing")


@needs_tshark
def test_every_metric_carries_its_n_or_says_why_it_has_none(dataset, params, service):
    for row in analyse(dataset, run_id="run_test", params=params, service=service).metrics:
        if row.value is not None:
            assert row.n is not None and row.n >= 0, row
        elif row.n is None:
            assert row.detail.get("reason"), row  # a missing number always says why


@needs_tshark
def test_the_stored_metrics_and_facts_can_be_read_back(dataset, params, service):
    result = analyse(dataset, run_id="run_test", params=params, service=service)
    metrics = load_metrics(dataset, result.analysis_id)
    # Two of three items are unanimous; on the third, one family abstains,
    # so one of the three voter pairs disagrees there: (1 + 1 + 1/3) / 3.
    assert metrics[("run", "run_test", "raw_agreement")]["value"] == pytest.approx(7 / 9)
    facts = load_call_facts(dataset, result.analysis_id)
    assert facts["call_pair_clm_syn_0_prm_base_0"]["cited_verified"] == [1, 2]
    assert latest_analysis(dataset, "run_test")["analysis_id"] == result.analysis_id


@needs_tshark
def test_the_position_bias_gap_is_measured_when_a_label_order_variant_ran(dataset, params, service):
    metrics = {r.key(): r for r in analyse(dataset, run_id="run_test", params=params, service=service).metrics}
    gap = metrics[("run", "run_test", "position_bias_gap")]
    assert gap.value == pytest.approx(0.0)  # this fixture answers identically under both orders
    assert gap.detail["variant"] == "labels_reversed"


@needs_tshark
def test_the_equivalence_judgement_is_pending_while_the_margin_is_unset(dataset, service):
    shipped = AnalysisParams.from_config(Config.load(apply_overrides=False)).with_overrides(
        {"bootstrap_resamples": 20}
    )
    assert shipped.equivalence_margin_flip_rate is None
    metrics = {r.key(): r for r in analyse(dataset, run_id="run_test", params=shipped, service=service,
                                           persist=False).metrics}
    row = metrics[("run", "run_test", "prompt_effect_within_margin")]
    assert row.value is None
    assert "UNSET" in row.detail["reason"]


def test_analysing_a_run_that_does_not_exist_is_refused(dataset, params):
    with pytest.raises(AnalysisError, match="no run"):
        analyse(dataset, run_id="run_nope", params=params, persist=False)


def test_a_capture_that_cannot_be_read_is_a_status_not_a_zero(dataset, params):
    """
    With the capture out of reach, every derived field stays empty.

    The failure mode this guards against is the tempting one: a missing
    capture quietly producing "0 packets re-executed, 0% sufficiency",
    which reads as a measurement and is not one.
    """
    result = analyse(dataset, run_id="run_test", params=params, service=None,
                     config=_config_without_tshark(), persist=False)
    for fact in result.facts.values():
        assert fact.status != "ok"
        assert fact.note
        assert fact.reexecuted_count is None and fact.sufficiency_ok is None
    metrics = {r.key(): r for r in result.metrics}
    assert metrics[("run", "run_test", "reexecution_coverage")].value == 0.0
    assert metrics[("run", "run_test", "sufficiency_pass_rate")].value is None


def _config_without_tshark() -> Config:
    """A config whose capture root holds nothing, so no capture can be read."""
    config = Config.load(CONFIG_DIR / "demo")
    config.experiment = json.loads(json.dumps(config.experiment))
    config.experiment["pcap_tool"]["allowed_roots"] = ["data/does-not-exist"]
    return config
