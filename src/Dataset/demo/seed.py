"""
Build a seeded demo dataset.

  Responsibility: produce a complete, reproducible dataset -- sources,
  captures, claims, pairs, prompts, a run and its model calls -- without an
  API key, so the dashboard and the analysis can be built and reviewed
  before any real result exists.

  Reproducible means byte-identical: ids are content-derived and every
  scripted behaviour is picked from a hash of (seed, call key), so seeding
  twice with the same seed yields the same ids, the same answers and the
  same results.jsonl. That is what makes the replay test meaningful.

  Everything written here is marked DEMO. The synthetic claims live in
  scenarios.py and are not attributed to any paper.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config import Config
from ..ids import content_hash, content_id
from ..manifest import REPO_ROOT, build_manifest, pcap_fingerprint
from ..models.base import ModelRequest, parse_answer
from ..models.mock import CallPlan, MockModel, ScriptedBehaviour
from ..schemas import (
    CallRecord,
    CaptureMetadata,
    Claim,
    Condition,
    ExpectedBasis,
    Pair,
    PairType,
    Pcap,
    Provenance,
    Source,
    Verdict,
)
from ..storage.db import Database
from ..storage.repository import Repository, utc_now
from .scenarios import DEMO_MUTATIONS, SCENARIOS

DEMO_LABEL = "demo"

#: Prompt variants are stubs until the prompt builder lands (B4). They carry
#: a real id and hash so calls can reference them, and no criteria text --
#: which is also why the leak test belongs to B4, not here.
DEMO_PROMPTS: tuple[dict[str, str], ...] = (
    {"dimension": "wording", "label": "wording_a", "template": "DEMO prompt variant: wording A. {claim} {capture_summary}"},
    {"dimension": "structure", "label": "structure_list", "template": "DEMO prompt variant: numbered list. {claim} {capture_summary}"},
    {"dimension": "control", "label": "control_no_criteria", "template": "DEMO control variant, no criteria. {claim} {capture_summary}"},
)

#: Per-family behaviour mix, so the demo panel is not uniformly good: the
#: analysis views need visible spread between families to be worth looking at.
FAMILY_MIX: dict[str, tuple[tuple[ScriptedBehaviour, int], ...]] = {
    "mock-alpha": (
        (ScriptedBehaviour.CORRECT, 78), (ScriptedBehaviour.WRONG, 6), (ScriptedBehaviour.ABSTAIN, 8),
        (ScriptedBehaviour.FABRICATED_PACKETS, 4), (ScriptedBehaviour.MALFORMED, 2), (ScriptedBehaviour.TOOL_FAILURE, 2),
    ),
    "mock-beta": (
        (ScriptedBehaviour.CORRECT, 62), (ScriptedBehaviour.WRONG, 14), (ScriptedBehaviour.ABSTAIN, 12),
        (ScriptedBehaviour.FABRICATED_PACKETS, 6), (ScriptedBehaviour.MALFORMED, 4), (ScriptedBehaviour.REFUSAL, 2),
    ),
    "mock-gamma": (
        (ScriptedBehaviour.CORRECT, 48), (ScriptedBehaviour.WRONG, 16), (ScriptedBehaviour.ABSTAIN, 22),
        (ScriptedBehaviour.FABRICATED_PACKETS, 6), (ScriptedBehaviour.MALFORMED, 6), (ScriptedBehaviour.TOOL_FAILURE, 2),
    ),
}


def _expected_for_level(level: int) -> Verdict:
    """Levels 4-5 are abstention tests; 1-3 should hold on their own capture."""
    return Verdict.NOT_VERIFIABLE if level in (4, 5) else Verdict.SUPPORTED


def _condition(claim_spec: dict[str, Any]) -> Condition | None:
    if "filter" not in claim_spec:
        return None
    return Condition(
        kind=claim_spec["kind"],
        display_filter=claim_spec["filter"],
        predicate=claim_spec.get("predicate", {}),
        parameters=claim_spec.get("parameters", {}),
    )


def seed_demo(
    *,
    db_path: str | Path,
    results_path: str | Path,
    config: Config,
    seed: int | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Create the demo dataset. Returns a small summary for the CLI."""
    root = repo_root or REPO_ROOT
    seed = seed if seed is not None else int(config.get("run.seed", 0))

    db = Database(db_path).initialise()
    repo = Repository(db, results_path=results_path)

    pcap_rows: list[dict[str, Any]] = []
    source_claims: list[tuple[Claim, str]] = []  # (claim, pcap_id)

    # -- sources, captures and claims ------------------------------------
    for scenario in SCENARIOS:
        source = Source(
            source_id=content_id("src", [DEMO_LABEL, scenario["key"]]),
            title=scenario["title"],
            origin=f"DEMO entry; capture already present in this repo at {scenario['pcap_path']}",
            license="UNVERIFIED",
            notes="Synthetic demo data. Claims are not quoted from any publication.",
        )
        repo.add_source(source)

        pcap_file = root / scenario["pcap_path"]
        fingerprint = pcap_fingerprint(pcap_file)
        pcap = Pcap(
            pcap_id=content_id("pcap", [DEMO_LABEL, scenario["key"], fingerprint["sha256"]]),
            source_id=source.source_id,
            path=scenario["pcap_path"],
            sha256=fingerprint["sha256"],
            size_bytes=fingerprint["size_bytes"],
            packet_count=None,  # unverified until the PCAP service counts it (B1)
            capture_metadata=CaptureMetadata(**scenario["capture_metadata"]),
            license="UNVERIFIED",
            origin="in-repo capture",
        )
        repo.add_pcap(pcap)
        pcap_rows.append({"pcap_id": pcap.pcap_id, "sha256": pcap.sha256, "packet_count": pcap.packet_count})
        repo.add_verification_check(
            item="packet count confirmed with tshark",
            status="unverified",
            source_id=source.source_id,
            pcap_id=pcap.pcap_id,
            notes="No PCAP service yet (milestone B1); the count was not read from the file.",
        )

        for index, claim_spec in enumerate(scenario["claims"]):
            claim = Claim(
                claim_id=content_id("clm", [DEMO_LABEL, scenario["key"], index, claim_spec["atomic"]]),
                source_id=source.source_id,
                source_location=claim_spec["location"],
                source_step_text=claim_spec["step"],
                atomic_text=claim_spec["atomic"],
                level=claim_spec["level"],
                kind=claim_spec["kind"],
                reason_code=claim_spec.get("reason_code"),
                condition=_condition(claim_spec),
                provenance=Provenance.AGENT,
            )
            repo.add_claim(claim)
            source_claims.append((claim, pcap.pcap_id))

    # -- pairs ------------------------------------------------------------
    pairs: list[Pair] = []

    def add_pair(pair: Pair) -> None:
        repo.add_pair(pair)
        pairs.append(pair)

    for claim, pcap_id in source_claims:
        add_pair(
            Pair(
                pair_id=content_id("pair", [DEMO_LABEL, "source", claim.claim_id, pcap_id]),
                claim_id=claim.claim_id,
                pair_type=PairType.SOURCE,
                pcap_id=pcap_id,
                expected=_expected_for_level(claim.level),
                expected_basis=ExpectedBasis.AUTHOR if claim.level < 4 else ExpectedBasis.CONSTRUCTION,
                level=claim.level,
                notes="DEMO pair.",
            )
        )
        # Knowledge-leakage probe: the same claim with no capture at all.
        add_pair(
            Pair(
                pair_id=content_id("pair", [DEMO_LABEL, "no_pcap", claim.claim_id]),
                claim_id=claim.claim_id,
                pair_type=PairType.NO_PCAP,
                pcap_id=None,
                expected=Verdict.NOT_VERIFIABLE,
                expected_basis=ExpectedBasis.CONSTRUCTION,
                level=claim.level,
                notes="DEMO leakage probe: no capture is supplied.",
            )
        )

    # Mutations: one changed detail, expected REFUTED by construction.
    for mutation in DEMO_MUTATIONS:
        match = next(
            (
                (claim, pcap_id)
                for claim, pcap_id in source_claims
                if claim.condition and claim.condition.display_filter == mutation["filter_from"]
                and mutation["text_from"] in claim.atomic_text
            ),
            None,
        )
        if match is None:
            continue
        claim, pcap_id = match
        mutated_text = claim.atomic_text.replace(mutation["text_from"], mutation["text_to"])
        mutated = Claim(
            claim_id=content_id("clm", [DEMO_LABEL, "mut", claim.claim_id, mutation["mutation_type"]]),
            source_id=claim.source_id,
            source_location=claim.source_location,
            source_step_text=claim.source_step_text,
            atomic_text=mutated_text,
            level=claim.level,
            kind=claim.kind,
            condition=Condition(
                kind=claim.kind,
                display_filter=mutation["filter_to"],
                predicate={**(claim.condition.predicate if claim.condition else {}), mutation["field"]: mutation["new_value"]},
                parameters=claim.condition.parameters if claim.condition else {},
            ),
            mutation_of=claim.claim_id,
            mutation_type=mutation["mutation_type"],
            provenance=Provenance.AGENT,
        )
        repo.add_claim(mutated)
        add_pair(
            Pair(
                pair_id=content_id("pair", [DEMO_LABEL, "mutation", mutated.claim_id, pcap_id]),
                claim_id=mutated.claim_id,
                pair_type=PairType.MUTATION,
                pcap_id=pcap_id,
                expected=Verdict.REFUTED,
                expected_basis=ExpectedBasis.CONSTRUCTION,
                level=mutated.level,
                notes="DEMO mutation; mechanical validation lands in B3.",
            )
        )

    # Swaps: a claim judged against another scenario's capture. Scored as
    # "not SUPPORTED" rather than REFUTED, which depends on closed world.
    by_pcap = {pcap_id for _, pcap_id in source_claims}
    for claim, pcap_id in source_claims:
        if claim.level >= 4:
            continue
        other = sorted(by_pcap - {pcap_id})
        if not other:
            continue
        add_pair(
            Pair(
                pair_id=content_id("pair", [DEMO_LABEL, "swap", claim.claim_id, other[0]]),
                claim_id=claim.claim_id,
                pair_type=PairType.SWAP,
                pcap_id=other[0],
                expected=None,  # scored as "not SUPPORTED", not as a verdict
                expected_basis=ExpectedBasis.CONSTRUCTION,
                level=claim.level,
                notes="DEMO swap: scored as not-SUPPORTED, never as REFUTED.",
            )
        )

    # -- prompts and panel -------------------------------------------------
    prompt_rows: list[dict[str, Any]] = []
    for variant in DEMO_PROMPTS:
        prompt_hash = content_hash(variant)
        prompt_id = content_id("prm", variant)
        db.insert(
            "prompt_variants",
            dict(
                prompt_id=prompt_id,
                dimension=variant["dimension"],
                label=variant["label"],
                template=variant["template"],
                prompt_hash=prompt_hash,
                config_version=int(config.get("config_version", 1)),
                created_at=utc_now(),
            ),
        )
        prompt_rows.append({"prompt_id": prompt_id, "prompt_hash": prompt_hash, "label": variant["label"]})

    model_rows: list[dict[str, Any]] = []
    for spec in config.models:
        repo.add_model_spec(spec)
        model_rows.append(
            {
                "model_id": spec.model_id,
                "family": spec.family,
                "version": spec.version,
                "temperature": spec.temperature,
                "supports_tools": spec.supports_tools,
            }
        )

    # -- the run -----------------------------------------------------------
    config.require_frozen()
    run_id, manifest = build_manifest(
        config=config, pcaps=pcap_rows, prompts=prompt_rows, models=model_rows, label=DEMO_LABEL, repo_root=root
    )
    repo.add_run(run_id, manifest)
    repo.add_run_event(run_id, "started")

    repeats = int(config.get("run.repeats", 2))
    adapters = {
        spec.model_id: MockModel(spec, seed=seed, plans={}) for spec in config.models
    }

    calls = 0
    format_errors = 0
    for pair in pairs:
        for spec in config.models:
            for prompt in prompt_rows:
                for repeat in range(repeats):
                    call_key = f"{run_id}:{pair.pair_id}:{spec.model_id}:{prompt['prompt_id']}:{repeat}"
                    adapter = adapters[spec.model_id]
                    plan = CallPlan(
                        behaviour=_behaviour_for(spec.family, call_key, seed),
                        verdict=pair.expected or Verdict.NOT_VERIFIABLE,
                        condition=_claim_filter(source_claims, pair.claim_id),
                        packets=(1, 2, 3),
                        packet_count=100,
                    )
                    adapter.plans[call_key] = plan
                    request = ModelRequest(
                        system_prompt=prompt["label"],
                        user_prompt=f"DEMO prompt for pair {pair.pair_id}",
                        call_key=call_key,
                        temperature=spec.temperature,
                        max_output_tokens=spec.max_output_tokens,
                        tools_enabled=spec.supports_tools,
                    )
                    result = adapter.generate(request)
                    parsed = parse_answer(result.raw_text)
                    format_errors += int(parsed.format_error)
                    repo.add_call(
                        CallRecord(
                            call_id=content_id("call", [call_key]),
                            run_id=run_id,
                            pair_id=pair.pair_id,
                            model_id=spec.model_id,
                            model_family=spec.family,
                            model_version=spec.version,
                            prompt_id=prompt["prompt_id"],
                            prompt_hash=prompt["prompt_hash"],
                            repeat=repeat,
                            temperature=spec.temperature,
                            raw_response=result.raw_text,
                            parsed=parsed.payload,
                            tool_calls=result.tool_calls,
                            format_error=parsed.format_error,
                            error=result.error,
                            latency_ms=result.latency_ms,
                            tokens_in=result.tokens_in,
                            tokens_out=result.tokens_out,
                            timestamp=utc_now(),
                        )
                    )
                    calls += 1

    repo.add_run_event(run_id, "finished", f"{calls} calls")
    summary = {
        "run_id": run_id,
        "seed": seed,
        "counts": repo.counts(),
        "pairs_by_type": {t.value: len([p for p in pairs if p.pair_type is t]) for t in PairType},
        "calls": calls,
        "format_errors": format_errors,
        "results_path": str(results_path),
        "db_path": str(db_path),
    }
    db.close()
    return summary


def _behaviour_for(family: str, call_key: str, seed: int) -> ScriptedBehaviour:
    from ..models.mock import _weighted_pick

    return _weighted_pick(call_key, seed, FAMILY_MIX.get(family, None) or FAMILY_MIX["mock-beta"])


def _claim_filter(source_claims: list[tuple[Claim, str]], claim_id: str) -> str:
    for claim, _ in source_claims:
        if claim.claim_id == claim_id and claim.condition:
            return claim.condition.display_filter
    return "frame"
