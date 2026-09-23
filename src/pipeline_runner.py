"""
PAnGEA — Pipeline orchestrator.

Wires all four stages together in order. This is the ONLY place that:
  - imports both `Preprocessor` and `Grounder`/`validator` (neither of
    those packages import each other or `Preprocessor` directly -- see
    each component's own docstring for why)
  - owns the ReducerOutput -> EvidenceItem/EvidenceAggregate adapter
    (previously demonstrated in the Evidence Matcher smoke test; promoted
    here as the real, non-test adapter now that a real orchestrator exists)
  - decides the token budget passed into Preprocessor (a number computed
    from context-window/system-prompt/description-length/safety-margin,
    per the earlier spec discussion -- Preprocessor itself cannot compute
    this, since R2 blocks it from ever seeing the description to measure)

Pipeline order:
    Attack Description ──┬──────────────────────────────────────┐
                          │                                      │
                          ▼                                      ▼
                    [Preprocessor]                       [Step Extractor]
                 (Filter Generator + Reducer)              (text-only, R2)
                          │                                      │
                          ▼                                      ▼
                    ReducerOutput                        actors, steps
                          │                                      │
                          ▼                                      │
               adapt_reducer_output()                            │
                          │                                      │
                          ▼                                      ▼
                          └──────────────► [Evidence Matcher] ◄──┘
                                                   │
                                                   ▼
                                     resolved_actors, grounded_steps
                                                   │
                                       ┌───────────┴───────────┐
                                       ▼                       ▼
                                 [Visualizer]              [Validator]
                            (raw actors/steps shape,             │
                             annotated w/ grounding)              │
                                       │                       ▼
                                       ▼                ValidatorAssessment
                          traffic_diagram.d2 (+ .svg/.png)

Note what does NOT happen here yet: the drill-down retry loop (re-calling
Preprocessor with a narrower filter when a step is
uncertain_needs_drilldown) is still out of scope -- flagged in every
component's docstring as an orchestrator-level concern, and this
orchestrator doesn't implement it yet either. This is a single forward
pass through all four stages.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Optional

from Preprocessor.preprocessor import run_preprocessing
from Preprocessor.schemas import ReducerOutput

from Grounder.models import Actor, Step, GroundedStep, EvidenceItem, EvidenceAggregate
from Grounder.steps_extractor import StepExtractor
from Grounder.evidence_matcher import (
    EvidenceMatcher,
    _build_ip_summary_table,       # noqa: for diagnostic-file writing only
    _find_identity_fanout_anomalies,  # noqa: for diagnostic-file writing only
)
# NOTE on the two "private" (leading-underscore) imports above: calling
# them here is a DELIBERATE, one-time-per-run extra computation purely to
# write out inspectable diagnostic files -- not the same class of issue as
# the earlier per-actor redundant recomputation bug (which called these
# once PER ACTOR, inside a loop). Here it's called once, after
# EvidenceMatcher.match() has already run its own internal (now
# single-computed) copy -- a small, deliberate duplication in exchange for
# visibility into exactly what Evidence Matcher saw, without changing
# EvidenceMatcher's tested public match() return signature.

from Visualizer.visualize import generate_diagram, VisualizerResult

from Validator.models import ValidatorAssessment
# NOTE: `Validator` itself (validator.validator) is imported lazily inside
# run_pipeline, only when actually needed -- see the run_validator param
# below. This keeps the rest of the pipeline usable even while the
# Validator stage isn't ready to be exercised yet.

from shared.llm_client import LLMClient

logger = logging.getLogger(__name__)


def _write_diagnostic(output_dir: Optional[str], filename: str, data) -> None:
    """
    Writes one intermediate-stage artifact as JSON, if output_dir is set.
    No-op (silently does nothing) if output_dir is None -- diagnostic
    output is opt-in, not a side effect that always happens.
    """
    if output_dir is None:
        return
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    file_path = path / filename
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    logger.info("  wrote diagnostic file: %s", file_path)


# --------------------------------------------------------------------------
# Console color helpers -- ANSI escape codes, only used when stdout is an
# interactive terminal (isatty), so redirected/piped output (e.g. `>
# log.txt`) doesn't fill up with raw escape-code garbage.
# --------------------------------------------------------------------------

class _Colors:
    _enabled = sys.stdout.isatty() if hasattr(sys, "stdout") else False

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""
    GREEN = "\033[32m" if _enabled else ""
    RED = "\033[31m" if _enabled else ""
    YELLOW = "\033[33m" if _enabled else ""
    CYAN = "\033[36m" if _enabled else ""
    GRAY = "\033[90m" if _enabled else ""


_STATUS_STYLE = {
    "grounded": (_Colors.GREEN, "\u2713"),                    # ✓ green
    "unsupported": (_Colors.RED, "\u2717"),                   # ✗ red
    "uncertain_needs_drilldown": (_Colors.YELLOW, "?"),        # ? yellow
}


def _colorize_status(status: str) -> str:
    color, symbol = _STATUS_STYLE.get(status, (_Colors.GRAY, " "))
    return f"{color}{symbol} {status}{_Colors.RESET}"


def adapt_reducer_output(
    reducer_out: ReducerOutput,
) -> tuple[list[EvidenceItem], dict[str, EvidenceAggregate]]:
    """
    Translates Preprocessor's ReducerOutput into the generic
    EvidenceItem/EvidenceAggregate shapes that Evidence Matcher and
    Validator actually depend on. This is deliberately NOT inside either
    of those components -- see evidence_matcher.py's docstring for why
    that separation matters (so a future evidence source other than
    Preprocessor's Reducer only requires a new adapter, not changes to
    Evidence Matcher/Validator themselves).
    """
    logger.debug(
        "Adapting ReducerOutput -> generic evidence shapes: "
        "%d reduced items, %d fingerprint_index entries",
        len(reducer_out.reduced_representation), len(reducer_out.fingerprint_index),
    )

    reduced_representation = [
        EvidenceItem(
            packet_id=item.packet_id,
            timestamp=item.timestamp,
            protocol=item.protocol,
            src=item.src,
            dst=item.dst,
            length=item.length,
            info=item.info,
            fingerprint_key=item.fingerprint_key,
        )
        for item in reducer_out.reduced_representation
    ]
    fingerprint_index = {
        fkey: EvidenceAggregate(
            fingerprint_key=agg.fingerprint_key,
            count=agg.count,
            unique_sources=list(agg.unique_sources),
            unique_destinations=list(agg.unique_destinations),
        )
        for fkey, agg in reducer_out.fingerprint_index.items()
    }

    logger.debug(
        "Adapter done: %d EvidenceItem(s), %d EvidenceAggregate key(s)",
        len(reduced_representation), len(fingerprint_index),
    )
    return reduced_representation, fingerprint_index


class PipelineResult:
    def __init__(
        self,
        reducer_output: ReducerOutput,
        actors: list[Actor],
        steps: list[Step],
        resolved_actors: list[Actor],
        grounded_steps: list[GroundedStep],
        validator_assessment: ValidatorAssessment,
        visualizer_result: Optional[VisualizerResult] = None,
    ):
        self.reducer_output = reducer_output
        self.actors = actors               # pre-resolution, from Step Extractor
        self.steps = steps                 # pre-grounding, from Step Extractor
        self.resolved_actors = resolved_actors
        self.grounded_steps = grounded_steps
        self.validator_assessment = validator_assessment
        self.visualizer_result = visualizer_result  # None if run_visualizer=False

    def to_dict(self) -> dict:
        def _d(obj):
            return asdict(obj) if is_dataclass(obj) else obj

        return {
            "Preprocessor": {
                "compression_stats": _d(self.reducer_output.compression_stats),
                "budget_status": self.reducer_output.budget_status.value,
                "budget_status_detail": self.reducer_output.budget_status_detail,
                "filter_string_used": self.reducer_output.filter_string_used,
                "capture_error": getattr(self.reducer_output, "capture_error", None),
            },
            "resolved_actors": [_d(a) for a in self.resolved_actors],
            "grounded_steps": [
                {"step": _d(gs.step), "grounding": _d(gs.grounding)}
                for gs in self.grounded_steps
            ],
            "validator_assessment": _d(self.validator_assessment),
            "visualizer": (
                {
                    "d2_path": self.visualizer_result.d2_path,
                    "rendered_paths": self.visualizer_result.rendered_paths,
                    "warnings": self.visualizer_result.warnings,
                }
                if self.visualizer_result is not None else None
            ),
        }


def build_system_sample_from_pipeline_result(
    result: "PipelineResult", reducer_output: ReducerOutput, sample_id: str,
):
    """
    Adapts this orchestrator's IN-MEMORY PipelineResult + ReducerOutput
    directly into the Evaluator's SystemSample shape -- no JSON
    round-trip through 03c_evidence_matcher_output.json /
    01_preprocessing_output.json needed (Evaluator.run_evaluator's
    load_system_output_from_pipeline_json does the same adaptation, but
    from files on disk; this is the equivalent for a pipeline run that's
    still live in this process). Mirrors that function's field mapping
    exactly, so a gold sample scored via either path gets the same
    result.

    Imports Evaluator lazily, same reasoning as Validator's lazy import
    above: keeps the rest of the pipeline runnable even in an environment
    where the Evaluator package isn't installed, unless evaluate mode is
    actually requested.
    """
    from Evaluator.schemas import SystemActor, SystemClaim, SystemSample

    actors = [
        SystemActor(
            actor_id=a.actor_id,
            description_ref=a.description_ref or "",
            resolved_endpoints=list(a.resolved_endpoints or []),
        )
        for a in result.resolved_actors
    ]

    claims = []
    for gs in result.grounded_steps:
        linked_keys = [r.fingerprint_key for r in gs.grounding.linked_aggregate_refs]
        linked_dests = {
            r.fingerprint_key: list(r.unique_destinations)
            for r in gs.grounding.linked_aggregate_refs
        }
        status = gs.grounding.status.value if hasattr(gs.grounding.status, "value") else gs.grounding.status
        claims.append(SystemClaim(
            step_id=gs.step.step_id,
            text=gs.step.text,
            actor_refs=list(gs.step.actor_refs or []),
            grounding_status=status,
            linked_fingerprint_keys=linked_keys,
            linked_fingerprint_destinations=linked_dests,
        ))

    observed_ips = set()
    for agg in reducer_output.fingerprint_index.values():
        observed_ips.update(agg.unique_sources)
        observed_ips.update(agg.unique_destinations)

    return SystemSample(sample_id=sample_id, actors=actors, claims=claims, observed_ips=observed_ips)


def run_evaluation(
    result: "PipelineResult",
    reducer_output: ReducerOutput,
    gold_path: str,
    sample_id: Optional[str] = None,
    alignment_threshold: float = 0.15,
    similarity: str = "tfidf",
):
    """
    Loads a gold sample from disk and scores THIS pipeline run against
    it, entirely in-memory. Returns an Evaluator.report.EvaluationReport
    -- call .to_text() or .to_json() on it, same as the standalone
    Evaluator CLI would produce.

    gold_path may be either:
      - a gold_sample.json (produced ahead of time by
        Evaluator.xlsx_to_gold_json), or
      - a filled-in gold_sample_template.xlsx directly -- detected by
        file extension, converted in-memory via
        Evaluator.xlsx_to_gold_json.convert() (no separate manual
        conversion step, no intermediate JSON file written to disk).

    similarity: "tfidf" (default, no external dependency), "embedding"
    (OpenAI API, needs OPENAI_API_KEY), or "local_embedding" (runs fully
    locally via sentence-transformers, no API key -- see alignment.py's
    local_embedding_similarity_matrix docstring for setup and its
    confirmed-untested-in-this-project's-own-sandbox status). Similarity
    SCALE differs between methods, so alignment_threshold likely needs
    re-tuning if you switch -- see --rubric-test's output for a
    data-driven way to pick a new threshold rather than guessing.
    """
    from Evaluator.run_evaluator import load_gold, gold_sample_from_dict
    from Evaluator.report import evaluate_sample
    from Evaluator.alignment import run_rubric_test

    similarity_fn = resolve_similarity_fn(similarity)

    if gold_path.lower().endswith((".xlsx", ".xlsm")):
        from Evaluator.xlsx_to_gold_json import convert as convert_xlsx_to_gold_dict
        gold = gold_sample_from_dict(convert_xlsx_to_gold_dict(gold_path))
    else:
        gold = load_gold(gold_path)

    system = build_system_sample_from_pipeline_result(
        result, reducer_output, sample_id or gold.sample_id,
    )
    report = evaluate_sample(gold, system, alignment_threshold=alignment_threshold, similarity_fn=similarity_fn)
    rubric_result = run_rubric_test(similarity_fn, method_name=similarity)
    return report, rubric_result


def resolve_similarity_fn(similarity: str):
    """
    The one place --alignment-similarity gets turned into an actual
    function -- shared between run_evaluation and anywhere else that
    needs the same selection (e.g. a standalone rubric-test run), so the
    mapping can't drift out of sync between them.
    """
    from Evaluator.alignment import tfidf_similarity_matrix, embedding_similarity_matrix, local_embedding_similarity_matrix
    return {
        "tfidf": tfidf_similarity_matrix,
        "embedding": embedding_similarity_matrix,
        "local_embedding": local_embedding_similarity_matrix,
    }[similarity]


def run_pipeline(
    pcap_bytes: bytes,
    attack_description: str,
    token_budget: int,
    step_extractor_llm_client: LLMClient,
    evidence_matcher_llm_client: Optional[LLMClient] = None,
    validator_llm_client: Optional[LLMClient] = None,
    run_validator: bool = False,
    filtering_limit: int = 3,
    filter_generator_llm_client: Optional[LLMClient] = None,
    output_dir: Optional[str] = None,
    run_visualizer: bool = True,
    diagram_dir: Optional[str] = None,
    diagram_formats: tuple[str, ...] = ("svg",),
) -> PipelineResult:
    """
    Run all four stages in order.

    Args:
        pcap_bytes: raw PCAP file contents.
        attack_description: free text. Fans out to TWO independent
            consumers (Preprocessor's Filter Generator, and Step
            Extractor) -- never to the Reducer directly (R2), and never to
            Evidence Matcher or Validator's step-grounding logic directly
            either (they only see what Step Extractor already produced).
        token_budget: final, pre-computed token budget for Preprocessor's
            output (see module docstring -- this must be computed
            upstream of this function; it is NOT derived here from
            attack_description automatically, on purpose).
        step_extractor_llm_client: REQUIRED -- Step Extractor has no
            algorithmic substitute (see its own module docstring).
        evidence_matcher_llm_client: optional. If None, Evidence Matcher
            falls back to its algorithmic-only paths (offline actor
            -resolution heuristic; no escalation for ambiguous step
            grounding -- those steps come back uncertain_needs_drilldown
            instead of being resolved).
        validator_llm_client: optional, only used if run_validator=True.
        run_validator: EXPLICIT opt-in, defaults to False. The Validator
            stage is currently under active development and not yet
            ready to be exercised as part of a full pipeline run -- with
            this defaulting to False, the stage is skipped by default
            regardless of whether validator_llm_client happens to be
            passed, and `validator.validator` is never even imported (see
            the lazy import inside this function) unless this is
            explicitly set to True. Flip to True once ready to test it.
        filtering_limit: raw samples retained per fingerprint by the
            Reducer before folding further instances into aggregate-only
            stats (default: 3).
        filter_generator_llm_client: optional, passed through to
            Preprocessor's Filter Generator. If None, Filter Generator
            uses its deterministic keyword fallback.
        output_dir: optional. If set, writes one JSON file per stage to
            this directory, for step-by-step inspection of exactly what
            each stage produced (useful for diagnosing where a wrong
            result originated -- e.g. bad extraction vs. bad actor
            resolution vs. bad grounding). If None (default), no
            diagnostic files are written at all.
        run_visualizer: whether to build the D2 traffic diagram after
            Evidence Matcher runs (default: True). The diagram's shape
            comes from Step Extractor's raw actors/steps; it is annotated
            with Evidence Matcher's resolved_actors/grounded_steps, so it
            always runs AFTER Stage 3, never before.
        diagram_dir: directory to write the diagram (.d2 source, plus any
            rendered images) into. If None (default), falls back to
            `output_dir` so passing just `--output-dir` on the CLI is
            enough to get diagrams for free; if both are None, the
            diagram is written to the current directory. Ignored if
            run_visualizer=False.
        diagram_formats: image formats to render from the .d2 source,
            e.g. ("svg",) (default), ("svg", "png"), or () to write only
            the .d2 source and skip rendering (useful if the `d2` CLI
            isn't installed in this environment).
    """
    pipeline_start = time.monotonic()
    logger.info("=" * 70)
    logger.info("PIPELINE START")
    logger.info(
        "  pcap size: %d bytes | description length: %d chars | token_budget=%d "
        "filtering_limit=%d",
        len(pcap_bytes), len(attack_description), token_budget, filtering_limit,
    )
    logger.info(
        "  LLM clients: step_extractor=%s evidence_matcher=%s validator=%s "
        "filter_generator=%s",
        type(step_extractor_llm_client).__name__,
        type(evidence_matcher_llm_client).__name__ if evidence_matcher_llm_client else "None (offline fallback)",
        type(validator_llm_client).__name__ if validator_llm_client else "None (stage will be SKIPPED)",
        type(filter_generator_llm_client).__name__ if filter_generator_llm_client else "None (keyword fallback)",
    )
    logger.info("=" * 70)

    # ---------------------------------------------------------------- #
    # Stage 1/4: Preprocessor
    # ---------------------------------------------------------------- #
    logger.info("--- Stage 1/4: Preprocessor (Filter Generator + Reducer) ---")
    stage_start = time.monotonic()
    try:
        reducer_output = run_preprocessing(
            pcap_bytes=pcap_bytes,
            attack_description=attack_description,
            token_budget=token_budget,
            filtering_limit=filtering_limit,
            llm_client=filter_generator_llm_client,
        )
    except Exception:
        logger.exception("Stage 1/4 (Preprocessor) raised an exception -- aborting pipeline.")
        raise
    stage_elapsed = time.monotonic() - stage_start

    logger.info(
        "Preprocessor done in %.2fs | filter_used=%r",
        stage_elapsed, reducer_output.filter_string_used,
    )
    logger.info(
        "  compression: raw_in=%d out=%d ratio=%.4f estimated_tokens=%d dropped_parse_failures=%d",
        reducer_output.compression_stats.raw_packet_count_in,
        reducer_output.compression_stats.packet_count_out,
        reducer_output.compression_stats.compression_ratio,
        reducer_output.compression_stats.estimated_tokens_out,
        reducer_output.compression_stats.dropped_parse_failures,
    )
    logger.info("  budget_status=%s%s", reducer_output.budget_status.value,
                f" ({reducer_output.budget_status_detail})" if reducer_output.budget_status_detail else "")
    if getattr(reducer_output, "capture_error", None):
        logger.warning("  capture_error reported: %s", reducer_output.capture_error)
    logger.info("  fingerprint_index size: %d unique fingerprint(s)", len(reducer_output.fingerprint_index))

    # Full item-level dump -- previously missing entirely; only the
    # aggregate compression_stats were logged above, never the actual
    # retained items or fingerprints themselves.
    logger.debug("  --- reduced_representation items (%d) ---", len(reducer_output.reduced_representation))
    for item in reducer_output.reduced_representation:
        agg_note = ""
        if item.aggregate is not None:
            agg_note = (f" [AGGREGATE count={item.aggregate.count} "
                        f"srcs={item.aggregate.unique_sources} dsts={item.aggregate.unique_destinations}]")
        logger.debug(
            "    #%s %s %-8s %s -> %s  len=%s  %s%s",
            item.packet_id, item.timestamp, item.protocol, item.src, item.dst,
            item.length, item.info, agg_note,
        )
    logger.info("  --- fingerprint_index entries (%d) ---", len(reducer_output.fingerprint_index))
    for fkey, agg in reducer_output.fingerprint_index.items():
        logger.info(
            "    %s: count=%d srcs=%s dsts=%s",
            fkey, agg.count, agg.unique_sources, agg.unique_destinations,
        )

    _write_diagnostic(output_dir, "01_preprocessing_output.json", {
        "compression_stats": asdict(reducer_output.compression_stats),
        "budget_status": reducer_output.budget_status.value,
        "budget_status_detail": reducer_output.budget_status_detail,
        "filter_string_used": reducer_output.filter_string_used,
        "capture_error": getattr(reducer_output, "capture_error", None),
        "reduced_representation": [asdict(i) for i in reducer_output.reduced_representation],
        "fingerprint_index": {k: asdict(v) for k, v in reducer_output.fingerprint_index.items()},
    })

    # ---------------------------------------------------------------- #
    # Stage 2/4: Step Extractor
    # ---------------------------------------------------------------- #
    logger.info("--- Stage 2/4: Step Extractor ---")
    stage_start = time.monotonic()
    try:
        step_extractor = StepExtractor(llm_client=step_extractor_llm_client)
        actors, steps = step_extractor.extract(attack_description)
    except Exception:
        logger.exception("Stage 2/4 (Step Extractor) raised an exception -- aborting pipeline.")
        raise
    stage_elapsed = time.monotonic() - stage_start

    logger.info("Step Extractor done in %.2fs: %d actor(s), %d step(s)",
                stage_elapsed, len(actors), len(steps))
    for a in actors:
        logger.info("  actor: id=%s role=%s description_ref=%r", a.actor_id, a.role, a.description_ref)
    for s in steps:
        ei = s.expected_indicators
        logger.info("  step: id=%s text=%r actor_refs=%s", s.step_id, s.text, s.actor_refs)
        logger.info(
            "    expected_indicators: protocol=%s port=%s flags=%s direction=%s "
            "volume_pattern=%s cardinality_pattern=%s ip_hint=%s",
            ei.protocol, ei.port, ei.flags, ei.direction,
            ei.volume_pattern, ei.cardinality_pattern, ei.ip_hint,
        )
        logger.info("    indicator_description: %r", ei.indicator_description)

    _write_diagnostic(output_dir, "02_step_extractor_output.json", {
        "actors": [asdict(a) for a in actors],
        "steps": [asdict(s) for s in steps],
    })

    # ---------------------------------------------------------------- #
    # Stage 3/4: Evidence Matcher
    # ---------------------------------------------------------------- #
    logger.info("--- Stage 3/4: Evidence Matcher ---")
    stage_start = time.monotonic()
    reduced_representation, fingerprint_index = adapt_reducer_output(reducer_output)
    try:
        evidence_matcher = EvidenceMatcher(llm_client=evidence_matcher_llm_client)
        resolved_actors, grounded_steps = evidence_matcher.match(
            actors, steps, reduced_representation, fingerprint_index,
        )
    except Exception:
        logger.exception("Stage 3/4 (Evidence Matcher) raised an exception -- aborting pipeline.")
        raise
    stage_elapsed = time.monotonic() - stage_start

    n_resolved = sum(1 for a in resolved_actors if a.resolved_endpoints)
    logger.info(
        "Evidence Matcher done in %.2fs: %d/%d actors resolved, %d steps grounded",
        stage_elapsed, n_resolved, len(resolved_actors), len(grounded_steps),
    )
    logger.info(f"{_Colors.BOLD}  --- Resolved Actors ---{_Colors.RESET}")
    for a in resolved_actors:
        if a.resolved_endpoints:
            logger.info(
                f"  {_Colors.GREEN}\u2713{_Colors.RESET} {a.actor_id:<16} -> "
                f"{_Colors.CYAN}{a.resolved_endpoints}{_Colors.RESET}"
                f"  {_Colors.DIM}({a.resolution_basis}){_Colors.RESET}"
            )
        else:
            logger.warning(
                f"  {_Colors.RED}\u2717{_Colors.RESET} {a.actor_id:<16} -> "
                f"{_Colors.RED}UNRESOLVED{_Colors.RESET}"
                f"  {_Colors.DIM}({a.resolution_basis}){_Colors.RESET}"
            )

    logger.info(f"{_Colors.BOLD}  --- Grounded Steps ---{_Colors.RESET}")
    status_counts: dict[str, int] = {}
    for gs in grounded_steps:
        status = gs.grounding.status.value
        status_counts[status] = status_counts.get(status, 0) + 1

        logger.debug(f"  {gs.step.step_id}  {_colorize_status(status)}")
        logger.debug(f"  {_Colors.DIM}\u2502 text: {gs.step.text!r}{_Colors.RESET}")
        logger.debug(
            f"  {_Colors.DIM}\u2502 linked_packets={len(gs.grounding.linked_packets)} "
            f"linked_aggregates={len(gs.grounding.linked_aggregate_refs)}{_Colors.RESET}"
        )
        for p in gs.grounding.linked_packets:
            logger.debug(
                f"  {_Colors.DIM}\u251c\u2500 packet #{p.packet_id} @ {p.timestamp}{_Colors.RESET}"
            )
        for r in gs.grounding.linked_aggregate_refs:
            logger.debug(
                f"  {_Colors.DIM}\u251c\u2500 aggregate {r.fingerprint_key} "
                f"count={r.count} srcs={r.unique_sources} dsts={r.unique_destinations}{_Colors.RESET}"
            )
        logger.debug(f"  {_Colors.DIM}\u2514\u2500 notes: {gs.grounding.notes}{_Colors.RESET}")

    breakdown = "  ".join(
        f"{_colorize_status(s)}={c}" for s, c in status_counts.items()
    )
    logger.info(f"  {_Colors.BOLD}grounding status breakdown:{_Colors.RESET}  {breakdown}")

    # These are recomputed here (once, not per-actor -- see the import
    # comment at the top of the file) purely to write them out for
    # inspection. EvidenceMatcher.match() already computed its own copy
    # internally; this is a deliberate, cheap, one-time duplication in
    # exchange for visibility, not a reintroduction of the per-actor
    # redundancy bug that was fixed earlier.
    ip_summary = _build_ip_summary_table(fingerprint_index)
    anomalies = _find_identity_fanout_anomalies(fingerprint_index)

    _write_diagnostic(output_dir, "03a_ip_summary.json", ip_summary)
    _write_diagnostic(output_dir, "03b_anomalies.json", anomalies)

    def _grounded_step_to_dict(gs: GroundedStep) -> dict:
        d = asdict(gs)
        d["grounding"]["status"] = gs.grounding.status.value
        return d

    _write_diagnostic(output_dir, "03c_evidence_matcher_output.json", {
        "resolved_actors": [asdict(a) for a in resolved_actors],
        "grounded_steps": [_grounded_step_to_dict(gs) for gs in grounded_steps],
    })

    # ---------------------------------------------------------------- #
    # Visualizer -- builds the D2 traffic diagram. Shape comes from the
    # RAW actors/steps (Step Extractor); resolved_actors/grounded_steps
    # (just produced by Evidence Matcher, above) are passed in purely to
    # annotate that shape -- color each node/edge and fill in tooltips
    # showing what evidence actually backs (or fails to back) each claim.
    # This is why it's placed here, after Stage 3, rather than right
    # after Stage 2 alongside the raw extraction.
    # ---------------------------------------------------------------- #
    visualizer_result: Optional[VisualizerResult] = None
    if run_visualizer:
        logger.info("--- Visualizer: building traffic diagram ---")
        stage_start = time.monotonic()
        try:
            visualizer_result = generate_diagram(
                actors=actors,
                steps=steps,
                resolved_actors=resolved_actors,
                grounded_steps=grounded_steps,
                output_dir=diagram_dir if diagram_dir is not None else (output_dir or "."),
                base_filename="traffic_diagram",
                render_formats=diagram_formats,
                title="PAnGEA -- extracted traffic",
                # Only meaningful if the diagram and the diagnostic JSON end
                # up in the same directory -- true by default, since
                # diagram_dir falls back to output_dir above. If you pass a
                # different diagram_dir, this relative link will be wrong;
                # pass your own evidence_link_base via generate_diagram()
                # directly in that case instead of going through run_pipeline.
                evidence_link_base=(
                    "03c_evidence_matcher_output.json"
                    if output_dir is not None and (diagram_dir is None or diagram_dir == output_dir)
                    else None
                ),
            )
        except Exception:
            # Deliberately non-fatal: a diagram-generation bug shouldn't
            # take down a pipeline run that otherwise succeeded. Rendering
            # failures inside generate_diagram() are already non-fatal on
            # their own (see renderer.py); this guards the D2-source-build
            # step itself.
            logger.exception("Visualizer raised an exception -- continuing without a diagram.")
        stage_elapsed = time.monotonic() - stage_start

        if visualizer_result is not None:
            logger.info(
                "Visualizer done in %.2fs: wrote %s, rendered %s",
                stage_elapsed, visualizer_result.d2_path,
                list(visualizer_result.rendered_paths.values()) or "(nothing -- see warnings above)",
            )
    else:
        logger.info("Visualizer SKIPPED -- run_visualizer=False.")

    # ---------------------------------------------------------------- #
    # Stage 4/4: Validator
    # ---------------------------------------------------------------- #
    logger.info("--- Stage 4/4: Validator ---")
    if run_validator and validator_llm_client is not None:
        from Validator.validator import Validator  # lazy: see run_validator's docstring above

        stage_start = time.monotonic()
        try:
            validator = Validator(llm_client=validator_llm_client)
            validator_assessment = validator.validate(
                attack_description, resolved_actors, grounded_steps, fingerprint_index,
            )
        except Exception:
            logger.exception("Stage 4/4 (Validator) raised an exception -- aborting pipeline.")
            raise
        stage_elapsed = time.monotonic() - stage_start

        logger.info(
            "Validator done in %.2fs: %d extraction flag(s), %d linkage flag(s) "
            "(reviewed %d steps)",
            stage_elapsed, len(validator_assessment.extraction_flags),
            len(validator_assessment.linkage_flags), validator_assessment.total_steps_reviewed,
        )
        for f in validator_assessment.extraction_flags:
            logger.warning("  [extraction:%s] step_id=%s text_span=%r reason=%s",
                            f.kind, f.step_id, f.text_span, f.reason)
        for f in validator_assessment.linkage_flags:
            logger.warning("  [linkage:%s] step_id=%s reason=%s", f.kind, f.step_id, f.reason)

        _write_diagnostic(output_dir, "04_validator_output.json", asdict(validator_assessment))
    else:
        if not run_validator:
            logger.info("Validator SKIPPED -- run_validator=False (explicit opt-in required; "
                         "stage not exercised yet).")
        else:
            logger.info("Validator SKIPPED -- run_validator=True but no validator_llm_client "
                         "provided (there is no degraded fallback mode for this stage).")
        validator_assessment = ValidatorAssessment(
            extraction_flags=[], linkage_flags=[], total_steps_reviewed=0,
        )

    total_elapsed = time.monotonic() - pipeline_start
    logger.info("=" * 70)
    logger.info("PIPELINE COMPLETE in %.2fs", total_elapsed)
    logger.info("=" * 70)

    result = PipelineResult(
        reducer_output=reducer_output,
        actors=actors,
        steps=steps,
        resolved_actors=resolved_actors,
        grounded_steps=grounded_steps,
        validator_assessment=validator_assessment,
        visualizer_result=visualizer_result,
    )

    _write_diagnostic(output_dir, "05_final_pipeline_output.json", result.to_dict())

    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _build_arg_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="pipeline_runner",
        description="Run the full PAnGEA pipeline (Preprocessor -> Step "
                    "Extractor -> Evidence Matcher -> Visualizer -> Validator) "
                    "on a PCAP and a traffic description.",
    )
    parser.add_argument("pcap_path", type=str, help="Path to the input .pcap/.pcapng file")
    parser.add_argument("--description", type=str, default=None,
                         help="Traffic description text, given directly on the command line.")
    parser.add_argument("--description-file", type=str, default=None,
                         help="Path to a text file containing the description.")
    parser.add_argument("--token-budget", type=int, default=4000,
                         help="Final token budget for Preprocessor's output (default: 4000).")
    parser.add_argument("--filtering-limit", type=int, default=3,
                         help="Raw samples retained per fingerprint before aggregating (default: 3).")
    parser.add_argument("--openai-api-key", type=str, default=None,
                         help="OpenAI API key. Falls back to OPENAI_API_KEY env var if omitted.")
    parser.add_argument("--model", type=str, default="gpt-4o",
                         help="OpenAI model to use for all LLM-backed stages (default: gpt-4o).")
    parser.add_argument("--no-evidence-matcher-llm", action="store_true",
                         help="Run Evidence Matcher offline (heuristic only, no escalation).")
    parser.add_argument("--run-validator", action="store_true",
                         help="Opt in to running the Validator stage (skipped by default -- "
                              "it's not ready to be exercised yet).")
    parser.add_argument("-o", "--output", type=str, default="pipeline_output.json",
                         help="Path to write the full pipeline result as JSON.")
    parser.add_argument(
        "--output-dir", type=str, default=None,
        help="If set, also writes one JSON file per stage into this "
             "directory (01_preprocessing_output.json, "
             "02_step_extractor_output.json, 03a_ip_summary.json, "
             "03b_anomalies.json, 03c_evidence_matcher_output.json, "
             "04_validator_output.json, 05_final_pipeline_output.json) "
             "for step-by-step inspection of what each stage produced. "
             "Not written at all if omitted.",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Enable DEBUG-level logging (per-step/per-actor detail).")
    parser.add_argument("--no-diagram", action="store_true",
                         help="Skip the Visualizer stage entirely (traffic diagram is built by default).")
    parser.add_argument("--diagram-dir", type=str, default=None,
                         help="Directory to write the traffic diagram (.d2 source + rendered images) "
                              "into. Defaults to --output-dir if set, otherwise the current directory.")
    parser.add_argument("--diagram-format", action="append", choices=["svg", "png"], default=None,
                         help="Image format to render the diagram to; repeatable "
                              "(e.g. --diagram-format svg --diagram-format png). Default: svg.")
    parser.add_argument("--evaluate", action="store_true",
                         help="After the pipeline run completes, score it against a gold sample "
                              "using the Evaluator -- in-memory, no need to re-read the diagnostic "
                              "JSON files back off disk. Requires --gold.")
    parser.add_argument("--gold", type=str, default=None,
                         help="Path to a gold sample: either a gold_sample.json, or a filled-in "
                              "gold_sample_template.xlsx directly (auto-converted in-memory, no "
                              "separate conversion step needed -- detected by file extension). "
                              "Required if --evaluate is set; ignored otherwise.")
    parser.add_argument("--evaluation-output", type=str, default=None,
                         help="Path to write the Evaluator's report as JSON. If omitted while "
                              "--evaluate is set, the report is only printed to the console, not saved.")
    parser.add_argument("--alignment-similarity", choices=["tfidf", "embedding", "local_embedding"], default="tfidf",
                         help="Similarity method for the Evaluator's claim/actor alignment "
                              "(default: tfidf, no extra dependency). 'embedding' needs "
                              "OPENAI_API_KEY (external API call); 'local_embedding' runs fully "
                              "locally via sentence-transformers (pip install sentence-transformers, "
                              "no API key). Both likely need --alignment-threshold re-tuned, since "
                              "neither is on the same similarity scale as TF-IDF's -- the printed "
                              "rubric-test result (run automatically alongside --evaluate) shows "
                              "where this method's scores actually fall, to pick a threshold from "
                              "real data rather than guessing.")
    parser.add_argument("--alignment-threshold", type=float, default=0.15,
                         help="Minimum similarity score for the Evaluator to count two claims/actors "
                              "as a match (default: 0.15, tuned for --alignment-similarity=tfidf).")
    return parser


def main():
    import json
    import os
    import sys
    from pathlib import Path

    parser = _build_arg_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    pcap_path = Path(args.pcap_path)
    if not pcap_path.exists():
        logger.error("PCAP file not found: %s", pcap_path)
        sys.exit(1)

    if args.description_file:
        desc_path = Path(args.description_file)
        if not desc_path.exists():
            logger.error("Description file not found: %s", desc_path)
            sys.exit(1)
        description = desc_path.read_text()
    elif args.description:
        description = args.description
    else:
        logger.error("Provide --description or --description-file")
        sys.exit(1)

    api_key = args.openai_api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.error(
            "An OpenAI API key is required (Step Extractor has no algorithmic "
            "fallback). Pass --openai-api-key or set OPENAI_API_KEY."
        )
        sys.exit(1)

    if args.evaluate and not args.gold:
        logger.error("--evaluate requires --gold (path to a gold_sample.json).")
        sys.exit(1)

    from shared.llm_client import OpenAIClient

    step_extractor_client = OpenAIClient(api_key=api_key, model=args.model)
    evidence_matcher_client = None if args.no_evidence_matcher_llm else \
        OpenAIClient(api_key=api_key, model=args.model)
    validator_client = OpenAIClient(api_key=api_key, model=args.model) if args.run_validator else None

    result = run_pipeline(
        pcap_bytes=pcap_path.read_bytes(),
        attack_description=description,
        token_budget=args.token_budget,
        step_extractor_llm_client=step_extractor_client,
        evidence_matcher_llm_client=evidence_matcher_client,
        validator_llm_client=validator_client,
        run_validator=args.run_validator,
        filtering_limit=args.filtering_limit,
        filter_generator_llm_client=None,
        output_dir=args.output_dir,
        run_visualizer=not args.no_diagram,
        diagram_dir=args.diagram_dir,
        diagram_formats=tuple(args.diagram_format) if args.diagram_format else ("svg",),
    )

    output_path = Path(args.output)
    output_path.write_text(json.dumps(result.to_dict(), indent=2, default=str))
    logger.info("Wrote full pipeline result to: %s", output_path)

    if args.evaluate:
        logger.info("--- Evaluate mode: scoring this run against %s ---", args.gold)
        try:
            report, rubric_result = run_evaluation(
                result, result.reducer_output, args.gold,
                alignment_threshold=args.alignment_threshold,
                similarity=args.alignment_similarity,
            )
        except Exception:
            logger.exception("Evaluation raised an exception -- pipeline result above is still valid, "
                              "just unscored.")
            return
        print(report.to_text())
        print()
        print(rubric_result.to_text())
        if not rubric_result.all_passed:
            logger.warning(
                "The rubric test found ordering-constraint failures for --alignment-similarity=%s "
                "-- the P/R numbers above may not be trustworthy for this method. See the rubric "
                "output for exactly which constraint(s) failed.",
                args.alignment_similarity,
            )
        if args.evaluation_output:
            eval_path = Path(args.evaluation_output)
            combined = {"evaluation_report": json.loads(report.to_json()), "rubric_test": rubric_result.to_dict()}
            eval_path.write_text(json.dumps(combined, indent=2))
            logger.info("Wrote evaluation report (+ rubric test) to: %s", eval_path)


if __name__ == "__main__":
    main()