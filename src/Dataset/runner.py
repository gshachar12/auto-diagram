"""
The run: models x prompts x pairs x repeats.

  Responsibility: decide what to call, call it, and store every outcome.

  Properties that matter more than speed here:

    Idempotent.  A unit is keyed by (run, pair, model, prompt, repeat) and
                 the database enforces that key, so re-running a run can
                 only fill gaps -- it can never double-count an answer.
    Resumable.   Work already stored is skipped on the next start, so a
                 crash, a rate limit or a pause costs only the unit in
                 flight.
    Pausable.    Status is a stream of run_events; the loop checks the
                 latest one between units, so `./pangea run --pause` stops
                 it without killing anything mid-call.
    Randomised but balanced. Units are shuffled with the run's seed, so
                 order effects cannot line up with any one model, prompt or
                 item -- and the shuffle is reproducible.
    Dry-runnable. The plan and a token/cost estimate print without a single
                 API call, because finding out what a run costs should not
                 cost anything.

  Nothing is dropped. A transport failure, a refusal, an unparseable answer
  and a tool error are all stored as rows with `error` or `format_error`
  set; they are what the operational metrics are computed from.
"""
from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .config import Config
from .ids import content_id
from .manifest import REPO_ROOT, build_manifest
from .models.base import ModelAdapter, ModelRequest, parse_answer
from .models.mock import MockModel
from .models.providers import ProviderError, build_adapter
from .pcap import PcapService, PcapServiceError
from .prompts import PromptBuilder, scan_for_leaks
from .schemas import CallRecord, ModelSpec
from .storage.db import Database
from .storage.repository import Repository, utc_now

#: Rough characters-per-token, used only for the dry-run estimate. Labelled
#: as an estimate everywhere it surfaces; the real counts come from the
#: providers' own usage fields.
CHARS_PER_TOKEN = 4


@dataclass(frozen=True)
class Unit:
    """One call to make."""

    pair_id: str
    model_id: str
    prompt_label: str
    repeat: int

    def key(self, run_id: str) -> str:
        return f"{run_id}:{self.pair_id}:{self.model_id}:{self.prompt_label}:{self.repeat}"


class RunPaused(RuntimeError):
    """The run was asked to stop, and did, between units."""


class Runner:
    def __init__(
        self,
        *,
        db: Database,
        config: Config,
        results_path: str | Path,
        service: PcapService | None = None,
        builder: PromptBuilder | None = None,
        adapters: dict[str, ModelAdapter] | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.repo = Repository(db, results_path=results_path)
        self.service = service
        self.builder = builder or PromptBuilder()
        self.root = repo_root or REPO_ROOT
        self._adapters = adapters or {}

    # -- planning ----------------------------------------------------------

    def pairs(self) -> list[dict[str, Any]]:
        """
        The items to ask about: every pair whose claim is not rejected.

        A rejected claim keeps its row but never reaches a model, and a
        superseded claim is replaced by the version that superseded it.
        """
        rejected = {
            row["claim_id"]
            for row in self.db.query("SELECT claim_id FROM claim_reviews WHERE action = 'reject'")
        }
        superseded = {
            row["supersedes"]
            for row in self.db.query("SELECT supersedes FROM claims WHERE supersedes IS NOT NULL")
        }
        rows = []
        for row in self.db.query(
            """
            SELECT p.*, c.atomic_text, c.source_id, s.title AS source_title
              FROM pairs p JOIN claims c ON c.claim_id = p.claim_id
              JOIN sources s ON s.source_id = c.source_id
             ORDER BY p.pair_id
            """
        ):
            if row["claim_id"] in rejected or row["claim_id"] in superseded:
                continue
            rows.append(dict(row))
        return rows

    def plan(self, *, models: list[str] | None = None, prompts: list[str] | None = None) -> list[Unit]:
        repeats = int(self.config.get("run.repeats", 2))
        model_ids = models or [m.model_id for m in self.config.models]
        prompt_labels = prompts or [v.label for v in self.builder.variants]
        units = [
            Unit(pair["pair_id"], model_id, label, repeat)
            for pair in self.pairs()
            for model_id in model_ids
            for label in prompt_labels
            for repeat in range(repeats)
        ]
        if self.config.get("run.randomize_order", True):
            random.Random(int(self.config.get("run.seed", 0))).shuffle(units)
        return units

    def estimate(self, units: list[Unit]) -> dict[str, Any]:
        """
        A dry run: what would be called, how big, and what it might cost.

        The token figure is an estimate from the rendered prompt length and
        is labelled as one. The cost is None for any model with no
        configured price -- an invented price would make the estimate worse
        than useless.
        """
        pairs = {pair["pair_id"]: pair for pair in self.pairs()}
        per_model: dict[str, dict[str, Any]] = {}
        for unit in units:
            pair = pairs.get(unit.pair_id)
            if pair is None:
                continue
            rendered = self.render(pair, unit.prompt_label)
            tokens_in = len(rendered.full_text) // CHARS_PER_TOKEN
            entry = per_model.setdefault(
                unit.model_id, {"calls": 0, "tokens_in_estimate": 0, "tokens_out_estimate": 0}
            )
            entry["calls"] += 1
            entry["tokens_in_estimate"] += tokens_in
            entry["tokens_out_estimate"] += 400  # the output schema is small and bounded

        for model_id, entry in per_model.items():
            raw = self.config.model_raw.get(model_id, {})
            price_in, price_out = raw.get("price_per_mtok_in"), raw.get("price_per_mtok_out")
            entry["cost_estimate"] = (
                None if price_in is None or price_out is None
                else round(entry["tokens_in_estimate"] / 1e6 * price_in
                           + entry["tokens_out_estimate"] / 1e6 * price_out, 4)
            )
            entry["model_name"] = raw.get("model_name")
        return {
            "units": len(units),
            "pairs": len(pairs),
            "per_model": per_model,
            "note": "token figures are estimates from prompt length; costs are null where no price is configured",
        }

    # -- rendering ---------------------------------------------------------

    def capture_view(self, pair: dict[str, Any]) -> dict[str, Any] | None:
        if not pair.get("pcap_id"):
            return None
        row = self.db.one("SELECT * FROM pcaps WHERE pcap_id = ?", (pair["pcap_id"],))
        if row is None:
            return None
        record = dict(row)
        record["capture_metadata"] = json.loads(record["capture_metadata"])
        return PromptBuilder.capture_view(record)

    def render(self, pair: dict[str, Any], prompt_label: str):
        variant = self.builder.variant(prompt_label)
        return self.builder.render(
            variant,
            claim_text=pair["atomic_text"],
            capture=self.capture_view(pair),
            thresholds=self.config.get("thresholds"),
        )

    def check_no_leaks(self, units: Iterable[Unit]) -> list[dict[str, Any]]:
        """
        Render every (pair, variant) that will be sent and scan it.

        Run before a run starts, not as a unit test alone: the template is
        innocent until an item is interpolated into it, and it is the
        interpolation that could carry a source title or a pair type.
        """
        pairs = {pair["pair_id"]: pair for pair in self.pairs()}
        seen: set[tuple[str, str]] = set()
        problems: list[dict[str, Any]] = []
        for unit in units:
            key = (unit.pair_id, unit.prompt_label)
            if key in seen:
                continue
            seen.add(key)
            pair = pairs.get(unit.pair_id)
            if pair is None:
                continue
            rendered = self.render(pair, unit.prompt_label)
            leaks = scan_for_leaks(
                rendered.full_text,
                expected=pair.get("expected"),
                pair_type=pair.get("pair_type"),
                source_title=pair.get("source_title"),
            )
            if leaks:
                problems.append(
                    {"pair_id": unit.pair_id, "prompt": unit.prompt_label,
                     "leaks": [leak.__dict__ for leak in leaks]}
                )
        return problems

    # -- adapters ----------------------------------------------------------

    def adapter_for(self, spec: ModelSpec, pair: dict[str, Any]) -> ModelAdapter:
        """
        One adapter per model, with the tool bound to this pair's capture.

        The executor closes over the capture rather than taking a path from
        the model: a model that could name the file could read another
        scenario's capture, which would quietly destroy the swap items.
        """
        if spec.adapter == "mock":
            return self._adapters.setdefault(spec.model_id, MockModel(spec, seed=int(self.config.get("run.seed", 0))))

        def execute(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if name != "pcap_query":
                return {"error": f"unknown tool {name!r}"}
            if self.service is None or not pair.get("pcap_id"):
                return {"match_count": 0, "packets": [], "note": "no capture is available for this item"}
            row = self.db.one("SELECT path FROM pcaps WHERE pcap_id = ?", (pair["pcap_id"],))
            try:
                result = self.service.query(
                    self.root / row["path"], arguments.get("filter", ""), limit=arguments.get("limit")
                )
            except PcapServiceError as exc:
                return {"error": str(exc)}
            return {"match_count": result.match_count, "packets": result.packets, "truncated": result.truncated}

        return build_adapter(spec, self.config.model_raw.get(spec.model_id, {}), tool_executor=execute)

    # -- the run -----------------------------------------------------------

    def create_run(self, *, label: str, units: list[Unit]) -> tuple[str, dict[str, Any]]:
        self.config.require_frozen()
        pcaps = [dict(row) for row in self.db.query("SELECT pcap_id, sha256, packet_count FROM pcaps")]
        prompts = [
            {"prompt_id": self.builder.prompt_id(v), "prompt_hash": self.builder.prompt_hash(v), "label": v.label}
            for v in self.builder.variants
        ]
        models = [
            {"model_id": m.model_id, "family": m.family, "version": m.version,
             "temperature": m.temperature, "supports_tools": m.supports_tools}
            for m in self.config.models
            if m.model_id in {u.model_id for u in units}
        ]
        run_id, manifest = build_manifest(
            config=self.config, pcaps=pcaps, prompts=prompts, models=models, label=label, repo_root=self.root
        )
        manifest["prompt_set_hash"] = self.builder.set_hash
        if self.db.one("SELECT run_id FROM runs WHERE run_id = ?", (run_id,)) is None:
            self.repo.add_run(run_id, manifest)
        return run_id, manifest

    def already_done(self, run_id: str) -> set[tuple[str, str, str, int]]:
        return {
            (row["pair_id"], row["model_id"], row["prompt_id"], row["repeat"])
            for row in self.db.query(
                "SELECT pair_id, model_id, prompt_id, repeat FROM calls WHERE run_id = ?", (run_id,)
            )
        }

    def paused(self, run_id: str, after_rowid: int = 0) -> bool:
        """
        Has a pause been asked for since this execution started?

        The rowid matters: execute() records its own "started" event, so
        asking only for the latest status would let the start cancel a
        pause requested a moment earlier -- and resuming a paused run would
        be impossible, since its latest status is always "paused".
        """
        row = self.db.one(
            "SELECT status FROM run_events WHERE run_id = ? AND rowid > ? ORDER BY rowid DESC LIMIT 1",
            (run_id, after_rowid),
        )
        return bool(row and row["status"] == "paused")

    def execute(
        self,
        run_id: str,
        units: list[Unit],
        *,
        on_progress: Callable[[int, int], None] | None = None,
        min_interval_seconds: float = 0.0,
    ) -> dict[str, Any]:
        pairs = {pair["pair_id"]: pair for pair in self.pairs()}
        specs = {m.model_id: m for m in self.config.models}
        done = self.already_done(run_id)
        self.repo.add_run_event(run_id, "started" if not done else "resumed", f"{len(done)} already stored")
        started_at = int(self.db.one("SELECT MAX(rowid) AS r FROM run_events")["r"])

        made = skipped = failures = 0
        last_call: dict[str, float] = {}
        for index, unit in enumerate(units, start=1):
            pair = pairs.get(unit.pair_id)
            spec = specs.get(unit.model_id)
            if pair is None or spec is None:
                skipped += 1
                continue
            rendered = self.render(pair, unit.prompt_label)
            if (unit.pair_id, unit.model_id, rendered.prompt_id, unit.repeat) in done:
                skipped += 1
                continue
            if self.paused(run_id, started_at):
                self.repo.add_run_event(run_id, "paused", f"stopped after {made} calls")
                raise RunPaused(f"run {run_id} paused after {made} calls")

            # Rate limit per model, so one slow provider does not throttle
            # the others.
            wait = min_interval_seconds - (time.monotonic() - last_call.get(unit.model_id, 0))
            if min_interval_seconds and wait > 0:
                time.sleep(wait)
            last_call[unit.model_id] = time.monotonic()

            try:
                adapter = self.adapter_for(spec, pair)
                result = adapter.generate(
                    ModelRequest(
                        system_prompt=rendered.system,
                        user_prompt=rendered.user,
                        call_key=unit.key(run_id),
                        temperature=spec.temperature,
                        max_output_tokens=spec.max_output_tokens,
                        tools_enabled=spec.supports_tools,
                    )
                )
            except ProviderError as exc:
                # Misconfiguration is recorded like any other failure: the
                # run continues and the gap is visible afterwards.
                from .models.base import ModelResult

                result = ModelResult(raw_text="", error=str(exc))

            parsed = parse_answer(result.raw_text)
            failures += int(bool(result.error) or parsed.format_error)
            self.repo.add_call(
                CallRecord(
                    call_id=content_id("call", [unit.key(run_id)]),
                    run_id=run_id,
                    pair_id=unit.pair_id,
                    model_id=spec.model_id,
                    model_family=spec.family,
                    model_version=spec.version,
                    prompt_id=rendered.prompt_id,
                    prompt_hash=rendered.prompt_hash,
                    prompt_rendered=rendered.full_text,
                    repeat=unit.repeat,
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
            made += 1
            if on_progress:
                on_progress(index, len(units))

        self.repo.add_run_event(run_id, "finished", f"{made} calls, {skipped} already stored")
        return {"run_id": run_id, "calls": made, "skipped": skipped, "failures": failures}
