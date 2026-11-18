"""
The analysis service: one versioned, saved pass over one run.

  Responsibility: load a run's stored calls, re-execute what the capture
  can answer, compute every metric, and store the result under an id that
  identifies what produced it.

  An analysis is identified by (run_id, params_hash, code_version). That
  triple is the whole reproducibility claim: the same responses, the same
  parameters and the same code give the same analysis id and -- by the
  replay test -- the same numbers. Change a parameter and you get a
  different analysis beside the old one, never a silently rewritten one.

  Parameters come from the configuration, never from a literal in this
  code. Where the owner has not chosen one yet, the sentinel UNSET travels
  through as None and the metrics that need it are stored as pending with
  the reason, rather than being computed against a number this code
  invented.

  Three modes:
    analyse()   compute and store.
    what_if()   compute with overridden parameters and store nothing. It is
                for asking "what would this look like with 5000 resamples",
                which is a legitimate question and a terrible thing to
                leave in the record as though it were the analysis.
    diff()      two stored analyses, metric by metric, with what changed.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..config import UNSET, Config
from ..ids import content_hash, content_id
from ..manifest import REPO_ROOT
from ..pcap import PcapService, PcapServiceError
from ..storage.db import Database
from ..storage.repository import utc_now
from .evidence import CallFact, EvidenceChecker
from .metrics import CallView, ItemView, MetricRow, MetricSet, fragile_items

#: Bumped whenever a metric's definition changes. It is part of the
#: analysis id, so an old analysis keeps its own number and a new
#: definition cannot quietly overwrite what an earlier one reported.
ANALYSIS_CODE_VERSION = "b5.1"


class AnalysisError(RuntimeError):
    """Something the analysis refuses to do, rather than guess at."""


def _number(value: Any) -> float | None:
    """A configured number, or None where the owner has not chosen one."""
    if value is None or value == UNSET:
        return None
    return float(value)


@dataclass(frozen=True)
class AnalysisParams:
    """
    Every knob the analysis has, all of them from configuration.

    Stored verbatim with the analysis and hashed into its id, so a number
    on the dashboard can always be traced to the parameters it was computed
    under -- including the ones the owner has not set, which are stored as
    null and make the metrics that need them pending.
    """

    unit: str = "family"
    majority_threshold: float = 0.5
    bootstrap_resamples: int = 2000
    bootstrap_seed: int = 0
    confidence_levels: int = 5
    min_items_for_rate: int = 3
    ci_z: float = 1.96
    max_capture_mb: float = 120.0
    reexecution_limit: int = 200
    max_cited_packets: int = 100
    equivalence_margin_flip_rate: float | None = None
    equivalence_margin_accuracy_points: float | None = None

    @classmethod
    def from_config(cls, config: Config, overrides: dict[str, Any] | None = None) -> "AnalysisParams":
        values = dict(
            unit=str(config.get("analysis.unit", "family")),
            majority_threshold=float(config.get("analysis.majority_threshold", 0.5)),
            bootstrap_resamples=int(config.get("analysis.bootstrap_resamples", 2000)),
            bootstrap_seed=int(config.get("analysis.bootstrap_seed", config.get("run.seed", 0))),
            confidence_levels=int(config.get("analysis.confidence_levels", 5)),
            min_items_for_rate=int(config.get("analysis.min_items_for_rate", 3)),
            ci_z=float(config.get("analysis.ci_z", 1.96)),
            max_capture_mb=float(config.get("analysis.max_capture_mb", 120)),
            reexecution_limit=int(config.get("analysis.reexecution_limit", 200)),
            max_cited_packets=int(config.get("analysis.max_cited_packets", 100)),
            equivalence_margin_flip_rate=_number(config.get("thresholds.equivalence_margin.flip_rate")),
            equivalence_margin_accuracy_points=_number(
                config.get("thresholds.equivalence_margin.accuracy_points")
            ),
        )
        return cls(**values).with_overrides(overrides)

    def with_overrides(self, overrides: dict[str, Any] | None) -> "AnalysisParams":
        """Apply what-if overrides, with the field's own type."""
        if not overrides:
            return self
        values = asdict(self)
        for key, raw in overrides.items():
            if key not in values:
                raise AnalysisError(f"unknown analysis parameter {key!r}; known: {', '.join(sorted(values))}")
            current = values[key]
            try:
                if isinstance(current, bool):
                    values[key] = str(raw).lower() in ("1", "true", "yes")
                elif isinstance(current, int) and not isinstance(current, bool):
                    values[key] = int(raw)
                elif isinstance(current, float) or current is None:
                    values[key] = None if raw in (None, "", "null") else float(raw)
                else:
                    values[key] = str(raw)
            except (TypeError, ValueError) as exc:
                raise AnalysisError(f"{key}={raw!r} is not a valid value: {exc}") from exc
        return AnalysisParams(**values)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def params_hash(self) -> str:
        return content_hash(self.as_dict())


@dataclass
class AnalysisResult:
    """What one pass produced, stored or not."""

    analysis_id: str
    run_id: str
    params: AnalysisParams
    code_version: str
    metrics: list[MetricRow]
    facts: dict[str, CallFact]
    persisted: bool
    created_at: str
    notes: list[str]

    def metric_map(self) -> dict[tuple[str, str, str], MetricRow]:
        return {row.key(): row for row in self.metrics}

    def summary(self) -> dict[str, Any]:
        """A small, printable account of the pass."""
        statuses: dict[str, int] = {}
        for fact in self.facts.values():
            statuses[fact.status] = statuses.get(fact.status, 0) + 1
        return {
            "analysis_id": self.analysis_id,
            "run_id": self.run_id,
            "code_version": self.code_version,
            "params_hash": self.params.params_hash,
            "params": self.params.as_dict(),
            "persisted": self.persisted,
            "created_at": self.created_at,
            "calls_analysed": len(self.facts),
            "call_facts_by_status": dict(sorted(statuses.items())),
            "metrics": len(self.metrics),
            "pending": sorted(
                f"{row.scope}:{row.metric}" for row in self.metrics
                if row.value is None and row.detail.get("status") == "pending"
            ),
            "notes": self.notes,
        }


# -- loading ----------------------------------------------------------------

def latest_run_id(db: Database) -> str | None:
    row = db.one("SELECT run_id FROM runs ORDER BY created_at DESC, rowid DESC LIMIT 1")
    return row["run_id"] if row else None


def _parsed(row: dict[str, Any]) -> dict[str, Any]:
    if row["format_error"] or not row["parsed"]:
        return {}
    try:
        payload = json.loads(row["parsed"])
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def load_views(db: Database, run_id: str) -> tuple[list[CallView], dict[str, ItemView], dict[str, dict[str, Any]], str | None]:
    """Calls, items, the captures behind them, and the reference prompt."""
    labels = {
        row["prompt_id"]: (row["label"], row["dimension"])
        for row in db.query("SELECT prompt_id, label, dimension FROM prompt_variants")
    }
    items: dict[str, ItemView] = {}
    captures: dict[str, dict[str, Any]] = {}
    for row in db.query(
        """
        SELECT p.pair_id, p.pcap_id, p.pair_type, p.expected, p.expected_basis, p.level,
               pc.path, pc.size_bytes, pc.packet_count, pc.sha256
          FROM pairs p LEFT JOIN pcaps pc ON pc.pcap_id = p.pcap_id
         ORDER BY p.pair_id
        """
    ):
        items[row["pair_id"]] = ItemView(
            pair_id=row["pair_id"], pcap_id=row["pcap_id"], pair_type=row["pair_type"],
            expected=row["expected"], expected_basis=row["expected_basis"], level=int(row["level"]),
        )
        if row["pcap_id"] and row["pcap_id"] not in captures:
            captures[row["pcap_id"]] = {
                "pcap_id": row["pcap_id"], "path": row["path"], "size_bytes": row["size_bytes"],
                "packet_count": row["packet_count"], "sha256": row["sha256"],
            }

    calls: list[CallView] = []
    for row in db.query("SELECT * FROM calls WHERE run_id = ? ORDER BY call_id", (run_id,)):
        record = dict(row)
        payload = _parsed(record)
        verdict = payload.get("verdict")
        survey = payload.get("survey") or {}
        confidence = survey.get("confidence") if isinstance(survey, dict) else None
        label, dimension = labels.get(record["prompt_id"], (record["prompt_id"], ""))
        calls.append(
            CallView(
                call_id=record["call_id"],
                pair_id=record["pair_id"],
                model_id=record["model_id"],
                family=record["model_family"],
                prompt_id=record["prompt_id"],
                prompt_label=label,
                dimension=dimension,
                repeat=int(record["repeat"]),
                verdict=verdict if verdict in ("SUPPORTED", "REFUTED", "NOT_VERIFIABLE") else None,
                confidence=int(confidence) if isinstance(confidence, (int, float)) else None,
                format_error=bool(record["format_error"]),
                tool_error=bool(record["error"]),
                condition=str(payload.get("condition") or ""),
                cited=[p for p in (payload.get("cited_packets") or []) if isinstance(p, int)],
            )
        )

    # The reference variant for the prompt comparison: the one whose
    # dimension says it is the baseline, else the first by label, which is
    # recorded with every number computed against it.
    used = {call.prompt_id for call in calls}
    base = sorted(p for p in used if labels.get(p, ("", ""))[1] == "base")
    reference = base[0] if base else (sorted(used, key=lambda p: labels.get(p, (p, ""))[0])[0] if used else None)
    return calls, items, captures, reference


# -- the pass ----------------------------------------------------------------

def analyse(
    db: Database,
    *,
    run_id: str | None = None,
    config: Config | None = None,
    params: AnalysisParams | None = None,
    overrides: dict[str, Any] | None = None,
    service: PcapService | None = None,
    repo_root: Path | None = None,
    persist: bool = True,
) -> AnalysisResult:
    """Analyse one run. Stores the result unless `persist` is false."""
    config = config or Config.load()
    params = (params or AnalysisParams.from_config(config)).with_overrides(overrides)
    run_id = run_id or latest_run_id(db)
    if run_id is None:
        raise AnalysisError("no run is stored; nothing to analyse")
    if db.one("SELECT run_id FROM runs WHERE run_id = ?", (run_id,)) is None:
        raise AnalysisError(f"no run {run_id!r}")

    root = repo_root or REPO_ROOT
    notes: list[str] = []
    if service is None:
        try:
            service = PcapService.from_config(config, db=db, repo_root=root)
        except PcapServiceError as exc:
            # Not fatal: everything computed from the stored responses alone
            # still is, and every evidence fact says why it is missing.
            notes.append(f"tshark unavailable, so no condition was re-executed: {exc}")

    calls, items, captures, reference = load_views(db, run_id)
    if not calls:
        raise AnalysisError(f"run {run_id} has no stored calls")

    checker = EvidenceChecker(
        service=service,
        repo_root=root,
        max_capture_bytes=int(params.max_capture_mb * 1_000_000) if params.max_capture_mb else None,
        reexecution_limit=params.reexecution_limit,
        max_cited_packets=params.max_cited_packets,
    )
    packet_counts = _packet_counts(service, root, captures, notes)

    facts: dict[str, CallFact] = {}
    for call in calls:
        item = items.get(call.pair_id)
        capture = captures.get(item.pcap_id) if item and item.pcap_id else None
        facts[call.call_id] = checker.fact(
            call_id=call.call_id,
            capture=capture,
            packet_count=packet_counts.get(capture["pcap_id"]) if capture else None,
            condition=call.condition,
            cited=call.cited,
            verdict=call.verdict,
        )

    metric_set = MetricSet(
        run_id=run_id, calls=calls, items=items, facts=facts, params=params,
        reference_prompt=reference, fact_status_counts=checker.counts,
    )
    metrics = metric_set.compute() + fragile_items(run_id, calls, params)

    analysis_id = content_id("ana", [run_id, params.params_hash, ANALYSIS_CODE_VERSION])
    result = AnalysisResult(
        analysis_id=analysis_id, run_id=run_id, params=params, code_version=ANALYSIS_CODE_VERSION,
        metrics=metrics, facts=facts, persisted=False, created_at=utc_now(), notes=notes,
    )
    if persist:
        store(db, result)
        result.persisted = True
    return result


def _packet_counts(
    service: PcapService | None, root: Path, captures: dict[str, dict[str, Any]], notes: list[str]
) -> dict[str, int]:
    """
    How many packets each capture holds -- the registry's count, or the
    file's own, read once per capture through the PCAP service.

    Fabrication is defined against this number, so a capture whose count
    nobody has read yields no fabrication figure at all rather than one
    measured against a guess.
    """
    counts: dict[str, int] = {}
    for pcap_id, capture in sorted(captures.items()):
        if capture.get("packet_count") is not None:
            counts[pcap_id] = int(capture["packet_count"])
            continue
        if service is None:
            continue
        try:
            counts[pcap_id] = service.summary(root / capture["path"]).packet_count
        except PcapServiceError as exc:
            notes.append(f"{capture['path']}: packet count unavailable ({exc}); fabrication is not counted there")
    return counts


# -- storage -----------------------------------------------------------------

def store(db: Database, result: AnalysisResult) -> None:
    """
    Write an analysis, replacing any earlier pass with the same id.

    Replacing is allowed precisely because these are derived tables: the
    same id means the same run, parameters and code, so a rewrite can only
    reproduce what was there. Raw data has no such door.
    """
    with db.conn:
        db.conn.execute("DELETE FROM analysis_metrics WHERE analysis_id = ?", (result.analysis_id,))
        db.conn.execute("DELETE FROM analysis_call_facts WHERE analysis_id = ?", (result.analysis_id,))
        db.conn.execute("DELETE FROM analyses WHERE analysis_id = ?", (result.analysis_id,))
        db.conn.execute(
            "INSERT INTO analyses(analysis_id, run_id, params, params_hash, code_version, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (result.analysis_id, result.run_id, json.dumps(result.params.as_dict(), sort_keys=True),
             result.params.params_hash, result.code_version, result.created_at),
        )
        for fact in result.facts.values():
            row = fact.as_row(result.analysis_id)
            db.conn.execute(
                f"INSERT INTO analysis_call_facts ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                tuple(row.values()),
            )
        for metric in result.metrics:
            row = metric.as_row(result.analysis_id)
            db.conn.execute(
                f"INSERT INTO analysis_metrics ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                tuple(row.values()),
            )


def what_if(
    db: Database,
    *,
    run_id: str | None = None,
    overrides: dict[str, Any],
    config: Config | None = None,
    service: PcapService | None = None,
) -> AnalysisResult:
    """Recompute with different parameters and store nothing."""
    return analyse(db, run_id=run_id, config=config, overrides=overrides, service=service, persist=False)


# -- reading back -------------------------------------------------------------

def list_analyses(db: Database, run_id: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT * FROM analyses"
    params: tuple[Any, ...] = ()
    if run_id:
        sql += " WHERE run_id = ?"
        params = (run_id,)
    rows = []
    for row in db.query(sql + " ORDER BY created_at DESC, rowid DESC", params):
        record = dict(row)
        record["params"] = json.loads(record["params"])
        record["metrics"] = db.one(
            "SELECT COUNT(*) n FROM analysis_metrics WHERE analysis_id = ?", (record["analysis_id"],)
        )["n"]
        rows.append(record)
    return rows


def latest_analysis(db: Database, run_id: str | None = None) -> dict[str, Any] | None:
    analyses = list_analyses(db, run_id)
    return analyses[0] if analyses else None


def load_metrics(db: Database, analysis_id: str) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Stored metrics, keyed by (scope, scope_id, metric), details parsed."""
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in db.query("SELECT * FROM analysis_metrics WHERE analysis_id = ? ORDER BY scope, scope_id, metric",
                        (analysis_id,)):
        record = dict(row)
        record["detail"] = json.loads(record["detail"] or "{}")
        out[(record["scope"], record["scope_id"], record["metric"])] = record
    return out


def load_call_facts(db: Database, analysis_id: str, call_ids: list[str] | None = None) -> dict[str, dict[str, Any]]:
    """Stored per-call facts, keyed by call id, with the JSON columns parsed."""
    sql = "SELECT * FROM analysis_call_facts WHERE analysis_id = ?"
    params: list[Any] = [analysis_id]
    if call_ids:
        sql += f" AND call_id IN ({', '.join('?' * len(call_ids))})"
        params += call_ids
    out: dict[str, dict[str, Any]] = {}
    for row in db.query(sql, tuple(params)):
        record = dict(row)
        for column in ("reexecuted_packets", "cited_verified", "cited_unverified"):
            record[column] = json.loads(record[column] or "[]")
        for column in ("sufficiency_ok", "necessity_ok"):
            record[column] = None if record[column] is None else bool(record[column])
        record["truncated"] = bool(record["truncated"])
        out[record["call_id"]] = record
    return out


# -- diffing -------------------------------------------------------------------

def diff(db: Database, left_id: str, right_id: str) -> dict[str, Any]:
    """
    Compare two stored analyses, metric by metric.

    What it is for: a parameter moved, or the code version changed, and the
    question is which numbers that actually touched. Metrics present in
    only one of the two are listed as added or removed rather than treated
    as a change from zero.
    """
    left_row = db.one("SELECT * FROM analyses WHERE analysis_id = ?", (left_id,))
    right_row = db.one("SELECT * FROM analyses WHERE analysis_id = ?", (right_id,))
    for analysis_id, row in ((left_id, left_row), (right_id, right_row)):
        if row is None:
            raise AnalysisError(f"no stored analysis {analysis_id!r}")

    left, right = load_metrics(db, left_id), load_metrics(db, right_id)
    left_params = json.loads(left_row["params"])
    right_params = json.loads(right_row["params"])
    param_changes = {
        key: {"from": left_params.get(key), "to": right_params.get(key)}
        for key in sorted(set(left_params) | set(right_params))
        if left_params.get(key) != right_params.get(key)
    }

    changed, unchanged = [], 0
    for key in sorted(set(left) & set(right)):
        a, b = left[key], right[key]
        if a["value"] == b["value"] and a["n"] == b["n"] and a["ci_low"] == b["ci_low"] and a["ci_high"] == b["ci_high"]:
            unchanged += 1
            continue
        delta = (
            None if a["value"] is None or b["value"] is None
            else b["value"] - a["value"]
        )
        changed.append(
            {
                "scope": key[0], "scope_id": key[1], "metric": key[2],
                "from": {"value": a["value"], "n": a["n"], "ci_low": a["ci_low"], "ci_high": a["ci_high"]},
                "to": {"value": b["value"], "n": b["n"], "ci_low": b["ci_low"], "ci_high": b["ci_high"]},
                "delta": delta,
                "note": _why_changed(a, b, param_changes),
            }
        )
    changed.sort(key=lambda c: (-(abs(c["delta"]) if c["delta"] is not None else 0.0), c["scope"], c["metric"]))

    return {
        "left": {"analysis_id": left_id, "run_id": left_row["run_id"], "code_version": left_row["code_version"],
                 "params_hash": left_row["params_hash"], "created_at": left_row["created_at"]},
        "right": {"analysis_id": right_id, "run_id": right_row["run_id"], "code_version": right_row["code_version"],
                  "params_hash": right_row["params_hash"], "created_at": right_row["created_at"]},
        "same_run": left_row["run_id"] == right_row["run_id"],
        "code_version_changed": left_row["code_version"] != right_row["code_version"],
        "parameter_changes": param_changes,
        "changed": changed,
        "unchanged": unchanged,
        "added": [list(key) for key in sorted(set(right) - set(left))],
        "removed": [list(key) for key in sorted(set(left) - set(right))],
    }


def _why_changed(left: dict[str, Any], right: dict[str, Any], param_changes: dict[str, Any]) -> str:
    """
    A short, honest account of what a difference can be attributed to.

    It names candidates; it does not pretend to know. The alternative --
    silently showing two numbers side by side -- leaves the reader to guess
    whether a changed interval means a changed sample or a changed seed.
    """
    reasons = []
    if left["n"] != right["n"]:
        reasons.append(f"n moved from {left['n']} to {right['n']}")
    if left["value"] == right["value"] and (left["ci_low"], left["ci_high"]) != (right["ci_low"], right["ci_high"]):
        reasons.append("the estimate is identical; only the interval moved")
    for key in ("bootstrap_resamples", "bootstrap_seed", "ci_z", "majority_threshold", "unit"):
        if key in param_changes:
            reasons.append(f"{key} changed ({param_changes[key]['from']} -> {param_changes[key]['to']})")
    return "; ".join(reasons)
