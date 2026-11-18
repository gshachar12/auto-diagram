"""
The read model behind the dashboard.

  Responsibility: turn stored calls into the numbers the views show, and
  nothing else. Every function here reads the database and computes; none
  of them writes, and none of them asks a model anything. That is what makes
  "why this number?" answerable -- each figure traces back to call rows the
  dashboard can also display verbatim.

  Two rules the spec sets that show up directly in this code:

    A family is one unit.  Two sizes of the same model are not independent
      votes, so a verdict is first reduced per family and the panel's
      majority is computed over families, not over calls.
    Silver is not truth.  Agreement is reported as agreement. The only
      place an expectation is compared against is a control item, whose
      expected verdict is fixed by construction, and even there the wording
      is "matches expected", never "correct".

  Where the numbers come from. Anything that can be read straight off the
  stored calls is computed here. Anything that needed the capture -- the
  re-executed conditions, the verified citations, sufficiency and
  necessity -- and anything whose interval has to resample PCAPs comes from
  a stored analysis (B5), read back by `analysis_context`. If no analysis
  has been stored for a run, those sections say so and stay empty: a view
  never recomputes an analysis on the fly, because then the number on the
  screen would not be the number in the record.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from typing import Any, Iterable

from ..analysis import expected_outcome as _analysis_expected_outcome
from ..analysis import latest_analysis, list_analyses, load_call_facts, load_metrics
from ..analysis.metrics import ItemView
from ..storage.db import Database

VERDICTS = ("SUPPORTED", "REFUTED", "NOT_VERIFIABLE")

#: Fewer than this many voting families makes a majority not worth reading.
LOW_N_FAMILIES = 3


# -- small statistics ----------------------------------------------------

def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """
    95% interval for a proportion.

    Wilson rather than normal-approximation because these counts are small
    and often near 0 or 1, where the normal interval runs past the ends of
    the scale and quietly misleads.
    """
    if total == 0:
        return (0.0, 1.0)
    phat = successes / total
    denominator = 1 + z * z / total
    centre = phat + z * z / (2 * total)
    spread = z * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total))
    return (max(0.0, (centre - spread) / denominator), min(1.0, (centre + spread) / denominator))


def entropy_bits(counts: Iterable[int]) -> float:
    """Shannon entropy of a vote distribution, in bits."""
    values = [c for c in counts if c > 0]
    total = sum(values)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in values)


def _majority(votes: list[str]) -> tuple[str | None, float]:
    """The strict majority (>50%) and its share. None when there is none."""
    if not votes:
        return None, 0.0
    counts = Counter(votes)
    verdict, count = counts.most_common(1)[0]
    share = count / len(votes)
    return (verdict if share > 0.5 else None), share


def _mode(votes: list[str]) -> str | None:
    return Counter(votes).most_common(1)[0][0] if votes else None


# -- loading -------------------------------------------------------------

def _parsed_verdict(row: dict[str, Any]) -> str | None:
    """
    The verdict a call expressed, or None.

    A format error has no verdict by definition; it is counted separately
    rather than being folded into the vote as an abstention, which would
    flatter a model that merely failed to answer.
    """
    if row["format_error"] or not row["parsed"]:
        return None
    try:
        payload = json.loads(row["parsed"])
    except json.JSONDecodeError:
        return None
    verdict = payload.get("verdict")
    return verdict if verdict in VERDICTS else None


def _confidence(row: dict[str, Any]) -> int | None:
    if row["format_error"] or not row["parsed"]:
        return None
    try:
        survey = json.loads(row["parsed"]).get("survey") or {}
    except json.JSONDecodeError:
        return None
    value = survey.get("confidence")
    return int(value) if isinstance(value, (int, float)) else None


def load_run(db: Database, run_id: str | None = None) -> dict[str, Any]:
    """The newest run, or a named one, with its manifest parsed."""
    row = (
        db.one("SELECT * FROM runs WHERE run_id = ?", (run_id,))
        if run_id
        else db.one("SELECT * FROM runs ORDER BY created_at DESC, rowid DESC LIMIT 1")
    )
    if row is None:
        return {}
    return {"run_id": row["run_id"], "created_at": row["created_at"], "manifest": json.loads(row["manifest"])}


def load_calls(db: Database, run_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("SELECT * FROM calls WHERE run_id = ?", (run_id,))]


def load_pairs(db: Database) -> dict[str, dict[str, Any]]:
    pairs: dict[str, dict[str, Any]] = {}
    for row in db.query(
        """
        SELECT p.*, c.atomic_text, c.source_step_text, c.source_location, c.kind,
               c.condition, c.mutation_of, c.mutation_type, c.reason_code,
               s.title AS source_title, pc.path AS pcap_path, pc.sha256 AS pcap_sha256,
               pc.capture_metadata, pc.packet_count
          FROM pairs p
          JOIN claims c  ON c.claim_id = p.claim_id
          JOIN sources s ON s.source_id = c.source_id
          LEFT JOIN pcaps pc ON pc.pcap_id = p.pcap_id
        """
    ):
        pair = dict(row)
        pair["condition"] = json.loads(pair["condition"]) if pair["condition"] else None
        pair["capture_metadata"] = json.loads(pair["capture_metadata"]) if pair["capture_metadata"] else None
        pairs[pair["pair_id"]] = pair
    return pairs


# -- per-pair aggregation -------------------------------------------------

def _family_votes(calls: list[dict[str, Any]]) -> dict[str, str]:
    """One verdict per family: the family's own modal answer."""
    by_family: dict[str, list[str]] = defaultdict(list)
    for call in calls:
        verdict = _parsed_verdict(call)
        if verdict:
            by_family[call["model_family"]].append(verdict)
    return {family: _mode(votes) for family, votes in by_family.items() if votes}


def _expected_outcome(pair: dict[str, Any], panel_verdict: str | None) -> bool | None:
    """
    Whether a verdict matched what construction fixed, by the analysis's own rule.

    Deliberately delegated rather than reimplemented: the dashboard and the
    analysis scoring the same item differently is the kind of drift nobody
    notices until the two disagree in public, so there is one rule and this
    is a thin adapter from a row to it.

    (The rule: a swap is scored as "not SUPPORTED", since REFUTED would
    assume a closed world on a capture the claim never came from, and
    anything resting on an author's claim is not scored at all.)
    """
    item = ItemView(
        pair_id=pair["pair_id"], pcap_id=pair.get("pcap_id"), pair_type=pair["pair_type"],
        expected=pair.get("expected"), expected_basis=pair.get("expected_basis") or "none",
        level=int(pair.get("level") or 1),
    )
    return _analysis_expected_outcome(item, panel_verdict)


def summarise_pair(pair: dict[str, Any], calls: list[dict[str, Any]]) -> dict[str, Any]:
    """Everything the claims table shows for one pair."""
    family_votes = _family_votes(calls)
    votes = list(family_votes.values())
    panel_verdict, share = _majority(votes)
    confidences = [c for c in (_confidence(call) for call in calls) if c is not None]
    verdict_counts = Counter(votes)

    # A prompt flips the majority -> the item is fragile and its label is not
    # to be relied on, however confident the models sounded.
    by_prompt: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in calls:
        by_prompt[call["prompt_id"]].append(call)
    per_prompt_verdict = {
        prompt_id: _majority(list(_family_votes(prompt_calls).values()))[0]
        for prompt_id, prompt_calls in by_prompt.items()
    }
    distinct = {v for v in per_prompt_verdict.values() if v is not None}

    flags = []
    if panel_verdict is None:
        flags.append("NO_MAJORITY")
    if len(distinct) > 1:
        flags.append("FRAGILE")
    if len(family_votes) < LOW_N_FAMILIES:
        flags.append("LOW_N")
    if any(_cited(call) for call in calls):
        # Honest naming: nothing has checked these against the capture yet.
        flags.append("CITED_UNCHECKED")

    return {
        "pair_id": pair["pair_id"],
        "claim_id": pair["claim_id"],
        "atomic_text": pair["atomic_text"],
        "level": pair["level"],
        "kind": pair["kind"],
        "pair_type": pair["pair_type"],
        "mutation_type": pair["mutation_type"],
        # Carried so the Captures section can hand the reader the items
        # derived from one capture without a second query.
        "pcap_id": pair["pcap_id"],
        "expected": pair["expected"],
        "expected_basis": pair["expected_basis"],
        "source_title": pair["source_title"],
        "pcap_path": pair["pcap_path"],
        "panel_verdict": panel_verdict,
        "vote_share": share,
        "votes": dict(verdict_counts),
        "families_voting": len(family_votes),
        "entropy_bits": entropy_bits(verdict_counts.values()),
        "mean_confidence": (sum(confidences) / len(confidences)) if confidences else None,
        "n_calls": len(calls),
        "n_format_errors": sum(1 for call in calls if call["format_error"]),
        "matches_expected": _expected_outcome(pair, panel_verdict),
        "per_prompt_verdict": per_prompt_verdict,
        "flags": flags,
    }


def _cited(call: dict[str, Any]) -> list[int]:
    if call["format_error"] or not call["parsed"]:
        return []
    try:
        packets = json.loads(call["parsed"]).get("cited_packets") or []
    except json.JSONDecodeError:
        return []
    return [p for p in packets if isinstance(p, int)]


# -- reading a stored analysis --------------------------------------------

def analysis_context(db: Database, run_id: str | None = None, analysis_id: str | None = None) -> dict[str, Any]:
    """
    The analysis a view should read: a named one, or the newest for the run.

    Returns an empty context rather than raising when nothing has been
    analysed yet, so every view can say "not analysed yet" in its own words
    instead of failing.
    """
    if analysis_id:
        row = db.one("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,))
        record = dict(row) if row else None
        if record:
            record["params"] = json.loads(record["params"])
    else:
        record = latest_analysis(db, run_id)
    if not record:
        return {"analysis": None, "metrics": {}}
    return {"analysis": record, "metrics": load_metrics(db, record["analysis_id"])}


def _stat(metrics: dict, scope: str, scope_id: str, metric: str) -> dict[str, Any] | None:
    """
    One stored metric, in the shape the page's `rate()` helper reads.

    `rate` is the name the dashboard uses for the value, and `n`, `ci_low`
    and `ci_high` always travel with it -- the page has no way to render a
    bare proportion, which is the point.
    """
    row = metrics.get((scope, scope_id, metric))
    if row is None:
        return None
    return {
        "metric": metric, "scope": scope, "scope_id": scope_id,
        "rate": row["value"], "value": row["value"], "n": row["n"],
        "ci_low": row["ci_low"], "ci_high": row["ci_high"], "detail": row["detail"],
    }


def _stats_in_scope(metrics: dict, scope: str, metric: str) -> list[dict[str, Any]]:
    """Every stored row of one metric within one scope, sorted by scope id."""
    return [
        _stat(metrics, scope, scope_id, name)
        for (scope_name, scope_id, name) in sorted(metrics)
        if scope_name == scope and name == metric
    ]


def _analysis_header(context: dict[str, Any]) -> dict[str, Any] | None:
    """What the page shows about the analysis a number came from."""
    record = context.get("analysis")
    if not record:
        return None
    pending = sorted(
        f"{scope_id if scope == 'run' else scope}:{metric}"
        for (scope, scope_id, metric), row in context["metrics"].items()
        if row["value"] is None and row["detail"].get("status") == "pending"
    )
    return {
        "analysis_id": record["analysis_id"],
        "run_id": record["run_id"],
        "code_version": record["code_version"],
        "params_hash": record["params_hash"],
        "params": record["params"],
        "created_at": record["created_at"],
        "metrics": len(context["metrics"]),
        "pending": pending,
    }


NOT_ANALYSED = (
    "No analysis has been stored for this run yet. Run `./pangea analyze` -- these numbers are "
    "read from a stored, versioned analysis rather than recomputed on the fly, so that what is on "
    "the screen is what is in the record."
)


# -- the views ------------------------------------------------------------

def overview(db: Database, run_id: str | None = None) -> dict[str, Any]:
    run = load_run(db, run_id)
    if not run:
        return {"run": None, "warnings": ["no run stored yet"]}
    calls = load_calls(db, run["run_id"])
    pairs = load_pairs(db)
    unverified = db.query("SELECT COUNT(*) n FROM verification_checks WHERE status = 'unverified'")[0]["n"]
    uncounted = db.query("SELECT COUNT(*) n FROM pcaps WHERE packet_count IS NULL")[0]["n"]

    warnings = []
    if run["manifest"]["code"]["git_commit"].endswith("-dirty"):
        warnings.append("This run was made from an uncommitted working tree (git commit marked dirty).")
    if uncounted:
        warnings.append(
            f"{uncounted} capture(s) carry no packet count in the registry (`./pangea ingest` reads it "
            f"with tshark). The analysis reads the count from the file itself where it needs one, and "
            f"records no fabrication figure for a capture whose length it could not establish."
        )
    if unverified:
        warnings.append(f"{unverified} verification checklist item(s) are still unverified.")
    if run["manifest"].get("label") == "demo":
        warnings.append("DEMO dataset: synthetic claims, scripted MockModel answers. Not a result.")

    context = analysis_context(db, run["run_id"])
    header = _analysis_header(context)
    if header is None:
        warnings.append(NOT_ANALYSED)
        pending = {"analysis": "no analysis is stored for this run; run `./pangea analyze`"}
    else:
        pending = {
            metric: (row["detail"].get("reason") or "not computed")
            for (scope, _scope_id, metric), row in sorted(context["metrics"].items())
            if row["value"] is None and row["detail"].get("status") == "pending"
        }
        facts = db.one(
            "SELECT COUNT(*) n FROM analysis_call_facts WHERE analysis_id = ? AND status != 'ok'",
            (header["analysis_id"],),
        )["n"]
        if facts:
            pending["evidence_for_some_calls"] = (
                f"{facts} call(s) could not be re-executed against a capture; each one says why "
                f"in the claim detail rather than being counted as zero"
            )

    return {
        "run": {"run_id": run["run_id"], "created_at": run["created_at"], "manifest": run["manifest"]},
        "counts": {
            "sources": db.count("sources"),
            "pcaps": db.count("pcaps"),
            "claims": db.count("claims"),
            "pairs": db.count("pairs"),
            "calls": len(calls),
            "format_errors": sum(1 for c in calls if c["format_error"]),
            "tool_errors": sum(1 for c in calls if c["error"]),
            "discards": db.count("discards"),
        },
        "pairs_by_type": dict(Counter(p["pair_type"] for p in pairs.values())),
        "analysis": header,
        "analyses": [
            {k: a[k] for k in ("analysis_id", "code_version", "params_hash", "created_at", "metrics")}
            for a in list_analyses(db, run["run_id"])
        ],
        # Only what really has not been computed, with the reason the
        # analysis itself gave. A stale "pending" naming a milestone that
        # has since landed is worse than no note at all: it tells the
        # reader to distrust a number that is in fact there.
        "pending": pending,
        "warnings": warnings,
    }


def sources(db: Database) -> list[dict[str, Any]]:
    """
    The source registry with its verification checklist.

    Nothing is summarised into a single green tick: a source is shown with
    the counts of what passed, what failed and what nobody has checked yet,
    because "6 sources registered" and "6 sources verified" are very
    different statements and only the first one is true today.
    """
    rows: list[dict[str, Any]] = []
    for source in db.query("SELECT * FROM sources ORDER BY title"):
        source_id = source["source_id"]
        checks = [dict(c) for c in db.query(
            "SELECT item, status, notes, pcap_id FROM verification_checks WHERE source_id = ? ORDER BY rowid",
            (source_id,),
        )]
        captures = []
        for pcap in db.query("SELECT * FROM pcaps WHERE source_id = ? ORDER BY path", (source_id,)):
            captures.append(
                {
                    "pcap_id": pcap["pcap_id"],
                    "path": pcap["path"],
                    "sha256": pcap["sha256"],
                    "size_bytes": pcap["size_bytes"],
                    "packet_count": pcap["packet_count"],
                    "capture_metadata": json.loads(pcap["capture_metadata"]),
                }
            )
        steps = db.query(
            "SELECT origin_file, COUNT(*) n FROM source_steps WHERE source_id = ? GROUP BY origin_file",
            (source_id,),
        )
        rows.append(
            {
                "source_id": source_id,
                "title": source["title"],
                "origin": source["origin"],
                "license": source["license"],
                "urls": json.loads(source["urls"]),
                "notes": source["notes"],
                "steps_total": sum(row["n"] for row in steps),
                "steps_by_file": [{"file": row["origin_file"], "n": row["n"]} for row in steps],
                "captures": captures,
                "checks": checks,
                "check_counts": dict(Counter(check["status"] for check in checks)),
            }
        )
    return rows


def source_files(db: Database, source_id: str) -> list[dict[str, Any]]:
    """
    The files behind one source: its steps CSVs, its provenance note and
    its captures, each one openable.

    Built from the database rather than by listing a directory, which is
    also what makes the reader safe: a path is served only if a row already
    refers to it.
    """
    files: list[dict[str, Any]] = []
    source = db.one("SELECT origin FROM sources WHERE source_id = ?", (source_id,))
    if source is None:
        return files

    for row in db.query(
        "SELECT origin_file, COUNT(*) n FROM source_steps WHERE source_id = ? GROUP BY origin_file ORDER BY origin_file",
        (source_id,),
    ):
        files.append({"path": row["origin_file"], "kind": "csv", "rows": row["n"]})
    if source["origin"]:
        files.append({"path": f"{source['origin']}/source.md", "kind": "markdown", "rows": None})
    for row in db.query("SELECT pcap_id, path, packet_count, size_bytes FROM pcaps WHERE source_id = ? ORDER BY path", (source_id,)):
        files.append(
            {
                "path": row["path"],
                "kind": "pcap",
                "pcap_id": row["pcap_id"],
                "packets": row["packet_count"],
                "size_bytes": row["size_bytes"],
            }
        )
    return files


def samples(db: Database) -> dict[str, Any]:
    """
    Every capture and every text file the dataset refers to, in one list.

    Built from rows, not from a directory listing: a sample is openable in
    the dashboard only because some row already names it, which is the same
    allowlist the file reader enforces. Captures are never served as bytes
    -- they are read through the PCAP service, bounded, and the viewer says
    how much of the file it is showing.
    """
    captures = []
    for row in db.query(
        """
        SELECT pc.*, s.title AS source_title
          FROM pcaps pc LEFT JOIN sources s ON s.source_id = pc.source_id
         ORDER BY pc.path
        """
    ):
        record = dict(row)
        captures.append(
            {
                "pcap_id": record["pcap_id"],
                "source_id": record["source_id"],
                "source_title": record["source_title"],
                "path": record["path"],
                "sha256": record["sha256"],
                "size_bytes": record["size_bytes"],
                "packet_count": record["packet_count"],
                "capture_metadata": json.loads(record["capture_metadata"]),
                "pairs": db.one(
                    "SELECT COUNT(*) n FROM pairs WHERE pcap_id = ?", (record["pcap_id"],)
                )["n"],
            }
        )

    files = []
    for row in db.query(
        """
        SELECT origin_file, source_id, COUNT(*) n FROM source_steps
         GROUP BY origin_file, source_id ORDER BY origin_file
        """
    ):
        files.append({"path": row["origin_file"], "kind": "csv", "rows": row["n"], "source_id": row["source_id"]})
    for row in db.query("SELECT source_id, origin, title FROM sources WHERE origin != '' ORDER BY title"):
        # `origin` is a folder for an ingested source and a sentence for a
        # seeded demo one. Only the first kind names a file, and offering
        # the second as one produces a link that can only 404.
        if " " in row["origin"]:
            continue
        files.append({"path": f"{row['origin']}/source.md", "kind": "markdown", "rows": None,
                      "source_id": row["source_id"]})
    return {"captures": captures, "files": files}


def readable_paths(db: Database) -> set[str]:
    """Every file path the database refers to. The allowlist for the reader."""
    paths = {row["origin_file"] for row in db.query("SELECT DISTINCT origin_file FROM source_steps")}
    paths |= {row["path"] for row in db.query("SELECT path FROM pcaps")}
    paths |= {
        f"{row['origin']}/source.md" for row in db.query("SELECT origin FROM sources WHERE origin != ''")
    }
    return paths


def source_steps(db: Database, source_id: str) -> list[dict[str, Any]]:
    """The steps exactly as transcribed, with the whole original row."""
    return [
        {
            "step_id": row["step_id"],
            "origin_file": row["origin_file"],
            "row_number": row["row_number"],
            "step_order": row["step_order"],
            "text": row["text"],
            "fields": json.loads(row["fields"]),
        }
        for row in db.query(
            "SELECT * FROM source_steps WHERE source_id = ? ORDER BY origin_file, row_number", (source_id,)
        )
    ]


def pairs_overview(db: Database) -> dict[str, Any]:
    """
    The pair set and what was thrown away building it.

    The discard log is shown beside the counts rather than behind a link:
    a mutation that stayed true means the original condition was too loose
    to tell two claims apart, and a swap that turned out supported means
    two scenarios were less different than assumed. Both are findings about
    the dataset, and both are invisible if only the kept pairs are shown.
    """
    counts = dict(
        Counter(row["pair_type"] for row in db.query("SELECT pair_type FROM pairs"))
    )
    by_expected = dict(
        Counter(
            f"{row['pair_type']}:{row['expected'] or 'not SUPPORTED'}"
            for row in db.query("SELECT pair_type, expected FROM pairs")
        )
    )
    discards = [dict(row) for row in db.query("SELECT * FROM discards ORDER BY created_at DESC, rowid DESC")]
    grouped: dict[str, dict[str, Any]] = {}
    for entry in discards:
        key = f"{entry['kind']}: {entry['reason']}"
        bucket = grouped.setdefault(key, {"kind": entry["kind"], "reason": entry["reason"], "n": 0, "examples": []})
        bucket["n"] += 1
        if len(bucket["examples"]) < 3:
            bucket["examples"].append({"ref_id": entry["ref_id"], "details": json.loads(entry["details"] or "{}")})

    rows = []
    for row in db.query(
        """
        SELECT p.*, c.atomic_text, c.mutation_type, s.title AS source_title, pc.path AS pcap_path
          FROM pairs p JOIN claims c ON c.claim_id = p.claim_id
          JOIN sources s ON s.source_id = c.source_id
          LEFT JOIN pcaps pc ON pc.pcap_id = p.pcap_id
         ORDER BY p.pair_type, p.pair_id
        """
    ):
        rows.append(
            {
                "pair_id": row["pair_id"], "pair_type": row["pair_type"], "level": row["level"],
                "expected": row["expected"], "expected_basis": row["expected_basis"],
                "atomic_text": row["atomic_text"], "mutation_type": row["mutation_type"],
                "source_title": row["source_title"], "pcap_path": row["pcap_path"],
                "notes": row["notes"],
            }
        )
    return {
        "counts": counts,
        "total": sum(counts.values()),
        "by_expected": by_expected,
        "discards_total": len(discards),
        "discards": sorted(grouped.values(), key=lambda g: -g["n"]),
        "pairs": rows,
    }


def claims_table(db: Database, run_id: str | None = None) -> list[dict[str, Any]]:
    run = load_run(db, run_id)
    if not run:
        return []
    pairs = load_pairs(db)
    by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in load_calls(db, run["run_id"]):
        by_pair[call["pair_id"]].append(call)
    rows = [summarise_pair(pair, by_pair.get(pair_id, [])) for pair_id, pair in pairs.items()]
    return sorted(rows, key=lambda r: (r["pair_type"], r["level"], r["pair_id"]))


def pair_detail(db: Database, pair_id: str, run_id: str | None = None) -> dict[str, Any]:
    run = load_run(db, run_id)
    pair = load_pairs(db).get(pair_id)
    if pair is None or not run:
        return {}
    calls = [c for c in load_calls(db, run["run_id"]) if c["pair_id"] == pair_id]
    summary = summarise_pair(pair, calls)
    context = analysis_context(db, run["run_id"])
    facts = (
        load_call_facts(db, context["analysis"]["analysis_id"], [c["call_id"] for c in calls])
        if context["analysis"] else {}
    )

    matrix = []
    for call in sorted(calls, key=lambda c: (c["model_id"], c["prompt_id"], c["repeat"])):
        payload = {}
        if call["parsed"]:
            try:
                payload = json.loads(call["parsed"])
            except json.JSONDecodeError:
                payload = {}
        matrix.append(
            {
                "call_id": call["call_id"],
                "model_id": call["model_id"],
                "model_family": call["model_family"],
                "prompt_id": call["prompt_id"],
                "repeat": call["repeat"],
                "verdict": _parsed_verdict(call),
                "reason_code": payload.get("reason_code"),
                "condition": payload.get("condition"),
                "cited_packets": _cited(call),
                "confidence": _confidence(call),
                "uncertainty_source": (payload.get("survey") or {}).get("uncertainty_source"),
                "format_error": bool(call["format_error"]),
                "error": call["error"],
                "tool_calls": json.loads(call["tool_calls"]) if call["tool_calls"] else [],
                "latency_ms": call["latency_ms"],
                "tokens_in": call["tokens_in"],
                "tokens_out": call["tokens_out"],
                # What the capture said about this answer. Absent rather
                # than zeroed when the analysis could not ask.
                "evidence": facts.get(call["call_id"]),
            }
        )

    return {
        "summary": summary,
        "claim": {
            "atomic_text": pair["atomic_text"],
            "source_step_text": pair["source_step_text"],
            "source_location": pair["source_location"],
            "source_title": pair["source_title"],
            "kind": pair["kind"],
            "level": pair["level"],
            "reason_code": pair["reason_code"],
            "condition": pair["condition"],
            "mutation_of": pair["mutation_of"],
            "mutation_type": pair["mutation_type"],
        },
        "capture": {
            "pcap_path": pair["pcap_path"],
            "pcap_sha256": pair["pcap_sha256"],
            "packet_count": pair["packet_count"],
            "capture_metadata": pair["capture_metadata"],
        },
        "matrix": matrix,
        "evidence": _pair_evidence(context, facts, matrix),
    }


def _pair_evidence(context: dict[str, Any], facts: dict[str, Any], matrix: list[dict[str, Any]]) -> dict[str, Any]:
    """
    The system's own reading of the capture for one item.

    The packet table is grouped by the condition that produced it, not by
    the model: several models usually write the same filter, and showing
    the same scan once -- with the models that asked for it -- is both
    shorter and more honest about how much independent evidence there is.
    """
    if not context["analysis"]:
        return {"status": "pending", "analysis_id": None, "conditions": [], "note": NOT_ANALYSED}

    grouped: dict[str, dict[str, Any]] = {}
    for cell in matrix:
        fact = cell["evidence"]
        if not fact:
            continue
        key = cell["condition"] or "(no condition)"
        entry = grouped.setdefault(
            key,
            {
                "condition": key, "models": [], "status": fact["status"], "note": fact["note"],
                "match_count": fact["reexecuted_count"], "truncated": fact["truncated"],
                "packets": [], "cited_verified": [], "cited_unverified": [],
                "fabricated_count": fact["fabricated_count"],
                "sufficiency_ok": fact["sufficiency_ok"], "necessity_ok": fact["necessity_ok"],
            },
        )
        entry["models"].append(cell["model_id"])
        entry["packets"] = sorted(set(entry["packets"]) | set(fact["reexecuted_packets"]))
        entry["cited_verified"] = sorted(set(entry["cited_verified"]) | set(fact["cited_verified"]))
        entry["cited_unverified"] = sorted(set(entry["cited_unverified"]) | set(fact["cited_unverified"]))

    for entry in grouped.values():
        entry["models"] = sorted(set(entry["models"]))

    unexplained = sorted({f["status"] for f in facts.values() if f["status"] != "ok"})
    return {
        "status": "computed" if any(e["status"] == "ok" for e in grouped.values()) else "unavailable",
        "analysis_id": context["analysis"]["analysis_id"],
        "conditions": [grouped[key] for key in sorted(grouped)],
        "not_executed": unexplained,
        "note": (
            "Each table below is the system re-running that condition on this capture -- not what "
            "the model reported. A cited packet that does not satisfy the model's own condition is "
            "marked \u201ccited, not verified\u201d. Sufficiency asks whether the cited packets alone "
            "still give the verdict; necessity asks whether removing them takes it away."
        ),
    }


def raw_call(db: Database, call_id: str) -> dict[str, Any]:
    """The stored response behind a number, verbatim."""
    row = db.one("SELECT * FROM calls WHERE call_id = ?", (call_id,))
    return dict(row) if row else {}


def panel(db: Database, run_id: str | None = None) -> dict[str, Any]:
    run = load_run(db, run_id)
    if not run:
        return {}
    calls = load_calls(db, run["run_id"])
    pairs = load_pairs(db)

    by_model: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in calls:
        by_model[call["model_id"]].append(call)
        by_family[call["model_family"]].append(call)

    def operational(rows: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(rows)
        verdicts = [_parsed_verdict(r) for r in rows]
        abstentions = sum(1 for v in verdicts if v == "NOT_VERIFIABLE")
        format_errors = sum(1 for r in rows if r["format_error"])
        tool_errors = sum(1 for r in rows if r["error"])
        # Self-consistency: do the repeats of one (pair, model, prompt) agree?
        groups: dict[tuple[str, str, str], list[str | None]] = defaultdict(list)
        for row in rows:
            groups[(row["pair_id"], row["model_id"], row["prompt_id"])].append(_parsed_verdict(row))
        comparable = [g for g in groups.values() if len([v for v in g if v]) > 1]
        consistent = sum(1 for g in comparable if len({v for v in g if v}) == 1)
        return {
            "n_calls": total,
            "abstention_rate": abstentions / total if total else None,
            "format_error_rate": format_errors / total if total else None,
            "tool_error_rate": tool_errors / total if total else None,
            "self_consistency": consistent / len(comparable) if comparable else None,
            "self_consistency_n": len(comparable),
        }

    def match_rate(rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Agreement with construction-based expectations, per model."""
        hits = n = 0
        for row in rows:
            pair = pairs.get(row["pair_id"])
            verdict = _parsed_verdict(row)
            if pair is None or verdict is None:
                continue
            outcome = _expected_outcome(pair, verdict)
            if outcome is None:
                continue
            n += 1
            hits += int(outcome)
        low, high = wilson_interval(hits, n)
        return {"matches": hits, "n": n, "rate": hits / n if n else None, "ci_low": low, "ci_high": high}

    models = [
        {
            "model_id": model_id,
            "family": rows[0]["model_family"],
            "version": rows[0]["model_version"],
            **operational(rows),
            "controls": match_rate(rows),
        }
        for model_id, rows in sorted(by_model.items())
    ]
    families = [
        {"family": family, **operational(rows), "controls": match_rate(rows)}
        for family, rows in sorted(by_family.items())
    ]

    # Pairwise family agreement, on the pairs where both families voted.
    family_names = sorted(by_family)
    per_pair_family: dict[str, dict[str, str]] = {}
    calls_by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in calls:
        calls_by_pair[call["pair_id"]].append(call)
    for pair_id, rows in calls_by_pair.items():
        per_pair_family[pair_id] = _family_votes(rows)

    agreement = []
    for i, left in enumerate(family_names):
        for right in family_names[i + 1 :]:
            both = [v for v in per_pair_family.values() if left in v and right in v]
            same = sum(1 for v in both if v[left] == v[right])
            low, high = wilson_interval(same, len(both))
            agreement.append(
                {"a": left, "b": right, "n": len(both), "rate": same / len(both) if both else None,
                 "ci_low": low, "ci_high": high}
            )

    context = analysis_context(db, run["run_id"])
    metrics = context["metrics"]
    header = _analysis_header(context)

    # The analysis's own figures, which the Wilson intervals above cannot
    # give: an interval that resamples captures, the error correlation
    # between families, and what the panel is worth once that correlation
    # is taken into account.
    for row in models:
        row["controls_bootstrap"] = _stat(metrics, "model", row["model_id"], "matches_expected_rate")
        row["self_consistency_analysis"] = _stat(metrics, "model", row["model_id"], "self_consistency")
    for row in families:
        row["controls_bootstrap"] = _stat(metrics, "family", row["family"], "matches_expected_rate")
        row["leave_one_out"] = _stat(metrics, "unit", row["family"], "leave_one_out_majority_change_rate")

    correlation = []
    for (scope, scope_id, metric) in sorted(metrics):
        if scope == "unit_pair" and metric == "error_phi":
            left, _, right = scope_id.partition("|")
            correlation.append(
                {
                    "a": left, "b": right,
                    "phi": _stat(metrics, scope, scope_id, "error_phi"),
                    "double_fault": _stat(metrics, scope, scope_id, "double_fault"),
                    "agreement": _stat(metrics, scope, scope_id, "agreement"),
                }
            )

    return {
        "models": models,
        "families": families,
        "pairwise_family_agreement": agreement,
        "analysis": header,
        "error_correlation": correlation,
        "effective_votes": _stat(metrics, "run", run["run_id"], "effective_votes"),
        "mean_error_correlation": _stat(metrics, "run", run["run_id"], "mean_error_correlation"),
        "majority_matches_expected": _stat(metrics, "run", run["run_id"], "majority_matches_expected_rate"),
        "calibration": [
            _stat(metrics, "confidence_bin", str(level), "matches_expected_rate")
            for level in range(1, 6)
            if _stat(metrics, "confidence_bin", str(level), "matches_expected_rate")
        ],
        "agreement_overall": {
            "raw_agreement": _stat(metrics, "run", run["run_id"], "raw_agreement"),
            "fleiss_kappa": _stat(metrics, "run", run["run_id"], "fleiss_kappa"),
            "gwet_ac1": _stat(metrics, "run", run["run_id"], "gwet_ac1"),
        },
        "pending": {} if header else {"analysis": NOT_ANALYSED},
        "note": (
            "The interval beside \u201cmatches expected\u201d in the table is Wilson, by item. The "
            "bootstrap column resamples whole captures instead, because claims about one capture "
            "are not independent, and is the wider and more honest of the two."
        ),
    }


def prompt_sensitivity(db: Database, run_id: str | None = None) -> dict[str, Any]:
    """
    Flip rate between prompts against the sampling-noise floor from repeats.

    Both are computed the same way over the same calls, which is the point:
    a prompt effect only means something relative to how much the same
    prompt already disagrees with itself.
    """
    run = load_run(db, run_id)
    if not run:
        return {}
    calls = load_calls(db, run["run_id"])

    # repeats within one (pair, model, prompt)
    repeat_groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    # prompts within one (pair, model), each reduced to its modal verdict
    prompt_groups: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for call in calls:
        verdict = _parsed_verdict(call)
        if not verdict:
            continue
        repeat_groups[(call["pair_id"], call["model_id"], call["prompt_id"])].append(verdict)
        prompt_groups[(call["pair_id"], call["model_id"])][call["prompt_id"]].append(verdict)

    repeat_comparable = [g for g in repeat_groups.values() if len(g) > 1]
    repeat_flips = sum(1 for g in repeat_comparable if len(set(g)) > 1)

    prompt_comparable = 0
    prompt_flips = 0
    for prompts in prompt_groups.values():
        modal = [_mode(v) for v in prompts.values() if v]
        if len(modal) > 1:
            prompt_comparable += 1
            prompt_flips += int(len(set(modal)) > 1)

    by_prompt: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for call in calls:
        by_prompt[call["prompt_id"]].append(call)
    prompt_rows = []
    for prompt_id, rows in sorted(by_prompt.items()):
        label = db.one("SELECT label, dimension FROM prompt_variants WHERE prompt_id = ?", (prompt_id,))
        verdicts = [_parsed_verdict(r) for r in rows]
        prompt_rows.append(
            {
                "prompt_id": prompt_id,
                "label": label["label"] if label else prompt_id,
                "dimension": label["dimension"] if label else "",
                "n_calls": len(rows),
                "format_error_rate": sum(1 for r in rows if r["format_error"]) / len(rows),
                "abstention_rate": sum(1 for v in verdicts if v == "NOT_VERIFIABLE") / len(rows),
                "supported_rate": sum(1 for v in verdicts if v == "SUPPORTED") / len(rows),
            }
        )

    flip_low, flip_high = wilson_interval(prompt_flips, prompt_comparable)
    noise_low, noise_high = wilson_interval(repeat_flips, len(repeat_comparable))
    context = analysis_context(db, run["run_id"])
    metrics = context["metrics"]
    header = _analysis_header(context)
    return {
        "prompt_flip_rate": {
            "flips": prompt_flips, "n": prompt_comparable,
            "rate": prompt_flips / prompt_comparable if prompt_comparable else None,
            "ci_low": flip_low, "ci_high": flip_high,
        },
        "repeat_flip_rate": {
            "flips": repeat_flips, "n": len(repeat_comparable),
            "rate": repeat_flips / len(repeat_comparable) if repeat_comparable else None,
            "ci_low": noise_low, "ci_high": noise_high,
        },
        "prompts": prompt_rows,
        "note": (
            "A 'no prompt effect' claim cannot be proved here. These two rates can only show "
            "whether the prompt effect is small relative to the sampling-noise floor, and that "
            "judgement needs an equivalence margin fixed before the run."
        ),
        "analysis": header,
        "flip_rate_excess": _stat(metrics, "run", run["run_id"], "prompt_flip_rate_excess"),
        "within_margin": _stat(metrics, "run", run["run_id"], "prompt_effect_within_margin"),
        "by_dimension": _stats_in_scope(metrics, "dimension", "flip_rate_vs_reference"),
        "by_variant": _stats_in_scope(metrics, "prompt", "flip_rate_vs_reference"),
        "position_bias": _stat(metrics, "run", run["run_id"], "position_bias_gap"),
        "variance": _stats_in_scope(metrics, "factor", "variance_explained_eta2"),
        "fragile_item_rate": _stat(metrics, "run", run["run_id"], "fragile_item_rate"),
        "pending": {} if header else {"analysis": NOT_ANALYSED},
    }


def controls(db: Database, run_id: str | None = None) -> dict[str, Any]:
    """Matches-expected by pair type, and the leakage indicator."""
    run = load_run(db, run_id)
    run_key = run["run_id"] if run else ""
    context = analysis_context(db, run_key or None)
    metrics = context["metrics"]
    header = _analysis_header(context)
    rows = claims_table(db, run_id)
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_type[row["pair_type"]].append(row)

    summary = []
    for pair_type, items in sorted(by_type.items()):
        scored = [r for r in items if r["matches_expected"] is not None]
        hits = sum(1 for r in scored if r["matches_expected"])
        low, high = wilson_interval(hits, len(scored))
        summary.append(
            {
                "pair_type": pair_type,
                "n_pairs": len(items),
                "n_scored": len(scored),
                "matches": hits,
                "rate": hits / len(scored) if scored else None,
                "ci_low": low, "ci_high": high,
                "basis": "construction" if pair_type in ("mutation", "swap", "no_pcap") else "author",
            }
        )

    no_pcap = by_type.get("no_pcap", [])
    leaked = [r for r in no_pcap if r["panel_verdict"] == "SUPPORTED"]
    leak_low, leak_high = wilson_interval(len(leaked), len(no_pcap))
    return {
        "by_pair_type": summary,
        "leakage": {
            "n": len(no_pcap),
            "supported": len(leaked),
            "rate": len(leaked) / len(no_pcap) if no_pcap else None,
            "ci_low": leak_low, "ci_high": leak_high,
            "note": "SUPPORTED on a pair with no capture indicates the claim was recognised, not verified.",
        },
        "swaps": {
            "n": len(by_type.get("swap", [])),
            "not_supported": sum(1 for r in by_type.get("swap", []) if r["matches_expected"]),
            "note": "Swaps are scored as 'not SUPPORTED'; REFUTED would assume a closed world.",
        },
        "mutation_survival_log": [
            dict(row) for row in db.query("SELECT * FROM discards WHERE kind = 'mutation' ORDER BY created_at")
        ],
        "analysis": header,
        # Every mutation and swap kept was validated against its capture
        # when the pair was built (B3); the ones that failed are in the
        # discard log above, not missing.
        "validation_note": (
            "Every mutation below found nothing on its capture and every swap came back not "
            "supported when the pair was built -- that is the condition for keeping one. The "
            "candidates that failed those checks are in the discard log on the Pairs section."
        ),
        "bootstrap_by_pair_type": _stats_in_scope(metrics, "pair_type", "majority_matches_expected_rate"),
        "leakage_analysis": _stat(metrics, "run", run_key, "no_pcap_supported_rate"),
        "leakage_by_call": _stat(metrics, "run", run_key, "no_pcap_supported_rate_by_call"),
        "pending": {} if header else {"analysis": NOT_ANALYSED},
    }


def evidence_quality(db: Database, run_id: str | None = None) -> dict[str, Any]:
    """
    What the capture said about the evidence the models offered.

    Every rate here needed a condition to be re-executed, so all of it
    comes from a stored analysis. Without one the section says so and
    shows only what the models themselves reported, clearly labelled as
    unverified -- which is what it was before anything checked it.
    """
    run = load_run(db, run_id)
    if not run:
        return {}
    calls = load_calls(db, run["run_id"])
    cited = [len(_cited(call)) for call in calls]
    with_citations = [c for c in cited if c]
    context = analysis_context(db, run["run_id"])
    metrics = context["metrics"]
    header = _analysis_header(context)
    run_key = run["run_id"]

    citations = {
        "calls_with_citations": len(with_citations),
        "calls_total": len(calls),
        "mean_cited_packets": sum(with_citations) / len(with_citations) if with_citations else None,
    }
    if not header:
        return {
            "citations": citations,
            "status": "pending",
            "analysis": None,
            "pending": {"everything_below": NOT_ANALYSED},
        }

    return {
        "citations": citations,
        "status": "computed",
        "analysis": header,
        "coverage": _stat(metrics, "run", run_key, "reexecution_coverage"),
        "rates": [
            row for row in (
                _stat(metrics, "run", run_key, "fabricated_packet_call_rate"),
                _stat(metrics, "run", run_key, "cited_and_verified_rate"),
                _stat(metrics, "run", run_key, "cited_unverified_rate"),
                _stat(metrics, "run", run_key, "sufficiency_pass_rate"),
                _stat(metrics, "run", run_key, "necessity_pass_rate"),
            ) if row
        ],
        "jaccard_mean": _stat(metrics, "run", run_key, "evidence_jaccard_mean"),
        "jaccard_pairs": _stats_in_scope(metrics, "model_pair", "evidence_jaccard"),
        "pending": {},
        "note": (
            "A cited packet counts as verified only if it satisfies the model's own condition when "
            "the system re-runs it. A fabricated packet is one whose number is past the end of the "
            "capture: it cannot be a mis-read packet, it is not in the file."
        ),
    }
