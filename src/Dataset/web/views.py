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

  What is deliberately NOT here: re-executing a model's condition on the
  capture, verifying cited packets, sufficiency and necessity. Those need
  the PCAP service and the analysis service (B1/B5). The views report them
  as pending rather than inventing them.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from typing import Any, Iterable

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
    Whether the panel matched what construction fixed.

    A swap has no expected verdict -- it is scored as "not SUPPORTED",
    because calling it REFUTED would assume a closed world on a capture the
    claim never came from. Anything with no construction-based expectation
    returns None and is never scored.
    """
    if panel_verdict is None:
        return None
    if pair["pair_type"] == "swap":
        return panel_verdict != "SUPPORTED"
    if pair["expected_basis"] != "construction" or not pair["expected"]:
        return None
    return panel_verdict == pair["expected"]


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
        warnings.append(f"{uncounted} capture(s) have no verified packet count -- the PCAP service (B1) has not run.")
    if unverified:
        warnings.append(f"{unverified} verification checklist item(s) are still unverified.")
    if run["manifest"].get("label") == "demo":
        warnings.append("DEMO dataset: synthetic claims, scripted MockModel answers. Not a result.")

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
        "pending": {
            "evidence_recomputation": "analysis service (B5)",
            "packet_verification": "PCAP service (B1)",
            "mutation_validation": "pair builder (B3)",
        },
        "warnings": warnings,
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
        "evidence": {
            "status": "pending",
            "note": (
                "Re-executing each model's condition on the capture, checking the cited packets "
                "and running the sufficiency and necessity tests needs the PCAP service (B1) and "
                "the analysis service (B5). Until then the cited packets below are shown as the "
                "models reported them and are marked unchecked."
            ),
        },
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

    return {
        "models": models,
        "families": families,
        "pairwise_family_agreement": agreement,
        "pending": {
            "error_correlation": "analysis service (B5)",
            "calibration": "analysis service (B5)",
            "leave_one_out": "analysis service (B5)",
            "bootstrap_ci_by_pcap": "analysis service (B5); the intervals here are Wilson, by item",
        },
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
            "whether the prompt effect is small relative to the sampling noise floor, and the "
            "equivalence margin that would make that judgement is still UNSET in the config."
        ),
        "pending": {"variance_decomposition": "analysis service (B5)", "position_bias": "prompt builder (B4)"},
    }


def controls(db: Database, run_id: str | None = None) -> dict[str, Any]:
    """Accuracy by pair type, and the leakage indicator."""
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
        "pending": {"mutation_validation": "pair builder (B3): no mutation has been mechanically validated yet"},
    }


def evidence_quality(db: Database, run_id: str | None = None) -> dict[str, Any]:
    """
    Deliberately mostly empty.

    Fabricated-packet rate, cited-and-verified rate, sufficiency/necessity
    pass rates and evidence-set Jaccard all require re-executing conditions
    against the capture. Reporting a plausible-looking number here before
    that exists would be exactly the kind of unfounded figure this project
    is built to avoid.
    """
    run = load_run(db, run_id)
    if not run:
        return {}
    calls = load_calls(db, run["run_id"])
    cited = [len(_cited(call)) for call in calls]
    with_citations = [c for c in cited if c]
    return {
        "citations": {
            "calls_with_citations": len(with_citations),
            "calls_total": len(calls),
            "mean_cited_packets": sum(with_citations) / len(with_citations) if with_citations else None,
        },
        "status": "pending",
        "pending": {
            "fabricated_packet_rate": "needs the PCAP service (B1) + analysis (B5)",
            "cited_and_verified_rate": "needs the PCAP service (B1) + analysis (B5)",
            "sufficiency_pass_rate": "needs the analysis service (B5)",
            "necessity_pass_rate": "needs the analysis service (B5)",
            "evidence_set_jaccard": "needs the analysis service (B5)",
        },
    }
