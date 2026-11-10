"""
Human review of the extraction.

  Responsibility: let a reviewer accept, edit, split, merge or reject each
  extracted claim, without ever overwriting what the agent produced.

  An edit is a new claim row whose `supersedes` points at the one it
  replaces, marked `human`; the agent's original stays readable forever.
  That matters twice over: it is what lets the dashboard show "the agent
  said X, a reviewer changed it to Y", and it is what keeps a claim that
  models already answered on from mutating under the answers.

  A review is itself a row (`claim_reviews`), so the queue's state is
  derived -- the latest action per claim -- rather than a flag somebody
  could flip.

  Rejection does not delete anything either. A rejected claim stays in the
  table and simply never becomes a pair.
"""
from __future__ import annotations

import json
from typing import Any

from .ids import content_id, event_id
from .schemas import Claim, ClaimKind, Condition, Provenance, ReasonCode, ReviewAction
from .storage.db import Database
from .storage.repository import Repository, utc_now


class ReviewError(ValueError):
    """An action that cannot be applied as asked."""


def _claim_row(db: Database, claim_id: str) -> dict[str, Any]:
    row = db.one("SELECT * FROM claims WHERE claim_id = ?", (claim_id,))
    if row is None:
        raise ReviewError(f"no claim {claim_id}")
    return dict(row)


def latest_actions(db: Database) -> dict[str, str]:
    """claim_id -> the most recent action taken on it."""
    actions: dict[str, str] = {}
    for row in db.query("SELECT claim_id, action FROM claim_reviews ORDER BY created_at, rowid"):
        actions[row["claim_id"]] = row["action"]
    return actions


def superseded_ids(db: Database) -> set[str]:
    return {
        row["supersedes"] for row in db.query("SELECT supersedes FROM claims WHERE supersedes IS NOT NULL")
    }


def queue(db: Database, *, include_reviewed: bool = False) -> list[dict[str, Any]]:
    """
    What is waiting for a reviewer.

    Ordered worst-first: claims whose condition found nothing on their own
    capture come first, because those are the ones where something is
    actually wrong -- then the rest in source order.
    """
    actions = latest_actions(db)
    superseded = superseded_ids(db)
    rows: list[dict[str, Any]] = []
    for row in db.query(
        """
        SELECT c.*, s.title AS source_title
          FROM claims c JOIN sources s ON s.source_id = c.source_id
         ORDER BY c.source_id, c.source_location, c.claim_id
        """
    ):
        claim = dict(row)
        claim_id = claim["claim_id"]
        if claim_id in superseded:
            continue
        action = actions.get(claim_id)
        if action and not include_reviewed:
            continue
        claim["condition"] = json.loads(claim["condition"]) if claim["condition"] else None
        claim["review_action"] = action
        claim["checks"] = [
            dict(check)
            for check in db.query(
                """
                SELECT k.*, p.path FROM claim_condition_checks k
                  JOIN pcaps p ON p.pcap_id = k.pcap_id
                 WHERE k.claim_id = ? ORDER BY p.path
                """,
                (claim_id,),
            )
        ]
        holds = [c["holds"] for c in claim["checks"] if c["holds"] is not None]
        claim["condition_holds"] = (any(holds) if holds else None)
        claim["flags"] = []
        if claim["condition"] and holds and not any(holds):
            # The one finding worth surfacing first: either the condition is
            # too narrow, the step was misread, or this capture is not the
            # one the step describes.
            claim["flags"].append("CONDITION_FINDS_NOTHING")
        if claim["level"] >= 4 and not claim["reason_code"]:
            claim["flags"].append("MISSING_REASON_CODE")
        if not claim["condition"] and claim["level"] <= 3:
            claim["flags"].append("NO_CONDITION")
        rows.append(claim)
    rows.sort(key=lambda r: (not r["flags"], r["source_title"], r["source_location"]))
    return rows


def _new_version(db: Database, base: dict[str, Any], edits: dict[str, Any], suffix: str) -> Claim:
    """Build the superseding claim, defaulting every field to the original."""
    condition_payload = edits.get("condition", json.loads(base["condition"]) if base["condition"] else None)
    condition = None
    if condition_payload and condition_payload.get("display_filter"):
        condition = Condition(
            kind=ClaimKind(condition_payload.get("kind") or base["kind"]),
            display_filter=condition_payload["display_filter"],
            predicate=condition_payload.get("predicate") or {},
            parameters=condition_payload.get("parameters") or {},
        )
    level = int(edits.get("level", base["level"]))
    reason = edits.get("reason_code", base["reason_code"])
    return Claim(
        claim_id=content_id("clm", [base["claim_id"], suffix, edits.get("atomic_text", base["atomic_text"])]),
        source_id=base["source_id"],
        source_location=base["source_location"],
        source_step_text=base["source_step_text"],
        atomic_text=edits.get("atomic_text", base["atomic_text"]),
        level=level,
        kind=ClaimKind(edits.get("kind", base["kind"])),
        reason_code=ReasonCode(reason) if reason else None,
        condition=condition if level <= 3 else None,
        mutation_of=base["mutation_of"],
        provenance=Provenance.HUMAN,
        version=int(base["version"]) + 1,
        supersedes=base["claim_id"],
    )


def apply_action(
    db: Database,
    *,
    claim_id: str,
    action: str,
    reviewer: str = "human",
    notes: str = "",
    edits: dict[str, Any] | None = None,
    parts: list[dict[str, Any]] | None = None,
    merge_with: list[str] | None = None,
) -> dict[str, Any]:
    """Record one review decision. Returns the claims it produced, if any."""
    try:
        verb = ReviewAction(action)
    except ValueError:
        raise ReviewError(f"unknown review action {action!r}")

    base = _claim_row(db, claim_id)
    repo = Repository(db)
    produced: list[str] = []

    if verb is ReviewAction.EDIT:
        if not edits:
            raise ReviewError("an edit needs the changed fields")
        claim = _new_version(db, base, edits, "edit")
        repo.add_claim(claim)
        produced.append(claim.claim_id)

    elif verb is ReviewAction.SPLIT:
        if not parts or len(parts) < 2:
            raise ReviewError("a split needs at least two parts")
        for index, part in enumerate(parts):
            if not part.get("atomic_text"):
                raise ReviewError("every part of a split needs its text")
            claim = _new_version(db, base, part, f"split{index}")
            repo.add_claim(claim)
            produced.append(claim.claim_id)

    elif verb is ReviewAction.MERGE:
        if not merge_with:
            raise ReviewError("a merge needs the other claims")
        others = [_claim_row(db, other) for other in merge_with]
        if any(other["source_id"] != base["source_id"] for other in others):
            raise ReviewError("claims from different sources cannot be merged")
        merged_text = (edits or {}).get("atomic_text") or " and ".join(
            [base["atomic_text"], *[o["atomic_text"] for o in others]]
        )
        claim = _new_version(db, base, {**(edits or {}), "atomic_text": merged_text}, "merge")
        repo.add_claim(claim)
        produced.append(claim.claim_id)
        # Each merged-away claim records its own review, so none of them
        # silently disappears from the queue.
        for other in others:
            db.insert(
                "claim_reviews",
                dict(
                    review_id=event_id("rev"),
                    claim_id=other["claim_id"], action="merge",
                    result_claim_ids=json.dumps([claim.claim_id]),
                    notes=notes or f"merged into {claim.claim_id}", reviewer=reviewer, created_at=utc_now(),
                ),
            )

    db.insert(
        "claim_reviews",
        dict(
            review_id=event_id("rev"),
            claim_id=claim_id,
            action=str(verb),
            result_claim_ids=json.dumps(produced),
            notes=notes,
            reviewer=reviewer,
            created_at=utc_now(),
        ),
    )
    return {"claim_id": claim_id, "action": str(verb), "produced": produced}


def review_stats(db: Database) -> dict[str, Any]:
    actions = latest_actions(db)
    superseded = superseded_ids(db)
    live = [
        row["claim_id"] for row in db.query("SELECT claim_id FROM claims") if row["claim_id"] not in superseded
    ]
    counts: dict[str, int] = {}
    for claim_id in live:
        counts[actions.get(claim_id, "pending")] = counts.get(actions.get(claim_id, "pending"), 0) + 1
    checks = db.query("SELECT holds, COUNT(*) n FROM claim_condition_checks GROUP BY holds")
    return {
        "claims_live": len(live),
        "by_action": counts,
        "condition_checks": {
            {1: "holds", 0: "finds nothing", None: "error"}[row["holds"]]: row["n"] for row in checks
        },
    }
