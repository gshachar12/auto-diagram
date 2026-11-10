"""
The pre-registered parameters, and what it means to change one.

  Responsibility: describe every threshold the analysis depends on -- what
  it is, what it does, and the range a slider may move it through -- and
  record every change to it.

  Why a slider is allowed here at all. These values must be fixed before a
  run and must not be tuned after results are seen; that is the whole point
  of calling them pre-registered. A dashboard control that edits them looks
  like exactly the wrong thing to build. It is defensible only because of
  three properties, which this module provides:

    Changing one never alters a finished run. Thresholds feed config_hash,
      which feeds the run id, so a different value is a different run and
      the old one keeps its own parameters in its own manifest.
    Every change is recorded. `config_changes` is append-only and stores
      the old value, the new value, both config hashes, and -- crucially --
      how many runs already existed when the change was made. A threshold
      moved after results exist is visible forever.
    The warning is shown, not buried. Once any run has stored calls, the
      API marks the parameters as "results exist" and the dashboard says so
      beside the slider.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ids import content_id
from .storage.db import Database
from .storage.repository import utc_now


@dataclass(frozen=True)
class Parameter:
    path: str
    label: str
    unit: str
    minimum: float
    maximum: float
    step: float
    help: str
    integer: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "label": self.label, "unit": self.unit,
            "min": self.minimum, "max": self.maximum, "step": self.step,
            "help": self.help, "integer": self.integer,
        }


#: Ranges are generous rather than opinionated: the point of the control is
#: that the owner chooses, and a range that quietly excludes a defensible
#: value would be choosing for them.
PARAMETERS: tuple[Parameter, ...] = (
    Parameter(
        "thresholds.delta_seconds", "δ — sequence tolerance", "s", 0.0, 1.0, 0.005,
        "Two events closer together than this have no reliable order. Below it a sequence "
        "claim is NOT_VERIFIABLE rather than SUPPORTED or REFUTED.",
    ),
    Parameter(
        "thresholds.tau_seconds", "τ — absence window", "s", 0.1, 30.0, 0.1,
        "How long to wait after a request before 'no response' counts. Only meaningful on a "
        "capture that recorded both directions.",
    ),
    Parameter(
        "thresholds.quantity.many", "N — 'many'", "packets", 2, 500, 1,
        "The count a vague quantifier like 'several ports' must reach. Without it such a claim "
        "is NOT_VERIFIABLE with reason VAGUE_QUANTIFIER.", integer=True,
    ),
    Parameter(
        "thresholds.quantity.thousands", "N — 'thousands'", "packets", 100, 100000, 100,
        "The count behind a claim like 'thousands of SYNs'.", integer=True,
    ),
    Parameter(
        "thresholds.equivalence_margin.flip_rate", "Equivalence margin — flip rate", "", 0.01, 0.30, 0.01,
        "How large a prompt-to-prompt flip rate still counts as 'no prompt effect'. Fixing it "
        "beforehand is what decides whether the sample is large enough to answer the question at all.",
    ),
    Parameter(
        "thresholds.equivalence_margin.accuracy_points", "Equivalence margin — accuracy", "pp", 0.5, 20.0, 0.5,
        "The same, in percentage points of agreement with construction-based expectations.",
    ),
)

BY_PATH = {parameter.path: parameter for parameter in PARAMETERS}


def runs_with_results(db: Database) -> int:
    """How many runs already have stored calls. The reason for the warning."""
    row = db.one("SELECT COUNT(DISTINCT run_id) AS n FROM calls")
    return int(row["n"]) if row else 0


def record_change(
    db: Database,
    *,
    path: str,
    old_value: Any,
    new_value: Any,
    config_hash_before: str,
    config_hash_after: str,
    changed_by: str = "human",
    note: str = "",
) -> str:
    change_id = content_id("cfg", [path, str(old_value), str(new_value), utc_now()])
    db.insert(
        "config_changes",
        dict(
            change_id=change_id,
            path=path,
            old_value=None if old_value is None else str(old_value),
            new_value=None if new_value is None else str(new_value),
            config_hash_before=config_hash_before,
            config_hash_after=config_hash_after,
            # Stored at the moment of the change, not computed later: this is
            # the number that says whether results were already in hand.
            runs_existing=runs_with_results(db),
            changed_by=changed_by,
            note=note,
            created_at=utc_now(),
        ),
    )
    return change_id


def change_log(db: Database) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("SELECT * FROM config_changes ORDER BY created_at DESC, rowid DESC")]
