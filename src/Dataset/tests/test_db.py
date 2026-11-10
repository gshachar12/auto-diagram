"""
The append-only rule is the one invariant the rest of the system assumes.
It is enforced in SQLite, so these tests go through raw SQL rather than the
repository -- a future module that reaches past the Python layer must hit
the same wall.
"""
from __future__ import annotations

import sqlite3

import pytest

from Dataset.storage.db import DERIVED_TABLES, RAW_TABLES, Database
from Dataset.storage.repository import utc_now

#: Minimal valid row per raw table, in dependency order.
SEED_ROWS: list[tuple[str, dict]] = [
    ("sources", dict(source_id="src_1", title="t", created_at=utc_now())),
    ("pcaps", dict(pcap_id="pcap_1", source_id="src_1", path="p", sha256="h", size_bytes=1, capture_metadata="{}", created_at=utc_now())),
    ("verification_checks", dict(check_id="chk_1", source_id="src_1", item="link", status="pass", created_at=utc_now())),
    ("source_steps", dict(step_id="stp_1", source_id="src_1", origin_file="steps.csv", row_number=1, text="a step", created_at=utc_now())),
    ("claims", dict(claim_id="clm_1", source_id="src_1", source_location="l", source_step_text="s", atomic_text="a", level=1, kind="existential", created_at=utc_now())),
    ("claim_reviews", dict(review_id="rev_1", claim_id="clm_1", action="accept", created_at=utc_now())),
    ("pairs", dict(pair_id="pair_1", claim_id="clm_1", pair_type="source", pcap_id="pcap_1", expected="SUPPORTED", expected_basis="author", level=1, created_at=utc_now())),
    ("discards", dict(discard_id="dsc_1", kind="mutation", ref_id="clm_1", reason="stayed true", created_at=utc_now())),
    ("prompt_variants", dict(prompt_id="prm_1", dimension="wording", label="a", template="t", prompt_hash="h", config_version=1, created_at=utc_now())),
    ("model_specs", dict(model_id="m1", family="f", version="v", adapter="mock", supports_tools=1, temperature=0.0, created_at=utc_now())),
    ("config_changes", dict(change_id="cfg_1", path="thresholds.tau_seconds", old_value="UNSET", new_value="2.0", created_at=utc_now())),
    ("runs", dict(run_id="run_1", manifest="{}", created_at=utc_now())),
    ("run_events", dict(event_id="evt_1", run_id="run_1", status="created", created_at=utc_now())),
    ("calls", dict(call_id="call_1", run_id="run_1", pair_id="pair_1", model_id="m1", model_family="f", model_version="v", prompt_id="prm_1", prompt_hash="h", repeat=0, temperature=0.0, raw_response="{}", timestamp=utc_now())),
    ("llm_calls", dict(llm_call_id="llm_1", purpose="extraction", model_id="m1", model_version="v", prompt="p", raw_response="r", created_at=utc_now())),
]


def _seed(db: Database) -> None:
    for table, row in SEED_ROWS:
        db.insert(table, row)


def test_every_raw_table_is_covered_by_the_seed():
    # Guards the two tests below: a new raw table must be added here too,
    # otherwise its triggers would go unverified.
    assert {table for table, _ in SEED_ROWS} == set(RAW_TABLES)


@pytest.mark.parametrize("table", RAW_TABLES)
def test_raw_rows_cannot_be_updated(db, table):
    _seed(db)
    first_column = next(iter(row for name, row in SEED_ROWS if name == table))
    first_column = next(iter(first_column))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn.execute(f"UPDATE {table} SET {first_column} = 'tampered'")


@pytest.mark.parametrize("table", RAW_TABLES)
def test_raw_rows_cannot_be_deleted(db, table):
    _seed(db)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn.execute(f"DELETE FROM {table}")


@pytest.mark.parametrize("table", DERIVED_TABLES)
def test_derived_tables_are_rewritable(db, table):
    # Derived data is recomputable by definition, so it must NOT be locked.
    db.clear_derived(table)


def test_clear_derived_refuses_a_raw_table(db):
    with pytest.raises(ValueError, match="append-only"):
        db.clear_derived("calls")


def test_call_idempotency_key_rejects_a_duplicate(db):
    _seed(db)
    duplicate = dict([r for t, r in SEED_ROWS if t == "calls"][0])
    duplicate["call_id"] = "call_2"  # different id, same (run, pair, model, prompt, repeat)
    with pytest.raises(sqlite3.IntegrityError):
        db.insert("calls", duplicate)


def test_a_correction_is_a_new_superseding_row(db):
    _seed(db)
    db.insert(
        "claims",
        dict(
            claim_id="clm_2", source_id="src_1", source_location="l", source_step_text="s",
            atomic_text="corrected", level=1, kind="existential", version=2, supersedes="clm_1",
            created_at=utc_now(),
        ),
    )
    rows = db.query("SELECT claim_id, atomic_text, supersedes FROM claims ORDER BY claim_id")
    assert [r["atomic_text"] for r in rows] == ["a", "corrected"]
    assert rows[1]["supersedes"] == "clm_1"
