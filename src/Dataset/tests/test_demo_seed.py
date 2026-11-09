"""
The demo dataset.

It exists so the dashboard and the analysis can be built before real
results exist, which only works if it is reproducible: the replay test that
B5 will run on real responses is this same property, checked early.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from Dataset.demo import seed_demo
from Dataset.schemas import PairType, Verdict
from Dataset.storage.db import Database
from Dataset.storage.repository import read_results_jsonl


@pytest.fixture(scope="module")
def seeded(tmp_path_factory, request):
    from Dataset.config import CONFIG_DIR, Config

    directory = tmp_path_factory.mktemp("demo")
    summary = seed_demo(
        db_path=directory / "demo.db",
        results_path=directory / "results.jsonl",
        config=Config.load(CONFIG_DIR / "demo"),
    )
    return summary, directory


def test_seeding_produces_a_complete_dataset(seeded):
    summary, _ = seeded
    counts = summary["counts"]
    assert counts["sources"] >= 3
    assert counts["claims"] >= 10
    assert counts["pairs"] >= 20
    assert counts["calls"] > 0


def test_all_four_pair_types_are_present(seeded):
    summary, _ = seeded
    assert set(summary["pairs_by_type"]) == {t.value for t in PairType}
    assert all(count > 0 for count in summary["pairs_by_type"].values())


def test_seeding_twice_reproduces_the_same_dataset(tmp_path):
    from Dataset.config import CONFIG_DIR, Config

    def run(name: str):
        directory = tmp_path / name
        summary = seed_demo(
            db_path=directory / "demo.db",
            results_path=directory / "results.jsonl",
            config=Config.load(CONFIG_DIR / "demo"),
        )
        rows = [json.loads(line) for line in (directory / "results.jsonl").read_text().splitlines()]
        for row in rows:  # the wall clock is the only thing allowed to differ
            row.pop("timestamp")
        return summary["run_id"], rows

    first_run_id, first_rows = run("a")
    second_run_id, second_rows = run("b")
    assert first_run_id == second_run_id
    assert first_rows == second_rows


def test_every_call_is_in_both_the_database_and_the_jsonl(seeded):
    summary, directory = seeded
    jsonl_ids = {row["call_id"] for row in read_results_jsonl(directory / "results.jsonl")}
    db = Database(directory / "demo.db")
    db_ids = {row["call_id"] for row in db.query("SELECT call_id FROM calls")}
    db.close()
    assert jsonl_ids == db_ids
    assert len(jsonl_ids) == summary["calls"]


def test_failures_are_stored_rather_than_dropped(seeded):
    summary, directory = seeded
    # The demo mix includes malformed answers and refusals on purpose: if
    # none survived into storage, something is swallowing them.
    assert summary["format_errors"] > 0
    db = Database(directory / "demo.db")
    errors = db.count("calls") and db.query("SELECT COUNT(*) n FROM calls WHERE format_error = 1")[0]["n"]
    tool_errors = db.query("SELECT COUNT(*) n FROM calls WHERE error IS NOT NULL")[0]["n"]
    db.close()
    assert errors == summary["format_errors"]
    assert tool_errors > 0


def test_no_pcap_pairs_reference_no_capture(seeded):
    _, directory = seeded
    db = Database(directory / "demo.db")
    rows = db.query("SELECT pcap_id, expected FROM pairs WHERE pair_type = 'no_pcap'")
    db.close()
    assert rows
    assert all(row["pcap_id"] is None for row in rows)
    assert all(row["expected"] == Verdict.NOT_VERIFIABLE for row in rows)


def test_abstention_levels_expect_an_abstention(seeded):
    _, directory = seeded
    db = Database(directory / "demo.db")
    rows = db.query("SELECT expected FROM pairs WHERE pair_type = 'source' AND level >= 4")
    db.close()
    assert rows
    assert all(row["expected"] == Verdict.NOT_VERIFIABLE for row in rows)


def test_swaps_carry_no_expected_verdict(seeded):
    # A swap is scored as "not SUPPORTED": calling it REFUTED would assume a
    # closed world on a capture the claim never came from.
    _, directory = seeded
    db = Database(directory / "demo.db")
    rows = db.query("SELECT expected, expected_basis FROM pairs WHERE pair_type = 'swap'")
    db.close()
    assert rows
    assert all(row["expected"] is None for row in rows)
    assert all(row["expected_basis"] == "construction" for row in rows)


def test_capture_packet_counts_stay_unverified_until_the_pcap_service_exists(seeded):
    _, directory = seeded
    db = Database(directory / "demo.db")
    pcaps = db.query("SELECT packet_count FROM pcaps")
    checks = db.query("SELECT status FROM verification_checks WHERE item LIKE '%packet count%'")
    db.close()
    assert all(row["packet_count"] is None for row in pcaps)
    assert all(row["status"] == "unverified" for row in checks)


def test_the_run_manifest_is_stored_with_the_run(seeded):
    summary, directory = seeded
    db = Database(directory / "demo.db")
    manifest = json.loads(db.one("SELECT manifest FROM runs WHERE run_id = ?", (summary["run_id"],))["manifest"])
    db.close()
    assert manifest["code"]["git_commit"]
    assert manifest["config"]["config_hash"]
    assert len(manifest["pcaps"]) == summary["counts"]["pcaps"]
    assert manifest["models"]


def test_a_seeded_run_cannot_be_silently_rewritten(seeded):
    _, directory = seeded
    db = Database(directory / "demo.db")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn.execute("UPDATE calls SET raw_response = 'tampered'")
    db.close()


def test_demo_data_attributes_no_publication(seeded):
    # The demo claims are synthetic. Nothing here may look like a quotation
    # from a paper, so the source rows must say so in plain words.
    _, directory = seeded
    db = Database(directory / "demo.db")
    rows = db.query("SELECT title, notes, license FROM sources")
    db.close()
    assert all(row["title"].startswith("DEMO") for row in rows)
    assert all("ynthetic" in row["notes"] for row in rows)
    assert all(row["license"] == "UNVERIFIED" for row in rows)
