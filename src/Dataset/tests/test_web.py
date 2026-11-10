"""
The dashboard's read model and its endpoints.

The point of these tests is the dashboard's promise: every number it shows
comes from stored rows and can be traced back to the response behind it,
and anything that has not actually been computed is reported as pending
rather than filled in with something plausible.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from Dataset.config import CONFIG_DIR, Config
from Dataset.demo import seed_demo
from Dataset.storage.db import Database
from Dataset.web import views
from Dataset.web.app import create_app


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    directory = tmp_path_factory.mktemp("web")
    summary = seed_demo(
        db_path=directory / "demo.db",
        results_path=directory / "results.jsonl",
        config=Config.load(CONFIG_DIR / "demo"),
    )
    return summary, directory


@pytest.fixture(scope="module")
def db(seeded):
    _, directory = seeded
    database = Database(directory / "demo.db")
    yield database
    database.close()


@pytest.fixture(scope="module")
def client(seeded, monkeypatch_module=None):
    import os

    _, directory = seeded
    os.environ["PANGEA_DATA_DIR"] = str(directory)
    (directory / "dataset.db").write_bytes((directory / "demo.db").read_bytes())
    yield TestClient(create_app())
    os.environ.pop("PANGEA_DATA_DIR", None)


# -- statistics ----------------------------------------------------------

def test_wilson_interval_brackets_the_estimate():
    low, high = views.wilson_interval(8, 10)
    assert low < 0.8 < high
    assert 0.0 <= low and high <= 1.0


def test_wilson_interval_of_nothing_is_the_whole_range():
    assert views.wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_interval_never_leaves_the_scale_at_the_extremes():
    # The reason for Wilson over the normal approximation: 10/10 must not
    # produce an upper bound above 1 or a zero-width interval.
    low, high = views.wilson_interval(10, 10)
    assert high <= 1.0 and low < 1.0


def test_entropy_is_zero_for_unanimity_and_maximal_for_a_three_way_split():
    assert views.entropy_bits([7]) == 0.0
    assert views.entropy_bits([3, 3, 3]) == pytest.approx(1.585, abs=1e-3)


# -- the read model -------------------------------------------------------

def test_overview_reports_demo_and_unverified_captures(db):
    data = views.overview(db)
    joined = " ".join(data["warnings"])
    assert "DEMO" in joined
    assert "packet count" in joined
    assert data["counts"]["calls"] > 0


def test_every_claims_row_shows_its_n(db):
    rows = views.claims_table(db)
    assert rows
    assert all(row["n_calls"] > 0 for row in rows)
    assert all(0.0 <= row["vote_share"] <= 1.0 for row in rows)


def test_format_errors_do_not_vote(db):
    # A model that failed to answer must not be counted as abstaining: that
    # would flatter it in the abstention rate and in the majority.
    rows = views.claims_table(db)
    for row in rows:
        assert sum(row["votes"].values()) <= row["families_voting"]


def test_swaps_are_scored_as_not_supported_never_as_refuted(db):
    rows = [r for r in views.claims_table(db) if r["pair_type"] == "swap"]
    assert rows
    for row in rows:
        if row["matches_expected"] is not None:
            assert row["matches_expected"] == (row["panel_verdict"] != "SUPPORTED")


def test_source_pairs_resting_on_an_author_claim_are_not_scored(db):
    rows = [r for r in views.claims_table(db) if r["expected_basis"] == "author"]
    assert rows
    assert all(row["matches_expected"] is None for row in rows)


def test_pair_detail_traces_back_to_stored_calls(db):
    rows = views.claims_table(db)
    detail = views.pair_detail(db, rows[0]["pair_id"])
    assert detail["matrix"]
    for cell in detail["matrix"]:
        raw = views.raw_call(db, cell["call_id"])
        assert raw["call_id"] == cell["call_id"]
        assert raw["raw_response"]  # the response behind the number exists


def test_cited_packets_are_marked_unchecked_until_the_analysis_exists(db):
    detail = views.pair_detail(db, views.claims_table(db)[0]["pair_id"])
    assert detail["evidence"]["status"] == "pending"
    assert "PCAP service" in detail["evidence"]["note"]


def test_evidence_quality_refuses_to_invent_verification_numbers(db):
    data = views.evidence_quality(db)
    assert data["status"] == "pending"
    assert "fabricated_packet_rate" in data["pending"]
    # Nothing that looks like a verified rate may be present.
    assert "cited_and_verified_rate" not in data["citations"]


def test_panel_reduces_to_families_and_reports_n(db):
    data = views.panel(db)
    assert data["families"]
    for family in data["families"]:
        assert family["controls"]["n"] >= 0
        assert family["n_calls"] > 0
    for row in data["pairwise_family_agreement"]:
        assert row["n"] >= 0


def test_prompt_sensitivity_reports_the_noise_floor_alongside_the_effect(db):
    data = views.prompt_sensitivity(db)
    assert data["prompt_flip_rate"]["n"] > 0
    assert data["repeat_flip_rate"]["n"] > 0
    assert "cannot be proved" in data["note"]


def test_controls_report_leakage_with_its_n(db):
    data = views.controls(db)
    assert data["leakage"]["n"] > 0
    assert 0.0 <= data["leakage"]["rate"] <= 1.0


# -- endpoints ------------------------------------------------------------

@pytest.mark.parametrize(
    "path",
    ["/", "/healthz", "/api/overview", "/api/claims", "/api/panel", "/api/prompts",
     "/api/controls", "/api/evidence", "/api/manifest", "/api/export/claims.csv",
     "/api/export/claims.json"],
)
def test_endpoint_responds(client, path):
    assert client.get(path).status_code == 200


def test_claims_filters_narrow_the_result(client):
    everything = client.get("/api/claims").json()
    mutations = client.get("/api/claims?pair_type=mutation").json()
    assert 0 < len(mutations) < len(everything)
    assert all(row["pair_type"] == "mutation" for row in mutations)


def test_a_missing_pair_is_a_404(client):
    assert client.get("/api/pair/pair_does_not_exist").status_code == 404


def test_the_dashboard_never_calls_a_number_correct_or_ground_truth(client):
    # The wording rule from the spec, checked where it is easiest to break:
    # the page itself. "ground truth" may appear only where it is denied.
    page = client.get("/").text.lower()
    assert "silver" in page
    for forbidden in ("ground truth", "correct"):
        position = page.find(forbidden)
        while position != -1:
            # Allowed only where the page denies the word, as in the banner
            # ("not ground truth", "never as correct").
            preceding = page[max(0, position - 40):position]
            assert "not" in preceding or "never" in preceding, page[max(0, position - 80):position + 20]
            position = page.find(forbidden, position + 1)


def test_export_csv_has_a_header_and_one_row_per_pair(client):
    rows = client.get("/api/export/claims.csv").text.strip().splitlines()
    assert len(rows) == len(client.get("/api/claims").json()) + 1
    assert "pair_id" in rows[0]
