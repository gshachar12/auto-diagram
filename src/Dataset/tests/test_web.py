"""
The dashboard's read model and its endpoints.

The point of these tests is the dashboard's promise: every number it shows
comes from stored rows and can be traced back to the response behind it,
and anything that has not actually been computed is reported as pending
rather than filled in with something plausible.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

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
def client(seeded):
    import os

    from Dataset.web.auth import Auth

    _, directory = seeded
    os.environ["PANGEA_DATA_DIR"] = str(directory)
    (directory / "dataset.db").write_bytes((directory / "demo.db").read_bytes())
    store = Auth(directory / "auth.json")
    store.set_password("tests-only-password")
    api = TestClient(create_app(store))
    api.post("/api/login", json={"password": "tests-only-password"})
    yield api
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
    import re

    # Word boundaries, so an HTML attribute like autocorrect="off" is not a
    # claim about a result.
    for forbidden in (r"\bground truth\b", r"\bcorrect\b"):
        for match in re.finditer(forbidden, page):
            # Allowed only where the page denies the word, as in the banner
            # ("not ground truth", "never as correct").
            preceding = page[max(0, match.start() - 40):match.start()]
            assert "not" in preceding or "never" in preceding, page[max(0, match.start() - 80):match.end() + 20]


def test_export_csv_has_a_header_and_one_row_per_pair(client):
    rows = client.get("/api/export/claims.csv").text.strip().splitlines()
    assert len(rows) == len(client.get("/api/claims").json()) + 1
    assert "pair_id" in rows[0]


# -- reading the samples --------------------------------------------------

def test_a_source_lists_its_steps_file_and_its_captures(db):
    rows = views.sources(db)
    source_id = rows[0]["source_id"]
    kinds = {f["kind"] for f in views.source_files(db, source_id)}
    assert "pcap" in kinds or "csv" in kinds
    assert "markdown" in kinds


def test_the_readable_allowlist_comes_from_the_database(db):
    allowed = views.readable_paths(db)
    assert allowed
    # Only paths some row already refers to; nothing else on the host.
    assert all(not p.startswith("/") for p in allowed)
    assert "README.md" not in allowed


@pytest.mark.parametrize("path", ["/etc/passwd", "README.md", "../../etc/passwd", "src/Dataset/cli.py"])
def test_the_file_reader_refuses_anything_not_referenced(client, path):
    assert client.get("/api/file", params={"path": path}).status_code == 404


def test_the_file_reader_refuses_a_capture(client, db):
    pcap_path = db.one("SELECT path FROM pcaps")["path"]
    # Captures go through the PCAP service, which bounds and jails the read.
    assert client.get("/api/file", params={"path": pcap_path}).status_code == 415


def test_a_capture_can_be_read_through_its_registry_row(client, db):
    pcap_id = db.one("SELECT pcap_id FROM pcaps")["pcap_id"]
    payload = client.get(f"/api/pcap/{pcap_id}", params={"limit": 5}).json()
    assert payload["sha256"] and payload["capture_metadata"]
    assert payload["head_error"] is None or payload["head"] == []
    if payload["head"]:
        assert payload["head"][0]["number"] == 1


def test_a_hostile_filter_through_the_api_is_a_400(client, db):
    pcap_id = db.one("SELECT pcap_id FROM pcaps")["pcap_id"]
    response = client.get(f"/api/pcap/{pcap_id}/query", params={"filter": "tcp; rm -rf /"})
    assert response.status_code == 400


def test_a_missing_capture_is_a_404(client):
    assert client.get("/api/pcap/pcap_nope").status_code == 404


# -- who answered, and with which prompt ----------------------------------

def test_the_panel_participants_are_listed_with_exact_versions(client):
    models = client.get("/api/models").json()
    assert models
    for model in models:
        assert model["version"] and "latest" not in model["version"]
        assert model["calls"] > 0
        assert set(model) >= {"model_id", "family", "version", "adapter", "supports_tools", "temperature"}


def test_the_prompt_variants_are_served_with_their_text(client):
    variants = client.get("/api/prompts/variants").json()
    assert variants
    for variant in variants:
        assert variant["template"] and variant["prompt_hash"]


def test_every_call_records_the_prompt_that_produced_it(db):
    rows = views.claims_table(db)
    detail = views.pair_detail(db, rows[0]["pair_id"])
    raw = views.raw_call(db, detail["matrix"][0]["call_id"])
    assert raw["prompt_rendered"]
    # The claim is in the prompt; the expected verdict never is.
    assert raw["prompt_rendered"].strip()
    assert "expected" not in raw["prompt_rendered"].lower()


# -- the page itself -------------------------------------------------------

def test_the_dashboard_javascript_parses():
    """
    The whole page is one script, so a single syntax error renders nothing
    at all -- the view sits at "loading…" forever and every tab is blank.
    That is exactly what happened: a stray backtick closed a template
    literal early and the dashboard was dead for two commits before anyone
    could tell, because the server kept answering 200.
    """
    import re
    import shutil
    import subprocess

    from Dataset.web.app import STATIC_DIR

    node = shutil.which("node") or str(Path.home() / ".n/bin/node")
    if not Path(node).exists():
        pytest.skip("node is not available to parse the page")

    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    script = re.search(r"<script>(.*?)</script>", html, re.S)
    assert script, "the page has no script block"

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as handle:
        handle.write(script.group(1))
        path = handle.name
    try:
        result = subprocess.run([node, "--check", path], capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
    finally:
        Path(path).unlink(missing_ok=True)


def test_every_tab_has_a_render_function():
    """A tab with no renderer throws the moment it is opened."""
    import re

    from Dataset.web.app import STATIC_DIR

    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    tabs = set(re.findall(r"\['(\w+)','[^']+'\]", html))
    dispatch = re.search(r"await \(\{(.*?)\}\[state\.tab\]\)", html, re.S)
    assert dispatch
    wired = set(re.findall(r"(\w+):\s*v\w+", dispatch.group(1)))
    assert tabs == wired, f"tabs without a renderer: {tabs - wired}"
