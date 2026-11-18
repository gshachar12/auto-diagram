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


def _tshark_available() -> bool:
    from Dataset.pcap import PcapServiceError

    try:
        from Dataset.pcap.service import resolve_tshark

        resolve_tshark()
        return True
    except PcapServiceError:
        return False


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    """
    The demo dataset, with a stored analysis where tshark allows one.

    The analysis is part of the fixture because the dashboard reads its
    derived numbers rather than recomputing them: a page tested against a
    database with no analysis would only ever exercise the "not analysed
    yet" path, which is the easy half.
    """
    directory = tmp_path_factory.mktemp("web")
    config = Config.load(CONFIG_DIR / "demo")
    summary = seed_demo(
        db_path=directory / "demo.db",
        results_path=directory / "results.jsonl",
        config=config,
    )
    summary["analysis_id"] = None
    if _tshark_available():
        from Dataset.analysis import AnalysisParams, analyse

        database = Database(directory / "demo.db").initialise()
        try:
            params = AnalysisParams.from_config(config).with_overrides({"bootstrap_resamples": 40})
            summary["analysis_id"] = analyse(database, config=config, params=params).analysis_id
        finally:
            database.close()
    return summary, directory


needs_analysis = pytest.mark.skipif(not _tshark_available(), reason="the analysis needs tshark")


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


@needs_analysis
def test_the_claim_detail_shows_the_system_recomputed_packets(db):
    """
    The most important view: what the capture says, beside what was said.

    The packet table here is the system re-running the model's own
    condition -- never the packets the model reported -- and a cited packet
    that does not satisfy that condition is listed separately.
    """
    detail = next(
        views.pair_detail(db, row["pair_id"])
        for row in views.claims_table(db) if row["pair_type"] != "no_pcap"
    )
    assert detail["evidence"]["status"] in ("computed", "unavailable")
    assert detail["evidence"]["analysis_id"]
    executed = [c for c in detail["evidence"]["conditions"] if c["status"] == "ok"]
    assert executed, "at least one condition must have been re-executed"
    for entry in executed:
        assert entry["match_count"] is not None
        assert set(entry["cited_verified"]) & set(entry["cited_unverified"]) == set()


@needs_analysis
def test_a_call_the_capture_could_not_answer_is_null_not_zero(db):
    """A no_pcap item has no evidence, and the view says so rather than scoring it."""
    row = next(r for r in views.claims_table(db) if r["pair_type"] == "no_pcap")
    detail = views.pair_detail(db, row["pair_id"])
    for cell in detail["matrix"]:
        if cell["evidence"]:
            assert cell["evidence"]["status"] != "ok"
            assert cell["evidence"]["reexecuted_count"] is None
            assert cell["evidence"]["note"]


@needs_analysis
def test_evidence_quality_reports_every_rate_with_its_n(db):
    data = views.evidence_quality(db)
    assert data["status"] == "computed"
    names = {row["metric"] for row in data["rates"]}
    assert {"fabricated_packet_call_rate", "cited_and_verified_rate",
            "sufficiency_pass_rate", "necessity_pass_rate"} <= names
    for row in data["rates"]:
        assert row["n"] is not None
        if row["value"] is not None:
            assert row["ci_low"] is not None and row["ci_high"] is not None
    assert data["coverage"]["value"] is not None


def test_evidence_quality_says_so_when_nothing_has_been_analysed(db, tmp_path):
    """Without a stored analysis the section stays empty rather than guessing."""
    from Dataset.storage.db import Database as DatabaseType

    bare = DatabaseType(tmp_path / "bare.db").initialise()
    try:
        for table in ("analysis_metrics", "analysis_call_facts", "analyses"):
            bare.clear_derived(table)
        # Copy nothing: an empty database has no run at all, which is the
        # other end of the same path.
        assert views.evidence_quality(bare) == {}
    finally:
        bare.close()


@needs_analysis
def test_the_panel_reports_error_correlation_calibration_and_effective_votes(db):
    data = views.panel(db)
    assert data["analysis"]["analysis_id"]
    assert data["error_correlation"], "a stored analysis must supply the pairwise correlation"
    for row in data["error_correlation"]:
        for key in ("phi", "double_fault", "agreement"):
            assert row[key] is None or row[key]["n"] is not None
    assert data["effective_votes"] is not None
    assert data["calibration"]
    for row in data["calibration"]:
        assert row["n"] is not None
    # kappa is never shown without AC1 beside it.
    assert data["agreement_overall"]["fleiss_kappa"] is not None
    assert data["agreement_overall"]["gwet_ac1"] is not None
    assert data["pending"] == {}


@needs_analysis
def test_prompt_sensitivity_reports_the_dimension_effect_and_position_bias(db):
    data = views.prompt_sensitivity(db)
    assert data["analysis"]["analysis_id"]
    assert data["flip_rate_excess"]["n"] is not None
    assert data["variance"], "the variance factors come from the stored analysis"
    # The demo has no label-order variant, so position bias must be pending
    # with its reason -- not reported as zero.
    assert data["position_bias"]["value"] is None
    assert data["position_bias"]["detail"]["reason"]


@needs_analysis
def test_the_controls_view_no_longer_blames_an_unfinished_milestone(db):
    data = views.controls(db)
    assert "mutation_validation" not in data["pending"]
    assert "found nothing on its capture" in data["validation_note"]
    assert data["bootstrap_by_pair_type"]
    for row in data["bootstrap_by_pair_type"]:
        assert row["n"] is not None


@needs_analysis
def test_the_overview_pending_list_names_only_what_is_really_missing(db):
    data = views.overview(db)
    assert data["analysis"]["analysis_id"]
    # The stale notes that blamed B1, B3 and B4 for work that has landed.
    assert "packet_verification" not in data["pending"]
    assert "mutation_validation" not in data["pending"]
    assert "evidence_recomputation" not in data["pending"]
    for reason in data["pending"].values():
        assert reason and reason != "not computed"


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
     "/api/controls", "/api/evidence", "/api/manifest", "/api/pcaps", "/api/analyses",
     "/api/export/claims.csv", "/api/export/claims.json", "/api/export/calls.csv",
     "/api/export/calls.json", "/api/export/consensus.json", "/api/export/manifest.json"],
)
def test_endpoint_responds(client, path):
    assert client.get(path).status_code == 200


@needs_analysis
@pytest.mark.parametrize(
    "path", ["/api/analysis", "/api/export/scores.csv", "/api/export/scores.json", "/api/export/metrics.csv"]
)
def test_the_analysis_endpoints_respond(client, path):
    assert client.get(path).status_code == 200


@needs_analysis
def test_the_analysis_endpoint_serves_the_stored_metrics(client):
    payload = client.get("/api/analysis").json()
    assert payload["analysis"]["analysis_id"]
    assert payload["metrics"]
    for row in payload["metrics"]:
        assert set(row) >= {"scope", "scope_id", "metric", "value", "n", "ci_low", "ci_high", "detail"}
    only_run = client.get("/api/analysis?scope=run").json()["metrics"]
    assert only_run and all(row["scope"] == "run" for row in only_run)


@needs_analysis
def test_a_what_if_through_the_api_stores_nothing(client):
    before = client.get("/api/analyses").json()["analyses"]
    payload = client.post("/api/analysis/what-if", json={"params": {"majority_threshold": 0.95}}).json()
    assert payload["persisted"] is False
    assert "stored" in payload["note"] or "not for changing" in payload["note"]
    after = client.get("/api/analyses").json()["analyses"]
    assert [a["analysis_id"] for a in before] == [a["analysis_id"] for a in after]


def test_a_what_if_with_an_unknown_parameter_is_refused(client):
    assert client.post("/api/analysis/what-if", json={"params": {"nonsense": 1}}).status_code == 400
    assert client.post("/api/analysis/what-if", json={}).status_code == 400


@needs_analysis
def test_a_diff_of_an_analysis_with_itself_reports_no_change(client):
    analysis_id = client.get("/api/analyses").json()["latest"]
    report = client.get(f"/api/analysis/diff?left={analysis_id}&right={analysis_id}").json()
    assert report["changed"] == []
    assert report["unchanged"] > 0


def test_a_diff_of_something_unstored_is_a_404(client):
    assert client.get("/api/analysis/diff?left=ana_a&right=ana_b").status_code == 404


def test_the_captures_list_names_every_registered_capture(client, db):
    payload = client.get("/api/pcaps").json()
    assert len(payload["captures"]) == db.count("pcaps")
    for capture in payload["captures"]:
        assert capture["sha256"] and capture["path"]
    assert all(not f["path"].startswith("/") for f in payload["files"])


def test_the_exports_cover_answers_scores_consensus_and_the_manifest(client):
    calls = client.get("/api/export/calls.json").json()
    assert calls and "raw_response" in calls[0]
    consensus = client.get("/api/export/consensus.json").json()
    assert consensus and "panel_verdict" in consensus[0]
    manifest = client.get("/api/export/manifest.json").json()
    assert manifest["manifest"]["code"]["git_commit"]
    # Parsed, not split on newlines: a stored response contains them.
    import csv as csv_module
    import io as io_module

    rows = list(csv_module.DictReader(io_module.StringIO(client.get("/api/export/calls.csv").text)))
    assert len(rows) == len(calls)
    assert rows[0]["call_id"] and rows[0]["raw_response"] is not None


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


def test_the_capture_summary_describes_the_file_or_says_why_not(client, db):
    pcap_id = db.one("SELECT pcap_id FROM pcaps ORDER BY size_bytes LIMIT 1")["pcap_id"]
    payload = client.get(f"/api/pcap/{pcap_id}/summary").json()
    if payload["available"]:
        assert payload["packet_count"] > 0
        assert payload["protocol_hierarchy"]
    else:
        # A capture too large to dissect says so; it never returns an empty
        # protocol list as though the file held nothing.
        assert payload["reason"]


def test_a_refused_filter_shows_tsharks_own_words_and_no_table(client, db):
    pcap_id = db.one("SELECT pcap_id FROM pcaps ORDER BY size_bytes LIMIT 1")["pcap_id"]
    response = client.get(f"/api/pcap/{pcap_id}/query", params={"filter": "nonsense.field == "})
    assert response.status_code == 400
    assert "refused" in response.json()["detail"]
    assert "packets" not in response.json()


def test_the_filter_box_is_rate_limited_per_capture(client, db):
    """
    A filter is a full read of the file, so the explorer gets a ceiling.

    The limit is configuration (`pcap_tool.max_queries_per_minute`) and it
    is charged only for a scan that actually ran: a filter tshark refused
    never touched the capture.
    """
    pcap_id = db.one("SELECT pcap_id FROM pcaps ORDER BY size_bytes DESC LIMIT 1")["pcap_id"]
    first = client.get(f"/api/pcap/{pcap_id}/query", params={"filter": "tcp"})
    assert first.status_code in (200, 429, 503)
    if first.status_code != 200:
        pytest.skip("the capture could not be scanned here")
    second = client.get(f"/api/pcap/{pcap_id}/query", params={"filter": "udp"})
    assert second.status_code == 429
    assert "scan" in second.json()["detail"]
    # While the ceiling holds, nothing reaches the capture at all -- the
    # budget is only charged for a scan that actually ran, so a refused
    # filter never costs the reader the next few seconds.


def test_a_text_file_can_be_downloaded_as_it_is_on_disk(client, db):
    path = next(iter(views.readable_paths(db) - {row["path"] for row in db.query("SELECT path FROM pcaps")}))
    response = client.get("/api/file/download", params={"path": path})
    assert response.status_code in (200, 404)  # 404 only if the file is not on this host
    assert client.get("/api/file/download", params={"path": "/etc/passwd"}).status_code == 404
    capture = db.one("SELECT path FROM pcaps")["path"]
    assert client.get("/api/file/download", params={"path": capture}).status_code == 415


def test_the_claims_table_can_be_narrowed_to_one_capture(client, db):
    pcap_id = db.one("SELECT pcap_id FROM pcaps")["pcap_id"]
    rows = client.get("/api/claims", params={"pcap_id": pcap_id}).json()
    assert rows
    assert all(row["pcap_id"] == pcap_id for row in rows)
    assert len(rows) < len(client.get("/api/claims").json())


def test_the_captures_section_carries_the_explorer_and_the_file_viewer():
    """
    The two tools live inline in the Captures section, with their controls
    explained where they are used.
    """
    from Dataset.web.app import STATIC_DIR

    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    for needed in ("STARTER_FILTERS", "applyFilter(", "renderHistory(", "renderSheet(",
                   "sortSheet(", "toggleColumn(", "showClaimsFor("):
        assert needed in html, needed
    # The truncation statement is not optional: a capped scan must never
    # read as the whole count.
    assert "the real count is higher than" in html
    assert "file/download" in html


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


def test_every_section_has_a_caption_and_a_renderer():
    """
    One scrolling page, and every section on it explains itself.

    The caption is not decoration: a reader who has not read the spec has
    no way to know that a vote share is agreement rather than accuracy, and
    a dashboard that does not say so invites exactly the reading the whole
    project is built to prevent.
    """
    import re

    from Dataset.web.app import STATIC_DIR

    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    sections = re.findall(r"\n  \['(\w+)','([^']+)',\n", html)
    assert len(sections) >= 10, sections
    entries = re.findall(r"\['(\w+)','[^']+',\n(.*?)\n   \+? ?'?[^\n]*?, (v\w+)\]", html, re.S)
    assert len(entries) == len(sections), "every section needs a caption and a render function"
    for key, caption, renderer in entries:
        assert len(caption) > 40, f"{key} has no real caption"
        assert f"function {renderer}(" in html, f"{key} names a renderer that does not exist"


def test_the_page_has_no_hidden_tabs():
    """Everything is on one page; the links at the top only scroll to it."""
    from Dataset.web.app import STATIC_DIR

    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert "<nav" not in html
    assert 'id="jump"' in html
    # The sections exist once, as the template the script builds them from,
    # and nowhere as a pane that something could hide.
    assert html.count('<section class="section"') == 1
    assert "buildSections()" in html
    assert "state.tab" not in html
