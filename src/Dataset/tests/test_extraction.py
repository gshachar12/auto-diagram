"""
The extraction agent and the review queue.

The agent writes conditions; the capture decides whether they hold. These
tests are about the handover: that a condition which finds nothing is
flagged rather than dropped or kept, that every call is recorded, and that
a reviewer can never overwrite what the agent produced.
"""
from __future__ import annotations

import json

import pytest

from Dataset.extraction import ExtractionAgent, HeuristicExtractionClient, extract_all
from Dataset.ids import content_id
from Dataset.pcap import PcapService, PcapServiceError
from Dataset.review import ReviewError, apply_action, queue, review_stats
from Dataset.schemas import Source
from Dataset.storage.repository import Repository, utc_now


def _tshark_available() -> bool:
    try:
        from Dataset.pcap.service import resolve_tshark

        resolve_tshark()
        return True
    except PcapServiceError:
        return False


@pytest.fixture
def source_with_steps(db, tmp_path):
    """One source, four steps, one small real capture."""
    from scapy.all import IP, TCP, wrpcap

    from Dataset.schemas import CaptureMetadata, Pcap

    repo = Repository(db)
    source_id = content_id("src", ["test"])
    repo.add_source(Source(source_id=source_id, title="Test source"))

    capture = tmp_path / "sample.pcap"
    wrpcap(str(capture), [IP(dst="10.0.0.1") / TCP(dport=p, flags="S") for p in range(20)])
    repo.add_pcap(
        Pcap(
            pcap_id="pcap_test", source_id=source_id, path=str(capture), sha256="0" * 64,
            size_bytes=capture.stat().st_size, capture_metadata=CaptureMetadata(vantage_point="test"),
        )
    )

    steps = [
        "The attacker performs a network scan with Nmap",
        "The attacker brute-forces SSH credentials",
        "The attacker gains access and escalates privileges",
        "The operator reviews the quarterly budget",
    ]
    for number, text in enumerate(steps, start=1):
        db.insert(
            "source_steps",
            dict(
                step_id=content_id("stp", [source_id, number]), source_id=source_id,
                origin_file="steps.csv", row_number=number, step_order=str(number),
                text=text, fields=json.dumps({"attack_step": text}), created_at=utc_now(),
            ),
        )
    return source_id, tmp_path


@pytest.fixture
def extracted(db, source_with_steps):
    source_id, tmp_path = source_with_steps
    service = PcapService(allowed_roots=[tmp_path]) if _tshark_available() else None
    agent = ExtractionAgent(db=db, service=service, repo_root=tmp_path.parent)
    return agent.extract_source(source_id), source_id


# -- extraction -----------------------------------------------------------

def test_every_step_produces_at_least_one_claim(db, extracted):
    summary, _ = extracted
    assert summary["steps_processed"] == 4
    assert summary["claims"] >= 4


def test_claims_carry_their_step_and_location(db, extracted):
    for row in db.query("SELECT * FROM claims"):
        assert row["source_step_text"]
        assert "#" in row["source_location"]  # file#row, so it is findable again


def test_levels_one_to_three_get_a_condition_and_four_to_five_do_not(db, extracted):
    for row in db.query("SELECT level, condition, reason_code FROM claims"):
        if row["level"] <= 3:
            assert row["condition"], "a checkable claim with no condition is not checkable"
        else:
            assert row["condition"] is None
            assert row["reason_code"], "an abstention must say why"


def test_an_outcome_step_becomes_a_deliberate_abstention(db, extracted):
    rows = db.query("SELECT level, reason_code FROM claims WHERE atomic_text LIKE 'The step succeeded%'")
    assert rows
    assert all(row["level"] == 5 and row["reason_code"] == "OUTCOME" for row in rows)


def test_a_step_no_rule_matches_is_not_given_an_invented_condition(db, extracted):
    row = db.one("SELECT * FROM claims WHERE source_step_text LIKE '%quarterly budget%'")
    assert row["condition"] is None
    assert row["reason_code"] == "NOT_EXPRESSIBLE"


def test_every_extraction_call_is_stored(db, extracted):
    summary, _ = extracted
    calls = db.query("SELECT * FROM llm_calls WHERE purpose = 'extraction'")
    assert len(calls) == summary["steps_processed"]
    for call in calls:
        assert call["prompt"] and call["raw_response"]
        assert call["model_version"]


def test_the_extraction_prompt_contains_the_step_and_the_capture(db, extracted):
    prompt = db.one("SELECT prompt FROM llm_calls WHERE purpose = 'extraction'")["prompt"]
    assert "STEP:" in prompt and "CAPTURE:" in prompt


def test_extraction_is_resumable_and_does_not_duplicate(db, source_with_steps):
    source_id, tmp_path = source_with_steps
    agent = ExtractionAgent(db=db, repo_root=tmp_path.parent)
    first = agent.extract_source(source_id)
    second = agent.extract_source(source_id)
    assert first["claims"] > 0
    assert second["steps_processed"] == 0  # already extracted, nothing redone


def test_claims_are_marked_as_the_agents_work(db, extracted):
    assert {row["provenance"] for row in db.query("SELECT provenance FROM claims")} == {"agent"}


# -- condition checks ------------------------------------------------------

@pytest.mark.skipif(not _tshark_available(), reason="tshark not available")
def test_conditions_are_run_against_the_source_capture(db, extracted):
    checks = db.query("SELECT * FROM claim_condition_checks")
    assert checks
    for check in checks:
        assert check["display_filter"]
        assert check["match_count"] is not None or check["error"]


@pytest.mark.skipif(not _tshark_available(), reason="tshark not available")
def test_a_condition_that_finds_nothing_is_flagged_not_dropped(db, extracted, source_with_steps):
    source_id, tmp_path = source_with_steps
    # The capture is SYN-only, so an SSH-port condition finds nothing.
    ssh = db.one("SELECT claim_id FROM claims WHERE condition LIKE '%22%'")
    if ssh is None:
        pytest.skip("no port-22 claim in this extraction")
    check = db.one("SELECT holds, match_count FROM claim_condition_checks WHERE claim_id = ?", (ssh["claim_id"],))
    assert check["holds"] == 0 and check["match_count"] == 0
    # It is still a claim, and the queue surfaces it first.
    flagged = [item for item in queue(db) if item["claim_id"] == ssh["claim_id"]]
    assert flagged and "CONDITION_FINDS_NOTHING" in flagged[0]["flags"]


@pytest.mark.skipif(not _tshark_available(), reason="tshark not available")
def test_the_check_table_is_derived_and_clearable(db, extracted):
    db.clear_derived("claim_condition_checks")
    assert db.count("claim_condition_checks") == 0


# -- review ---------------------------------------------------------------

def test_the_queue_lists_unreviewed_claims_worst_first(db, extracted):
    items = queue(db)
    assert items
    flagged = [bool(item["flags"]) for item in items]
    assert flagged == sorted(flagged, reverse=True)


def test_accepting_removes_an_item_from_the_queue(db, extracted):
    claim_id = queue(db)[0]["claim_id"]
    apply_action(db, claim_id=claim_id, action="accept", notes="fine")
    assert claim_id not in {item["claim_id"] for item in queue(db)}
    assert db.one("SELECT action FROM claim_reviews WHERE claim_id = ?", (claim_id,))["action"] == "accept"


def test_an_edit_creates_a_new_version_and_keeps_the_original(db, extracted):
    original = queue(db)[0]
    result = apply_action(
        db, claim_id=original["claim_id"], action="edit",
        edits={"atomic_text": "A reviewer's wording", "level": 2, "condition": {"display_filter": "tcp.port == 80"}},
    )
    new_id = result["produced"][0]
    new_row = db.one("SELECT * FROM claims WHERE claim_id = ?", (new_id,))
    old_row = db.one("SELECT * FROM claims WHERE claim_id = ?", (original["claim_id"],))

    assert new_row["atomic_text"] == "A reviewer's wording"
    assert new_row["supersedes"] == original["claim_id"]
    assert new_row["version"] == original["version"] + 1
    assert new_row["provenance"] == "human"
    # The agent's original is untouched and still readable.
    assert old_row["atomic_text"] == original["atomic_text"]
    assert old_row["provenance"] == "agent"
    # And it is gone from the queue, replaced by its successor.
    live = {item["claim_id"] for item in queue(db)}
    assert original["claim_id"] not in live and new_id in live


def test_a_split_produces_one_claim_per_part(db, extracted):
    original = queue(db)[0]
    result = apply_action(
        db, claim_id=original["claim_id"], action="split",
        parts=[{"atomic_text": "First half"}, {"atomic_text": "Second half"}],
    )
    assert len(result["produced"]) == 2
    texts = {db.one("SELECT atomic_text FROM claims WHERE claim_id = ?", (cid,))["atomic_text"]
             for cid in result["produced"]}
    assert texts == {"First half", "Second half"}


def test_a_split_needs_at_least_two_parts(db, extracted):
    with pytest.raises(ReviewError, match="at least two"):
        apply_action(db, claim_id=queue(db)[0]["claim_id"], action="split", parts=[{"atomic_text": "one"}])


def test_a_merge_supersedes_every_claim_it_absorbs(db, extracted):
    items = queue(db)
    first, second = items[0]["claim_id"], items[1]["claim_id"]
    result = apply_action(db, claim_id=first, action="merge", merge_with=[second])
    merged = result["produced"][0]
    live = {item["claim_id"] for item in queue(db)}
    assert merged in live
    assert first not in live and second not in live
    # The absorbed claim records its own review, so it did not just vanish.
    assert db.one("SELECT action FROM claim_reviews WHERE claim_id = ?", (second,))["action"] == "merge"


def test_rejecting_keeps_the_row(db, extracted):
    claim_id = queue(db)[0]["claim_id"]
    apply_action(db, claim_id=claim_id, action="reject", notes="not checkable")
    assert db.one("SELECT claim_id FROM claims WHERE claim_id = ?", (claim_id,)) is not None
    reviewed = {item["claim_id"]: item for item in queue(db, include_reviewed=True)}
    assert reviewed[claim_id]["review_action"] == "reject"


def test_an_unknown_action_is_refused(db, extracted):
    with pytest.raises(ReviewError, match="unknown review action"):
        apply_action(db, claim_id=queue(db)[0]["claim_id"], action="approve-ish")


def test_review_stats_count_what_is_live(db, extracted):
    stats = review_stats(db)
    assert stats["claims_live"] > 0
    assert stats["by_action"]["pending"] == stats["claims_live"]
    apply_action(db, claim_id=queue(db)[0]["claim_id"], action="accept")
    assert review_stats(db)["by_action"]["accept"] == 1


def test_extract_all_covers_every_source(db, source_with_steps):
    summary = extract_all(db=db, service=None)
    assert summary["sources"]
    assert sum(entry["claims"] for entry in summary["sources"]) > 0
