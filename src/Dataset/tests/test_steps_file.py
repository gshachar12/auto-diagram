"""The steps file: the schema, the rules the validator must enforce, the views."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from Dataset import steps_file
from Dataset.manifest import REPO_ROOT
from Dataset.steps_file import (GENERATED_BANNER, MD_COLUMNS, csv_rows, json_schema,
                                render_csv, render_markdown, steps_files, validate_file,
                                validate_payload)

REAL = REPO_ROOT / "sources" / "NRDelegationAttack" / "steps.json"


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    """A file standing in for a capture, so sha256 and size checks have something real."""
    path = tmp_path / "pcaps" / "x.pcap"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"pretend capture" * 4)
    return path


@pytest.fixture
def payload(capture: Path) -> dict:
    body = capture.read_bytes()
    return {
        "paper": {"id": "P", "title": "T", "authors": None, "venue": None,
                  "year": None, "url": None, "license": None},
        "pcap": {"file": "pcaps/x.pcap", "sha256": hashlib.sha256(body).hexdigest(),
                 "size_bytes": len(body), "packet_count": 10, "origin_url": None,
                 "matches_figure": "Figure 1", "match_note": None},
        "steps": [
            {"step_id": "P-S01", "seq": 1, "phase": "Phase I",
             "source_location": "Figure 1, arrow 1", "verbatim": "a client asks",
             "normalized": "C -> R: query [DNS; qname=x]", "actor": "C", "target": "R",
             "protocol": "DNS", "step_type": "message", "compound": False,
             "pcap_check": {"status": "found", "packets": [3], "filter": "dns", "note": ""},
             "extracted_by": "agent", "needs_review": False},
            {"step_id": "P-S02", "seq": 2, "phase": "Phase I",
             "source_location": "Figure 1, box 2", "verbatim": "it thinks",
             "normalized": "R -> R: thinks [none; internal]", "actor": "R", "target": "R",
             "protocol": None, "step_type": "internal", "compound": True,
             "pcap_check": {"status": "not_found", "packets": [], "filter": "dns", "note": "n"},
             "extracted_by": "agent", "needs_review": False},
        ],
    }


def check(payload: dict, root: Path) -> list[str]:
    _, problems = validate_payload(payload, "t.json", root)
    return [p.message for p in problems]


def test_the_fixture_is_valid(payload, tmp_path):
    assert check(payload, tmp_path) == []


# -- the failures the validator is required to catch ----------------------

def test_missing_field_fails(payload, tmp_path):
    del payload["steps"][0]["protocol"]
    assert any("protocol" in m for m in check(payload, tmp_path))


def test_extra_field_fails(payload, tmp_path):
    payload["steps"][0]["confidence"] = 0.9
    assert any("confidence" in m for m in check(payload, tmp_path))


def test_duplicate_step_id_fails(payload, tmp_path):
    payload["steps"][1]["step_id"] = "P-S01"
    assert any("duplicate step_id" in m for m in check(payload, tmp_path))


def test_gap_in_seq_fails(payload, tmp_path):
    payload["steps"][1]["seq"] = 3
    payload["steps"][1]["step_id"] = "P-S03"
    assert any("seq is 3, expected 2" in m for m in check(payload, tmp_path))


def test_id_scheme_mismatch_fails(payload, tmp_path):
    payload["steps"][1]["step_id"] = "P-step2"
    assert any("id scheme" in m for m in check(payload, tmp_path))


def test_value_outside_the_allowed_list_fails(payload, tmp_path):
    payload["steps"][0]["step_type"] = "arrow"
    assert any("step_type" in m for m in check(payload, tmp_path))


def test_status_outside_the_allowed_list_fails(payload, tmp_path):
    payload["steps"][0]["pcap_check"]["status"] = "maybe"
    assert any("status" in m for m in check(payload, tmp_path))


def test_found_without_packets_fails(payload, tmp_path):
    payload["steps"][0]["pcap_check"]["packets"] = []
    assert any("no packets" in m for m in check(payload, tmp_path))


def test_found_without_filter_fails(payload, tmp_path):
    payload["steps"][0]["pcap_check"]["filter"] = "   "
    assert any("no filter" in m for m in check(payload, tmp_path))


def test_sha256_mismatch_fails(payload, tmp_path):
    payload["pcap"]["sha256"] = "0" * 64
    assert any("sha256 mismatch" in m for m in check(payload, tmp_path))


def test_size_mismatch_fails(payload, tmp_path):
    payload["pcap"]["size_bytes"] = 1
    assert any("size_bytes" in m for m in check(payload, tmp_path))


def test_missing_capture_file_fails(payload, tmp_path):
    payload["pcap"]["file"] = "pcaps/gone.pcap"
    assert any("no such file" in m for m in check(payload, tmp_path))


def test_citing_packets_with_no_capture_fails(payload, tmp_path):
    payload["pcap"]["file"] = None
    assert any("pcap.file is null" in m for m in check(payload, tmp_path))


def test_packet_beyond_the_capture_fails(payload, tmp_path):
    payload["steps"][0]["pcap_check"]["packets"] = [3, 9999]
    assert any("beyond packet_count" in m for m in check(payload, tmp_path))


def test_zero_packet_number_fails(payload, tmp_path):
    payload["steps"][0]["pcap_check"]["packets"] = [0]
    assert any("1-based" in m for m in check(payload, tmp_path))


def test_reordered_fields_fail(payload, tmp_path):
    step = payload["steps"][0]
    payload["steps"][0] = {"seq": step["seq"], **{k: v for k, v in step.items() if k != "seq"}}
    assert any("field order" in m for m in check(payload, tmp_path))


def test_unreadable_arrow_must_be_flagged(payload, tmp_path):
    payload["steps"][0]["target"] = None
    assert any("needs_review is false" in m for m in check(payload, tmp_path))

    payload["steps"][0]["needs_review"] = True
    assert check(payload, tmp_path) == []


def test_internal_step_may_have_no_protocol(payload, tmp_path):
    assert payload["steps"][1]["protocol"] is None
    assert check(payload, tmp_path) == []


def test_no_steps_fails(payload, tmp_path):
    payload["steps"] = []
    assert any("no steps" in m for m in check(payload, tmp_path))


def test_invalid_json_is_reported(tmp_path):
    path = tmp_path / "steps.json"
    path.write_text("{oops")
    doc, problems = validate_file(path, tmp_path)
    assert doc is None and any("invalid JSON" in p.message for p in problems)


# -- views ----------------------------------------------------------------

def test_markdown_is_marked_generated_and_has_the_fixed_columns(payload, tmp_path):
    doc, _ = validate_payload(payload, "t.json", tmp_path)
    text = render_markdown(doc)
    assert text.startswith(GENERATED_BANNER)
    assert "| " + " | ".join(MD_COLUMNS) + " |" in text
    for step in doc.steps:
        assert step.step_id in text


def test_csv_has_the_same_columns_as_the_markdown(payload, tmp_path):
    doc, _ = validate_payload(payload, "t.json", tmp_path)
    assert csv_rows(doc)[0] == list(MD_COLUMNS)
    assert len(csv_rows(doc)) == 1 + len(doc.steps)
    assert render_csv(doc).startswith(",".join(MD_COLUMNS))


def test_a_pipe_in_the_paper_cannot_break_the_table(payload, tmp_path):
    payload["steps"][0]["verbatim"] = "a | b"
    doc, _ = validate_payload(payload, "t.json", tmp_path)
    row = [line for line in render_markdown(doc).splitlines() if "P-S01" in line][0]
    assert "a \\| b" in row                      # the pipe survives, escaped
    unescaped = row.replace("\\|", "").count("|")  # ... and does not open a cell
    assert unescaped == len(MD_COLUMNS) + 1


def test_schema_covers_every_field_and_closes_the_lists():
    schema = json_schema()
    step = schema["$defs"]["Step"]["properties"]
    assert set(step) == set(steps_file.Step.model_fields)
    assert schema["$defs"]["Step"]["additionalProperties"] is False
    dumped = json.dumps(schema)
    for value in steps_file.STEP_TYPES + steps_file.CHECK_STATUSES:
        assert f'"{value}"' in dumped


def test_the_committed_schema_matches_the_model():
    on_disk = json.loads((REPO_ROOT / "src" / "Dataset" / "schemas_json" /
                          "steps.schema.json").read_text())
    assert on_disk == json_schema(), "run: pangea steps schema > src/Dataset/schemas_json/steps.schema.json"


# -- the real file --------------------------------------------------------

def test_every_steps_file_in_the_repo_validates():
    paths = steps_files()
    assert paths, "no sources/*/steps.json found"
    for path in paths:
        doc, problems = validate_file(path)
        assert problems == [], f"{path}: {[str(p) for p in problems]}"


def test_nrdelegation_matches_the_paper_and_its_markdown_is_current():
    doc, problems = validate_file(REAL)
    assert problems == []
    assert doc.paper.id == "NRDelegationAttack"
    assert [s.seq for s in doc.steps] == list(range(1, 14))
    assert {s.phase for s in doc.steps} == {"Phase I", "Phase II", "Phase III"}
    assert REAL.with_name("steps.md").read_text(encoding="utf-8") == render_markdown(doc)
