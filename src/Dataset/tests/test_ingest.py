"""
Ingesting the dataset folders.

The registry's value is that it does not improve on its sources. These
tests are mostly about what ingest refuses to fill in: a licence nobody
stated, a direction coverage nobody established, a capture that is not
there, and a packet count that disagrees with the paper.
"""
from __future__ import annotations

import json

import pytest

from Dataset.ingest import ingest_datasets
from Dataset.pcap import PcapService, PcapServiceError
from Dataset.storage.db import Database


def _tshark_available() -> bool:
    try:
        from Dataset.pcap.service import resolve_tshark

        resolve_tshark()
        return True
    except PcapServiceError:
        return False


@pytest.fixture
def datasets(tmp_path):
    """A miniature pcaps/datasets/ tree: one folder with a capture, one without."""
    from scapy.all import IP, TCP, wrpcap

    with_pcap = tmp_path / "WITH-CAPTURE"
    with_pcap.mkdir()
    (with_pcap / "attack_steps.csv").write_text(
        "step_order,attack_step,tools\n"
        "1,Network scan,Nmap\n"
        "2,Brute force,Hydra\n",
        encoding="utf-8",
    )
    (with_pcap / "scenario_steps_extra.csv").write_text(
        "scenario,step,description\nAS1,1,An insider plugs in a device\n", encoding="utf-8"
    )
    wrpcap(str(with_pcap / "sample.pcap"), [IP(dst="10.0.0.1") / TCP(dport=port, flags="S") for port in range(10)])
    (with_pcap / "source.md").write_text(
        "# Example Dataset — steps + sample pcap\n\n"
        "Steps transcribed from Table 2 of https://example.org/paper.pdf\n\n"
        "`sample.pcap` — unmodified, 10 packets.\n",
        encoding="utf-8",
    )

    without = tmp_path / "NO-CAPTURE"
    without.mkdir()
    (without / "attack_steps.csv").write_text("row_order,tactic\n1,Collection\n", encoding="utf-8")
    (without / "source.md").write_text(
        "# Gated Dataset\n\nNo pcap: the download is behind a personal-data form.\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def ingested(db: Database, datasets, tmp_path):
    service = PcapService(allowed_roots=[datasets]) if _tshark_available() else None
    return ingest_datasets(db=db, datasets_dir=datasets, service=service, repo_root=datasets.parent)


def test_both_folders_are_registered(db, ingested):
    assert db.count("sources") == 2
    titles = {row["title"] for row in db.query("SELECT title FROM sources")}
    assert titles == {"Example Dataset — steps + sample pcap", "Gated Dataset"}


def test_steps_are_stored_verbatim_with_their_origin(db, ingested):
    rows = db.query("SELECT * FROM source_steps ORDER BY origin_file, row_number")
    assert len(rows) == 4  # 2 + 1 steps, plus the single row of the gated folder
    first = next(r for r in rows if r["text"] == "Network scan")
    assert first["step_order"] == "1"
    # The whole row survives, not just the column used for the text.
    assert json.loads(first["fields"]) == {"step_order": "1", "attack_step": "Network scan", "tools": "Nmap"}
    assert first["origin_file"].endswith("attack_steps.csv")


def test_a_second_steps_file_is_ingested_too(db, ingested):
    assert any(r["origin_file"].endswith("scenario_steps_extra.csv") for r in db.query("SELECT * FROM source_steps"))


def test_urls_come_from_source_md_and_are_not_invented(db, ingested):
    urls = json.loads(db.one("SELECT urls FROM sources WHERE title LIKE 'Example%'")["urls"])
    assert urls == ["https://example.org/paper.pdf"]
    assert json.loads(db.one("SELECT urls FROM sources WHERE title = 'Gated Dataset'")["urls"]) == []


def test_licence_is_never_guessed(db, ingested):
    assert {row["license"] for row in db.query("SELECT license FROM sources")} == {"UNVERIFIED"}
    check = db.one("SELECT status FROM verification_checks WHERE item LIKE 'licence%'")
    assert check["status"] == "unverified"


def test_direction_coverage_is_left_unknown(db, ingested):
    for row in db.query("SELECT capture_metadata FROM pcaps"):
        assert json.loads(row["capture_metadata"])["both_directions"] is None


def test_a_missing_capture_is_a_failed_check_not_a_missing_row(db, ingested):
    source_id = db.one("SELECT source_id FROM sources WHERE title = 'Gated Dataset'")["source_id"]
    assert db.query("SELECT * FROM pcaps WHERE source_id = ?", (source_id,)) == []
    check = db.one(
        "SELECT status, notes FROM verification_checks WHERE source_id = ? AND item = 'sample capture obtained'",
        (source_id,),
    )
    assert check["status"] == "fail"


def test_the_manual_checks_stay_unverified(db, ingested):
    for item in ("every step located in the capture", "keep / drop decision"):
        rows = db.query("SELECT status FROM verification_checks WHERE item = ?", (item,))
        assert rows and all(row["status"] == "unverified" for row in rows)


def test_re_ingesting_does_not_duplicate(db, datasets, ingested):
    again = ingest_datasets(db=db, datasets_dir=datasets, service=None, repo_root=datasets.parent)
    assert all("skipped" in entry for entry in again["registered"])
    assert db.count("sources") == 2


@pytest.mark.skipif(not _tshark_available(), reason="tshark not available")
def test_captures_are_opened_and_counted(db, ingested):
    row = db.one("SELECT packet_count, sha256, size_bytes FROM pcaps")
    assert row["packet_count"] == 10
    assert len(row["sha256"]) == 64 and row["size_bytes"] > 0
    check = db.one("SELECT status FROM verification_checks WHERE item = 'opened and counted with tshark'")
    assert check["status"] == "pass"


@pytest.mark.skipif(not _tshark_available(), reason="tshark not available")
def test_the_count_is_cross_checked_against_the_source(db, ingested):
    check = db.one("SELECT status, notes FROM verification_checks WHERE item LIKE '%matches the figure%'")
    assert check["status"] == "pass"
    assert "10" in check["notes"]


@pytest.mark.skipif(not _tshark_available(), reason="tshark not available")
def test_a_count_that_disagrees_with_the_source_is_a_failed_check(db, datasets, tmp_path):
    # The point of the cross-check: a capture that is not the one the paper
    # describes must be visible, not quietly accepted.
    folder = datasets / "WITH-CAPTURE"
    (folder / "source.md").write_text(
        "# Example Dataset\n\n`sample.pcap` — unmodified, 999 packets.\n", encoding="utf-8"
    )
    ingest_datasets(
        db=db, datasets_dir=datasets, service=PcapService(allowed_roots=[datasets]), repo_root=datasets.parent
    )
    check = db.one("SELECT status, notes FROM verification_checks WHERE item LIKE '%matches the figure%'")
    assert check["status"] == "fail"
    assert "999" in check["notes"] and "10" in check["notes"]


def test_ingest_without_the_pcap_service_still_registers(db, datasets):
    summary = ingest_datasets(db=db, datasets_dir=datasets, service=None, repo_root=datasets.parent)
    assert len(summary["registered"]) == 2
    row = db.one("SELECT packet_count, sha256 FROM pcaps")
    # No count without tshark -- and the row says so rather than guessing.
    assert row["packet_count"] is None
    assert len(row["sha256"]) == 64
    check = db.one("SELECT status FROM verification_checks WHERE item = 'opened and counted with tshark'")
    assert check["status"] == "fail"
