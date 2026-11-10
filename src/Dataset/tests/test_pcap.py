"""
The PCAP service.

Most of this file is about the service refusing things. The display filter
it runs is, in the experiment, written by a model: it is untrusted input
that reaches a subprocess, so the refusals are the feature and the happy
path is the easy part.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from Dataset.manifest import REPO_ROOT
from Dataset.pcap import (
    FilterError,
    PathNotAllowed,
    PcapService,
    PcapServiceError,
    PcapTimeout,
)
from Dataset.storage.db import Database

PORTSCAN = "pcaps/PortScanning/portscan.pcap"
HTTP = "pcaps/http.cap"


def _tshark_available() -> bool:
    try:
        from Dataset.pcap.service import resolve_tshark

        resolve_tshark()
        return True
    except PcapServiceError:
        return False


pytestmark = pytest.mark.skipif(not _tshark_available(), reason="tshark not available; run through ./pangea")


@pytest.fixture
def service() -> PcapService:
    return PcapService(allowed_roots=[REPO_ROOT / "pcaps"])


@pytest.fixture
def cached_service(db: Database) -> PcapService:
    return PcapService(allowed_roots=[REPO_ROOT / "pcaps"], db=db)


# -- reading a capture ----------------------------------------------------

def test_summary_counts_the_packets_in_a_known_capture(service):
    summary = service.summary(PORTSCAN)
    assert summary.packet_count == 29
    assert summary.size_bytes == 2228
    assert summary.duration_seconds and summary.duration_seconds > 0
    assert summary.first_packet_epoch < summary.last_packet_epoch
    assert len(summary.sha256) == 64


def test_summary_reports_the_protocols_present(service):
    protocols = {row["protocol"] for row in service.summary(PORTSCAN).protocol_hierarchy}
    assert {"eth", "ip", "tcp"} <= protocols


def test_query_counts_matches_and_returns_the_first_few(service):
    result = service.query(PORTSCAN, "tcp.flags.syn == 1 && tcp.flags.ack == 0", limit=3)
    assert result.match_count == 29  # every packet in this capture is a SYN
    assert len(result.packets) == 3
    assert result.truncated is False
    assert result.packets[0]["number"] == 1


def test_query_returns_packets_in_file_order(service):
    numbers = [p["number"] for p in service.query(PORTSCAN, "tcp", limit=10).packets]
    assert numbers == sorted(numbers)


def test_a_filter_matching_nothing_is_an_answer_not_an_error(service):
    result = service.query(PORTSCAN, "dns", limit=5)
    assert result.match_count == 0 and result.packets == []


def test_query_works_on_a_different_capture_and_protocol(service):
    result = service.query(HTTP, 'http.request.method == "GET"', limit=5)
    assert result.match_count > 0
    assert any("GET" in p["info"] for p in result.packets)


def test_limit_is_capped_by_the_service_maximum():
    service = PcapService(allowed_roots=[REPO_ROOT / "pcaps"], max_packets_returned=2)
    result = service.query(PORTSCAN, "tcp", limit=100)
    assert len(result.packets) == 2
    assert result.match_count == 29  # the count is not capped, only the sample


# -- the filter is untrusted input ---------------------------------------

@pytest.mark.parametrize(
    "hostile",
    [
        "tcp; rm -rf /",
        "tcp && $(id)",
        "tcp `id`",
        "tcp | cat /etc/passwd",
        "tcp\nrm -rf /",
        "tcp & touch /tmp/pangea_pwned",
        "'; DROP TABLE calls; --",
        "tcp.port == 80 || 1=1; shutdown -h now",
    ],
)
def test_shell_metacharacters_cannot_do_anything(service, hostile):
    # tshark is executed with an argument list, so there is no shell to
    # break out of: these are simply invalid display filters.
    with pytest.raises(FilterError):
        service.query(PORTSCAN, hostile)


def test_an_injection_attempt_leaves_no_trace(service, tmp_path):
    sentinel = tmp_path / "pwned"
    with pytest.raises(FilterError):
        service.query(PORTSCAN, f"tcp; touch {sentinel}")
    assert not sentinel.exists()


@pytest.mark.parametrize("flag", ["-r /etc/passwd", "--version", "-G", "  -Y tcp"])
def test_a_filter_shaped_like_an_option_is_refused(service, flag):
    # An argument beginning with '-' would be read as a flag by any
    # argv-based caller, so it is rejected before tshark ever sees it.
    with pytest.raises(FilterError, match="may not start with"):
        service.query(PORTSCAN, flag)


@pytest.mark.parametrize("bad", ["", "   ", "tcp.port ==", "nosuchprotocol.field == 1", "((tcp"])
def test_malformed_filters_are_refused(service, bad):
    with pytest.raises(FilterError):
        service.query(PORTSCAN, bad)


def test_a_filter_with_a_nul_byte_is_refused(service):
    with pytest.raises(FilterError, match="NUL"):
        service.query(PORTSCAN, "tcp\x00")


def test_an_absurdly_long_filter_is_refused(service):
    with pytest.raises(FilterError, match="longer than"):
        service.query(PORTSCAN, "tcp || " * 5000)


# -- the capture path is untrusted too -----------------------------------

def test_a_capture_outside_the_roots_is_refused(service):
    with pytest.raises(PathNotAllowed):
        service.summary("/etc/passwd")


def test_path_traversal_out_of_the_roots_is_refused(service):
    with pytest.raises(PathNotAllowed):
        service.summary("pcaps/../README.md")


def test_a_symlink_pointing_out_of_the_roots_is_refused(service, tmp_path):
    # The check is on where the path resolves, not on where it sits: a link
    # inside the jail that leaves it is still leaving it.
    link = REPO_ROOT / "pcaps" / "_test_escape.pcap"
    try:
        link.symlink_to("/etc/passwd")
        with pytest.raises(PathNotAllowed):
            service.summary(link)
    finally:
        link.unlink(missing_ok=True)


def test_a_directory_is_not_a_capture(service):
    with pytest.raises(PathNotAllowed, match="regular file"):
        service.summary("pcaps")


def test_a_missing_capture_is_refused(service):
    with pytest.raises(PathNotAllowed):
        service.summary("pcaps/does_not_exist.pcap")


# -- limits ---------------------------------------------------------------

def test_a_timeout_is_enforced():
    service = PcapService(allowed_roots=[REPO_ROOT / "pcaps"], timeout_seconds=0.001)
    with pytest.raises(PcapTimeout):
        service.query(PORTSCAN, "tcp")


def test_output_is_capped_and_says_so():
    service = PcapService(allowed_roots=[REPO_ROOT / "pcaps"], max_output_bytes=120)
    result = service.query(PORTSCAN, "tcp", limit=50)
    assert result.truncated is True
    assert result.match_count < 29  # the scan stopped early, and admits it


# -- caching --------------------------------------------------------------

def test_results_are_cached_by_content(cached_service):
    first = cached_service.query(PORTSCAN, "tcp", limit=5)
    second = cached_service.query(PORTSCAN, "tcp", limit=5)
    assert first.cached is False and second.cached is True
    assert second.match_count == first.match_count
    assert second.packets == first.packets


def test_a_different_filter_or_limit_is_a_different_cache_entry(cached_service, db):
    cached_service.query(PORTSCAN, "tcp", limit=5)
    cached_service.query(PORTSCAN, "tcp", limit=6)
    cached_service.query(PORTSCAN, "ip", limit=5)
    assert db.count("pcap_query_cache") == 3


def test_the_cache_is_derived_data_and_can_be_cleared(cached_service, db):
    cached_service.query(PORTSCAN, "tcp", limit=5)
    db.clear_derived("pcap_query_cache")
    assert db.count("pcap_query_cache") == 0
    assert cached_service.query(PORTSCAN, "tcp", limit=5).cached is False
