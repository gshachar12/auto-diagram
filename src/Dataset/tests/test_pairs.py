"""
The pair builder.

Each pair type carries an expectation, and an expectation is only worth
something if it was checked. These tests are mostly about the checking: a
mutation that stays true, a swap that turns out supported, and a claim whose
own condition finds nothing all have to be discarded *and logged*, because
each one is a finding about the dataset rather than an accident to hide.
"""
from __future__ import annotations

import json

import pytest

from Dataset.ids import content_id
from Dataset.pairs import PairBuilder, discard_log, mutations_for
from Dataset.pcap import PcapService, PcapServiceError
from Dataset.schemas import (
    CaptureMetadata,
    Claim,
    ClaimKind,
    Condition,
    MutationType,
    Pcap,
    ReasonCode,
    Source,
)
from Dataset.storage.repository import Repository


def _tshark_available() -> bool:
    try:
        from Dataset.pcap.service import resolve_tshark

        resolve_tshark()
        return True
    except PcapServiceError:
        return False


pytestmark = pytest.mark.skipif(not _tshark_available(), reason="tshark not available")


# -- the mutation generator ------------------------------------------------

def _condition(display_filter: str, kind: str = "protocol") -> Condition:
    return Condition(kind=ClaimKind(kind), display_filter=display_filter, predicate={}, parameters={})


def test_a_port_claim_mutates_its_port():
    mutations = mutations_for(_condition("tcp.port == 22"), "SSH traffic on port 22")
    assert mutations
    first = mutations[0]
    assert first.mutation_type is MutationType.PORT
    assert "tcp.port == 22" not in first.display_filter
    assert first.display_filter.startswith("tcp.port ==")


def test_a_flag_claim_mutates_one_flag_only():
    mutations = mutations_for(_condition("tcp.flags.syn == 1 && tcp.flags.ack == 0"), "SYN packets")
    assert mutations
    mutated = mutations[0].display_filter
    # Exactly one detail changed: the ack half is untouched.
    assert "tcp.flags.fin == 1" in mutated
    assert "tcp.flags.ack == 0" in mutated


def test_a_bare_protocol_claim_mutates_its_protocol():
    assert mutations_for(_condition("dns"), "a DNS query")[0].display_filter == "arp"


def test_a_direction_claim_exchanges_source_and_destination():
    mutations = [m for m in mutations_for(_condition("ip.src == 10.0.0.1 && ip.dst == 10.0.0.2"), "A to B")
                 if m.mutation_type is MutationType.DIRECTION]
    assert mutations
    assert mutations[0].display_filter == "ip.dst == 10.0.0.1 && ip.src == 10.0.0.2"


def test_a_condition_with_nothing_to_change_yields_no_mutations():
    assert mutations_for(_condition("frame.len > 0"), "a packet exists") == []


# -- fixtures --------------------------------------------------------------

@pytest.fixture
def world(db, tmp_path):
    """
    Two scenarios with genuinely different traffic:

      A: TCP SYNs to port 22        B: DNS over UDP 53

    so a claim about one finds nothing in the other -- which is what makes a
    swap a control rather than a coincidence.
    """
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, wrpcap

    repo = Repository(db)
    sources = {}
    for key, packets in {
        "A": [IP(dst="10.0.0.1") / TCP(dport=22, flags="S") for _ in range(12)],
        "B": [IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.org")) for _ in range(8)],
    }.items():
        source_id = content_id("src", [key])
        repo.add_source(Source(source_id=source_id, title=f"Scenario {key}"))
        path = tmp_path / f"{key}.pcap"
        wrpcap(str(path), packets)
        repo.add_pcap(
            Pcap(
                pcap_id=f"pcap_{key}", source_id=source_id, path=str(path), sha256="0" * 64,
                size_bytes=path.stat().st_size, capture_metadata=CaptureMetadata(vantage_point="test"),
            )
        )
        sources[key] = source_id
    return sources, tmp_path


def _claim(db, source_id, *, text, level=2, display_filter=None, reason=None, claim_id=None):
    repo = Repository(db)
    claim = Claim(
        claim_id=claim_id or content_id("clm", [source_id, text]),
        source_id=source_id, source_location="steps.csv#1", source_step_text="a step",
        atomic_text=text, level=level, kind=ClaimKind.PROTOCOL,
        reason_code=ReasonCode(reason) if reason else None,
        condition=_condition(display_filter) if display_filter else None,
    )
    repo.add_claim(claim)
    return claim.claim_id


@pytest.fixture
def builder(db, world):
    _, tmp_path = world
    return PairBuilder(db=db, service=PcapService(allowed_roots=[tmp_path]), repo_root=tmp_path.parent)


# -- source pairs ----------------------------------------------------------

def test_a_holding_condition_becomes_a_source_pair(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    builder.build()
    pair = db.one("SELECT * FROM pairs WHERE pair_type = 'source'")
    assert pair["expected"] == "SUPPORTED"
    assert pair["expected_basis"] == "author"   # the author's claim, not a control
    assert "12 packets match" in pair["notes"]


def test_a_condition_finding_nothing_is_discarded_and_logged(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="FTP traffic", display_filter="tcp.port == 21")
    builder.build()
    assert db.query("SELECT * FROM pairs WHERE pair_type = 'source'") == []
    reasons = [d["reason"] for d in discard_log(db)]
    assert any("finds nothing on the claim's own capture" in r for r in reasons)


def test_an_abstention_claim_gets_a_source_pair_and_no_mutation(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="the attacker intended to map services", level=4, reason="INTENT")
    builder.build()
    pairs = {p["pair_type"]: p for p in db.query("SELECT * FROM pairs")}
    assert pairs["source"]["expected"] == "NOT_VERIFIABLE"
    assert pairs["source"]["expected_basis"] == "construction"
    assert "mutation" not in pairs and "swap" not in pairs


# -- mutations -------------------------------------------------------------

def test_a_validated_mutation_is_kept_and_expects_refuted(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    builder.build()
    pair = db.one("SELECT * FROM pairs WHERE pair_type = 'mutation'")
    assert pair["expected"] == "REFUTED"
    assert pair["expected_basis"] == "construction"
    assert "0 packets match" in pair["notes"]

    mutated = db.one("SELECT * FROM claims WHERE claim_id = ?", (pair["claim_id"],))
    assert mutated["mutation_of"] is not None
    assert mutated["mutation_type"] == "port"
    # The mutated condition really does find nothing.
    assert json.loads(mutated["condition"])["display_filter"] != "tcp.port == 22"


def test_a_mutation_that_stays_true_is_discarded_and_logged(db, world, builder):
    sources, _ = world
    # "any TCP" mutates to "any ICMP" cleanly, but a claim whose filter still
    # matches after the change must not become a REFUTED item. Port 22 and
    # port 9 both appear here, so the port mutation stays true.
    from scapy.all import IP, TCP, wrpcap

    _, tmp_path = world
    packets = [IP(dst="10.0.0.1") / TCP(dport=22, flags="S") for _ in range(5)]
    packets += [IP(dst="10.0.0.1") / TCP(dport=9, flags="S") for _ in range(5)]
    wrpcap(str(tmp_path / "A.pcap"), packets)

    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    builder.build()

    entries = [d for d in discard_log(db, kind="mutation")]
    assert entries, "a mutation that still matches must be logged"
    assert "still matches" in entries[0]["reason"]
    details = json.loads(entries[0]["details"])
    assert details["matches"] > 0


# -- swaps -----------------------------------------------------------------

def test_a_validated_swap_is_kept_with_no_expected_verdict(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    builder.build()
    pair = db.one("SELECT * FROM pairs WHERE pair_type = 'swap'")
    assert pair["pcap_id"] == "pcap_B"
    # Scored as "not SUPPORTED": REFUTED would assume a closed world on a
    # capture the claim never came from.
    assert pair["expected"] is None
    assert pair["expected_basis"] == "construction"


def test_a_swap_supported_on_the_other_capture_is_discarded(db, world, builder):
    sources, _ = world
    # "ip" matches in both scenarios, so swapping proves nothing.
    _claim(db, sources["A"], text="IP traffic exists", display_filter="ip")
    builder.build()
    assert db.query("SELECT * FROM pairs WHERE pair_type = 'swap'") == []
    reasons = [d["reason"] for d in discard_log(db, kind="swap")]
    assert any("also supported on the other capture" in r for r in reasons)


# -- no_pcap and exclusions ------------------------------------------------

def test_every_claim_gets_a_leakage_probe(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    _claim(db, sources["A"], text="an intent claim", level=5, reason="OUTCOME")
    builder.build()
    probes = db.query("SELECT * FROM pairs WHERE pair_type = 'no_pcap'")
    assert len(probes) == 2
    assert all(p["pcap_id"] is None and p["expected"] == "NOT_VERIFIABLE" for p in probes)


def test_a_rejected_claim_never_becomes_a_pair(db, world, builder):
    from Dataset.review import apply_action

    sources, _ = world
    claim_id = _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    apply_action(db, claim_id=claim_id, action="reject", notes="not usable")
    builder.build()
    assert db.query("SELECT * FROM pairs") == []


def test_a_superseded_claim_is_replaced_not_duplicated(db, world, builder):
    from Dataset.review import apply_action

    sources, _ = world
    claim_id = _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    result = apply_action(
        db, claim_id=claim_id, action="edit",
        edits={"atomic_text": "SSH traffic, reworded", "condition": {"display_filter": "tcp.port == 22"}},
    )
    builder.build()
    claim_ids = {p["claim_id"] for p in db.query("SELECT claim_id FROM pairs WHERE pair_type = 'source'")}
    assert claim_ids == {result["produced"][0]}


def test_a_capture_too_large_to_validate_is_skipped_and_logged(db, world, tmp_path):
    sources, world_path = world
    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    builder = PairBuilder(
        db=db, service=PcapService(allowed_roots=[world_path]), repo_root=world_path.parent,
        max_capture_bytes=1,  # everything is "too large"
    )
    builder.build()
    assert db.query("SELECT * FROM pairs WHERE pair_type = 'source'") == []
    assert any("too large to validate" in d["reason"] for d in discard_log(db))
    assert builder.stats.skipped_unvalidatable > 0


def test_building_twice_does_not_duplicate(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    builder.build()
    first = db.count("pairs")
    PairBuilder(db=db, service=builder.service, repo_root=builder.root).build()
    assert db.count("pairs") == first


def test_the_stats_add_up(db, world, builder):
    sources, _ = world
    _claim(db, sources["A"], text="SSH traffic on port 22", display_filter="tcp.port == 22")
    summary = builder.build()
    stats = summary["stats"]
    assert stats["source"] == 1 and stats["mutation"] == 1 and stats["swap"] == 1 and stats["no_pcap"] == 1
    assert db.count("pairs") == 4
