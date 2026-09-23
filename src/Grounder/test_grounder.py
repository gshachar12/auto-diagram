"""
Unit tests covering the Grounder's branch logic against the rules stated in
PANGEA_SPEC (Actor Resolution and Step Grounding). Run with:

    python -m pytest pangea_grounder/test_grounder.py -q
"""

from __future__ import annotations

from .evidence_matcher import EvidenceMatcher
from .fingerprint_utils import build_fingerprint_key
from .llm_client import MockLLMClient
from .models import Actor, Step, ExpectedIndicators, GroundingStatus


def _pcap():
    return [
        {"packet_id": 1, "timestamp": 0.0, "protocol": "TCP", "src_ip": "203.0.113.17",
         "dst_ip": "10.0.0.5", "src_port": 40001, "dst_port": 22, "flags": ["SYN"], "length": 60},
        {"packet_id": 2, "timestamp": 0.01, "protocol": "TCP", "src_ip": "203.0.113.17",
         "dst_ip": "10.0.0.5", "src_port": 40002, "dst_port": 80, "flags": ["SYN"], "length": 60},
    ]


def _index():
    return {
        "TCP|SYN": {
            "protocol": "TCP",
            "raw_packet_ids": [1, 2],
            "aggregate": {"count": 2, "bytes": 120, "unique_src": ["203.0.113.17"], "unique_dst": ["10.0.0.5"]},
        }
    }


def test_fingerprint_key_tcp():
    assert build_fingerprint_key("TCP", flags=["SYN"]) == "TCP|SYN"


def test_fingerprint_key_none_without_protocol():
    assert build_fingerprint_key(None) is None


def test_actor_resolution_single_unambiguous_match():
    matcher = EvidenceMatcher(_pcap(), _index(), MockLLMClient())
    attacker = Actor(actor_id="attacker", role="attacker", description_ref="external host")
    victim = Actor(actor_id="victim", role="victim", description_ref="internal server")
    matcher.resolve_actors([attacker, victim])

    assert attacker.resolved_endpoints == ["203.0.113.17"]
    assert victim.resolved_endpoints == ["10.0.0.5"]
    assert attacker.is_resolved and victim.is_resolved


def test_actor_resolution_no_match_stays_unresolved():
    matcher = EvidenceMatcher([], {}, MockLLMClient())
    unknown = Actor(actor_id="ghost", role="attacker", description_ref="nobody")
    matcher.resolve_actors([unknown])
    assert not unknown.is_resolved


def test_Step_grounded_from_single_clean_match():
    matcher = EvidenceMatcher(_pcap(), _index(), MockLLMClient())
    attacker = Actor(actor_id="attacker", role="attacker", description_ref="x", resolved_endpoints=["203.0.113.17"])
    victim = Actor(actor_id="victim", role="victim", description_ref="y", resolved_endpoints=["10.0.0.5"])
    Step = Step(
        Step_id="c1",
        text="SYN scan",
        expected_indicators=ExpectedIndicators(protocol="TCP", flags=["SYN"], direction="attacker->victim"),
        actor_refs=["attacker", "victim"],
    )
    matcher.ground_Steps([Step], [attacker, victim])
    assert Step.grounding.status == GroundingStatus.GROUNDED
    assert set(Step.grounding.linked_packets) == {1, 2}


def test_Step_unsupported_when_no_match():
    matcher = EvidenceMatcher(_pcap(), _index(), MockLLMClient())
    attacker = Actor(actor_id="attacker", role="attacker", description_ref="x", resolved_endpoints=["203.0.113.17"])
    Step = Step(
        Step_id="c2",
        text="HTTP response that never happened",
        expected_indicators=ExpectedIndicators(protocol="HTTP", port=8080),
        actor_refs=["attacker"],
    )
    matcher.ground_Steps([Step], [attacker])
    assert Step.grounding.status == GroundingStatus.UNSUPPORTED


def test_Step_uncertain_when_actor_unresolved():
    matcher = EvidenceMatcher(_pcap(), _index(), MockLLMClient())
    ghost = Actor(actor_id="ghost", role="attacker", description_ref="nobody")  # unresolved
    Step = Step(
        Step_id="c3",
        text="depends on unresolved actor",
        expected_indicators=ExpectedIndicators(protocol="TCP", flags=["SYN"]),
        actor_refs=["ghost"],
    )
    matcher.ground_Steps([Step], [ghost])
    assert Step.grounding.status == GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN


def test_Step_escalates_when_no_structured_indicators():
    llm = MockLLMClient()
    llm.register('"Step_id": "c4"', {
        "status": "uncertain_needs_drilldown",
        "confidence": 0.4,
        "linked_packets": [],
        "linked_aggregate_refs": [],
    })
    matcher = EvidenceMatcher(_pcap(), _index(), llm)
    Step = Step(
        Step_id="c4",
        text="free text only",
        expected_indicators=ExpectedIndicators(indicator_description="vague reconnaissance vibe"),
        actor_refs=[],
    )
    matcher.ground_Steps([Step], [])
    assert Step.grounding.status == GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN
    assert Step.grounding.confidence == 0.4


def test_Step_aggregate_only_match_is_uncertain():
    index = {
        "TCP|SYN": {
            "protocol": "TCP",
            "raw_packet_ids": [],  # everything was folded -> aggregate only
            "aggregate": {"count": 500, "bytes": 30000, "unique_src": ["203.0.113.17"], "unique_dst": ["10.0.0.5"]},
        }
    }
    matcher = EvidenceMatcher([], index, MockLLMClient())
    Step = Step(
        Step_id="c5",
        text="SYN scan, only aggregate evidence retained",
        expected_indicators=ExpectedIndicators(protocol="TCP", flags=["SYN"]),
        actor_refs=[],
    )
    matcher.ground_Steps([Step], [])
    assert Step.grounding.status == GroundingStatus.UNCERTAIN_NEEDS_DRILLDOWN
    assert Step.grounding.linked_aggregate_refs == ["TCP|SYN"]
