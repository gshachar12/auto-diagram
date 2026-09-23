"""
End-to-end demo of the Grounder stage, using MockLLMClient so it runs completely
offline (no API key / network required). Swap in AnthropicLLMClient for real use:

    from pangea_grounder import Grounder
    from pangea_grounder.llm_client import AnthropicLLMClient
    grounder = Grounder(AnthropicLLMClient(model="claude-sonnet-4-6"))

Run:  python -m pangea_grounder.demo
"""

from __future__ import annotations

import json

from .grounder import Grounder
from .llm_client import MockLLMClient

TRAFFIC_DESCRIPTION = """\
An external host scanned our internal web server. The attacker sent TCP SYN
packets to many different ports on the victim without completing the handshake,
consistent with a port scan. The probing happened in a short burst. Separately,
the victim appears to have replied to the attacker with an HTTP 200 OK on port
8080. Overall, the traffic pattern is consistent with reconnaissance activity
that typically precedes an exploitation attempt.
"""

# --- Mock "Reduced PCAP" + "Fingerprint_index" (normally produced by the Preprocessor) ---

REDUCED_PCAP = [
    {"packet_id": 101, "timestamp": 10.001, "protocol": "TCP", "src_ip": "203.0.113.17",
     "dst_ip": "10.0.0.5", "src_port": 51000, "dst_port": 22, "flags": ["SYN"], "length": 60},
    {"packet_id": 102, "timestamp": 10.004, "protocol": "TCP", "src_ip": "203.0.113.17",
     "dst_ip": "10.0.0.5", "src_port": 51001, "dst_port": 80, "flags": ["SYN"], "length": 60},
    {"packet_id": 103, "timestamp": 10.007, "protocol": "TCP", "src_ip": "203.0.113.17",
     "dst_ip": "10.0.0.5", "src_port": 51002, "dst_port": 443, "flags": ["SYN"], "length": 60},
]

FINGERPRINT_INDEX = {
    "TCP|SYN": {
        "protocol": "TCP",
        "raw_packet_ids": [101, 102, 103],
        "aggregate": {
            "count": 850,               # thousands of ports scanned; most folded into this stat
            "bytes": 51000,
            "unique_src": ["203.0.113.17"],
            "unique_dst": ["10.0.0.5"],
        },
    },
    # Note: nothing under "HTTP|8080" -> the HTTP 200 OK Step has no supporting
    # evidence at all, so it should come back "unsupported".
}


def build_mock_llm() -> MockLLMClient:
    """Registers a canned Step Extractor response and one Step-escalation
    response, so the whole pipeline runs deterministically offline.
    """
    llm = MockLLMClient()

    # Step Extractor is "necessarily LLM-based" per spec, so its call always
    # needs a mock response when running offline.
    llm.register(
        "An external host scanned",
        {
            "actors": [
                {"actor_id": "attacker", "role": "attacker",
                 "description_ref": "the external host performing the scan"},
                {"actor_id": "victim", "role": "victim",
                 "description_ref": "the internal web server"},
            ],
            "Steps": [
                {
                    "Step_id": "c1",
                    "text": "The attacker sent TCP SYN packets to many ports on the victim "
                            "without completing the TCP handshake (a half-open port scan).",
                    "actor_refs": ["attacker", "victim"],
                    "expected_indicators": {
                        "protocol": "TCP",
                        "flags": ["SYN"],
                        "direction": "attacker->victim",
                        "cardinality_pattern": "one-to-many",
                        "indicator_description": "TCP SYN packets from attacker to victim across "
                                                  "many destination ports with no completed handshake",
                    },
                },
                {
                    "Step_id": "c2",
                    "text": "The port probing happened in a short burst.",
                    "actor_refs": ["attacker", "victim"],
                    "expected_indicators": {
                        "protocol": "TCP",
                        "flags": ["SYN"],
                        "volume_pattern": "burst",
                        "indicator_description": "many SYN packets from the attacker clustered "
                                                  "tightly in time",
                    },
                },
                {
                    "Step_id": "c3",
                    "text": "The victim replied to the attacker with an HTTP 200 OK response on port 8080.",
                    "actor_refs": ["attacker", "victim"],
                    "expected_indicators": {
                        "protocol": "HTTP",
                        "port": 8080,
                        "direction": "victim->attacker",
                        "indicator_description": "an HTTP response with status 200 from the "
                                                  "victim to the attacker on port 8080",
                    },
                },
                {
                    "Step_id": "c4",
                    "text": "The overall traffic pattern is consistent with reconnaissance "
                            "activity that typically precedes an exploitation attempt.",
                    "actor_refs": ["attacker", "victim"],
                    "expected_indicators": {
                        "indicator_description": "a general characterization of the traffic as "
                                                  "pre-exploitation reconnaissance; not reducible "
                                                  "to a single structured signature",
                    },
                },
            ],
        },
    )

    # c4 has no structured indicators -> Evidence Matcher escalates it to the LLM
    # with only the relevant PCAP slice. Give it a plausible judgment call.
    llm.register(
        '"Step_id": "c4"',
        {
            "status": "uncertain_needs_drilldown",
            "confidence": 0.55,
            "linked_packets": [101, 102, 103],
            "linked_aggregate_refs": ["TCP|SYN"],
            "basis": "The SYN-scan evidence supports reconnaissance broadly, but 'precedes "
                     "exploitation' is a forward-looking interpretive Step the PCAP alone "
                     "cannot confirm or deny.",
        },
    )
    return llm


def main() -> None:
    grounder = Grounder(llm_client=build_mock_llm())
    result = grounder.run(TRAFFIC_DESCRIPTION, REDUCED_PCAP, FINGERPRINT_INDEX)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
