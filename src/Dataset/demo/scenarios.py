"""
The demo dataset's content.

  Everything here is SYNTHETIC and labelled as such. The claims are written
  for this file; they are not quoted from any paper, and no paper, figure
  number, URL or author is attributed to them. The real claims come from the
  extraction agent reading real sources (milestone B2), under review.

  The captures referenced ARE real files already in the repo under pcaps/,
  because the demo is more useful when the hashes, sizes and paths are the
  ones the PCAP service will later meet. Their packet counts are left
  unverified until the PCAP service exists to count them.
"""
from __future__ import annotations

from typing import Any

#: scenario key -> everything needed to build its source, capture and claims.
SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "key": "portscan",
        "title": "DEMO scenario: TCP port scan (synthetic claims)",
        "pcap_path": "pcaps/PortScanning/portscan.pcap",
        "capture_metadata": {
            "vantage_point": "DEMO: unverified; recorded at the scanned host",
            "both_directions": False,
            "known_gaps": ["DEMO data: direction coverage not verified"],
            "notes": "Synthetic demo entry. Capture metadata must be confirmed in M0.",
        },
        "claims": [
            {
                "step": "A single source sends TCP SYN packets to several ports of one host, and closed ports answer with RST.",
                "location": "DEMO step 1",
                "atomic": "A single source sends TCP SYN packets to at least N distinct ports of one host.",
                "level": 1,
                "kind": "quantitative",
                "filter": "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "predicate": {"protocol": "tcp", "flags": ["syn"], "direction": "to_host", "distinct": "tcp.dstport"},
                "parameters": {"threshold": "thresholds.quantity.many"},
            },
            {
                "step": "A single source sends TCP SYN packets to several ports of one host, and closed ports answer with RST.",
                "location": "DEMO step 1",
                "atomic": "Closed ports answer with a TCP RST.",
                "level": 2,
                "kind": "protocol",
                "filter": "tcp.flags.reset == 1",
                "predicate": {"protocol": "tcp", "flags": ["rst"], "direction": "from_host"},
                "parameters": {},
            },
            {
                "step": "A single source sends TCP SYN packets to several ports of one host, and closed ports answer with RST.",
                "location": "DEMO step 1",
                "atomic": "Each RST appears after the SYN it answers.",
                "level": 3,
                "kind": "sequence",
                "filter": "tcp.flags.reset == 1",
                "predicate": {"before": {"flags": ["syn"]}, "after": {"flags": ["rst"]}, "match_on": "tcp.port"},
                "parameters": {"delta": "thresholds.delta_seconds"},
            },
            {
                "step": "A single source sends TCP SYN packets to several ports of one host, and closed ports answer with RST.",
                "location": "DEMO step 1",
                "atomic": "The sender is mapping which services the host exposes.",
                "level": 4,
                "kind": "semantic",
                "reason_code": "INTENT",
            },
        ],
    },
    {
        "key": "http",
        "title": "DEMO scenario: plain HTTP session (synthetic claims)",
        "pcap_path": "pcaps/http.cap",
        "capture_metadata": {
            "vantage_point": "DEMO: unverified; recorded on the client segment",
            "both_directions": True,
            "known_gaps": [],
            "notes": "Benign traffic. Present so the panel can be checked for finding attacks that are not there.",
        },
        "claims": [
            {
                "step": "A client issues an HTTP GET request and the server responds.",
                "location": "DEMO step 1",
                "atomic": "A client sends an HTTP GET request.",
                "level": 2,
                "kind": "protocol",
                "filter": 'http.request.method == "GET"',
                "predicate": {"protocol": "http", "field": "http.request.method", "value": "GET"},
                "parameters": {},
            },
            {
                "step": "A client issues an HTTP GET request and the server responds.",
                "location": "DEMO step 1",
                "atomic": "The server does not answer the request within the absence window.",
                "level": 3,
                "kind": "absence",
                "filter": "http.response",
                "predicate": {"protocol": "http", "expect_absent": True, "paired_with": "http.request"},
                "parameters": {"tau": "thresholds.tau_seconds"},
            },
        ],
    },
    {
        "key": "dns_delegation",
        "title": "DEMO scenario: DNS delegation capture (synthetic claims)",
        "pcap_path": "pcaps/NRDelegationAttack/Simulator_Figure1/NRDelegationAttack_figure1.pcap",
        "capture_metadata": {
            "vantage_point": "DEMO: unverified; recorded at the resolver",
            "both_directions": True,
            "known_gaps": ["DEMO data: capture window not verified against any figure"],
            "notes": (
                "References a capture already in this repo. The claims here are synthetic "
                "placeholders and are NOT taken from the accompanying paper; the real "
                "extraction happens under review in B2."
            ),
        },
        "claims": [
            {
                "step": "A resolver sends DNS queries and receives referrals.",
                "location": "DEMO step 1",
                "atomic": "The resolver sends at least one DNS query over UDP port 53.",
                "level": 1,
                "kind": "existential",
                "filter": "dns && udp.port == 53",
                "predicate": {"protocol": "dns", "transport": "udp", "port": 53, "direction": "from_resolver"},
                "parameters": {},
            },
            {
                "step": "A resolver sends DNS queries and receives referrals.",
                "location": "DEMO step 1",
                "atomic": "The exchange succeeded in exhausting the resolver's budget.",
                "level": 5,
                "kind": "semantic",
                "reason_code": "OUTCOME",
            },
        ],
    },
)

#: One-change mutations applied to a source claim's structured predicate.
#: The real generator (B3) derives these from the predicate's own fields and
#: validates each one against the capture; this list only feeds the demo.
DEMO_MUTATIONS: tuple[dict[str, Any], ...] = (
    {
        "mutation_type": "port",
        "field": "port",
        "new_value": 9999,
        "filter_from": "dns && udp.port == 53",
        "filter_to": "dns && udp.port == 9999",
        "text_from": "UDP port 53",
        "text_to": "UDP port 9999",
    },
    {
        "mutation_type": "protocol",
        "field": "protocol",
        "new_value": "icmp",
        "filter_from": "tcp.flags.reset == 1",
        "filter_to": "icmp.type == 3",
        "text_from": "a TCP RST",
        "text_to": "an ICMP destination-unreachable message",
    },
    {
        "mutation_type": "order",
        "field": "order",
        "new_value": "reversed",
        "filter_from": "tcp.flags.reset == 1",
        "filter_to": "tcp.flags.reset == 1",
        "text_from": "after the SYN it answers",
        "text_to": "before the SYN it answers",
    },
)
