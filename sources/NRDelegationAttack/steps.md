<!-- GENERATED FROM steps.json BY `./pangea steps render` - DO NOT EDIT BY HAND -->

# NRDelegationAttack: Complexity DDoS attack on DNS Recursive Resolvers

Yehuda Afek, Anat Bremler-Barr, Shani Stajnrod · 32nd USENIX Security Symposium (USENIX Security '23) · 2023

https://www.usenix.org/conference/usenixsecurity23/presentation/afek

## Capture

`pcaps/NRDelegationAttack/Simulator_Figure1/NRDelegationAttack_figure1.pcap`

- sha256 `7d582feed2b4e125b8c880f4f087676fbf8b8ba8270b376a750081adf7514566`
- 20882 bytes, 156 packets
- origin: None
- matches: Figure 1

Partial. The capture is from the authors' Inner Simulator (Section 5.1), not from the Figure 1 walk-through: the names are attack0.home.lan and nsNN.fakeNN.fake0, not xyz.referral.com and fooN.delegation.com. The capture starts after the referral response has already been obtained, so arrows 2 and 3 - the query to the referral zone and the LRR itself - are not in it; no response here carries more than one authority record. What it does show, end to end, is the loop the paper is about: NS-name resolution in batches of five, delegation to a non-responsive address, 28 restarts, and SERVFAIL to the client. packet_count 156 was read with tshark, not taken from the folder's README.

## Steps

13 steps — 6 found, 7 not_found. 2 flagged for review.

| ID | Phase | Location | Verbatim | Normalized | Type | PCAP check |
|---|---|---|---|---|---|---|
| NRDelegationAttack-S01 | Phase I | Figure 1, arrow 1; Section 4.1, Phase I item 1 | Attacker’s client queries the victim resolver about xyz.referral.com | Attacker Client -> Recursive Resolver: 'A' query xyz.referral.com [DNS; qtype=A, qname=xyz.referral.com] | message | found: 3 |
| NRDelegationAttack-S02 ⚠ | Phase I | Figure 1, arrow 2; Section 4.1, Phase I item 2 | Victim resolver queries referral.com | Recursive Resolver -> .referral.com name servers: 'A' query xyz.referral.com [DNS; qtype=A] | message | not_found |
| NRDelegationAttack-S03 | Phase I | Figure 1, arrow 3; Section 4.1, Phase I item 3 | Authoritative referral.com responds with a large referral response (LRR) | .referral.com name servers -> Recursive Resolver: Referral Response carrying n NS records and no glue [DNS; authority=n NS, additional=0] | message | not_found |
| NRDelegationAttack-S04 | Phase II | Figure 1, box 4; Section 4.1, Phase II item 1 | The resolver looks up each of the n names to see if any one of them already has a resolution it can use. This is a total of 2n lookups. This step is the core source of the high complexity, especially since it will be repeated many times, as explained in the next phase | Recursive Resolver -> Recursive Resolver: process the referral response and look up each of the n NS names in cache and ADB, 2n lookups [none; internal] | internal (compound) | not_found |
| NRDelegationAttack-S05 | Phase II | Figure 1, box 5; Section 4.1, Phase II items 2 and 3 | n > referral-limit, start only referral-limit* new resolution processes and Turn on “No_Fetch” flag | Recursive Resolver -> Recursive Resolver: start referral-limit new resolution processes and set the No_Fetch flag [none; internal, referral-limit=5 in BIND9] | internal (compound) | not_found |
| NRDelegationAttack-S06 | Phase II | Figure 1, arrow 6; Section 4.1, Phase II item 4 | The resolver issues the query for these referral-limit NS names | Recursive Resolver -> .delegation.com name servers: 'A' query for the referral-limit NS names [DNS; qtype=A, 5 in parallel] | message | found: 6, 8, 14, 20, 24, 82, … (23 total) |
| NRDelegationAttack-S07 | Phase III | Figure 1, arrow 7; Section 4.1, Phase III item 1 | Each such name leads the resolver to an authoritative, which responds with a server IP address that is non-responsive to DNS queries and issues the delegation response | .delegation.com name servers -> Recursive Resolver: 'A' response delegating to the address of a server that does not answer DNS [DNS; answer A = non-responsive host] | message (compound) | found: 9, 11, 15, 21, 26, 84, … (23 total) |
| NRDelegationAttack-S08 | Phase III | Figure 1, box 8; Section 4.1, Phase III item 2 | Upon receiving a delegation response, the resolver triggers a restart event and restarts the resolution for the LRR | Recursive Resolver -> Recursive Resolver: trigger a restart event and restart the LRR resolution [none; internal] | internal (compound) | not_found |
| NRDelegationAttack-S09 | Phase III | Figure 1, box 9; Section 4.1, Phase III item 3 | The victim resolver clears the “No_Fetch” flag | Recursive Resolver -> Recursive Resolver: clear the No_Fetch flag [none; internal] | internal | not_found |
| NRDelegationAttack-S10 | Phase III | Figure 1, arrow 10; Section 4.1, Phase III item 4(a) | Restarts the RR-list processing | Recursive Resolver -> Recursive Resolver: restart processing of the referral record list [none; internal] | internal | not_found |
| NRDelegationAttack-S11 | Phase III | Figure 1, arrow 11; Section 4.1, Phase III item 4(b) | 'A' query xyz.referral.com | Recursive Resolver -> Non-Responsive to DNS queries: 'A' query xyz.referral.com [DNS; qtype=A, 5 in parallel] | message | found: 4, 28, 30, 32, 34, 36, … (28 total) |
| NRDelegationAttack-S12 ⚠ | Phase III | Figure 1, arrow 12; Section 4.1, Phase III item 4(b) | No Response | Non-Responsive to DNS queries -> Recursive Resolver: nothing is returned [none; absence of a reply] | message | found: 5, 29, 31, 33, 35, 37, … (28 total) |
| NRDelegationAttack-S13 | Phase III | Figure 1, arrow 13; Section 4.1, Phase III item 6 | The victim loops through Phases II and III until a timeout or restart limit is reached and a ’FAIL’ response is returned to the client | Recursive Resolver -> Attacker Client: 'FAIL' response for xyz.referral.com after the restart limit or a timeout [DNS; rcode=SERVFAIL] | message (compound) | found: 156 |

## Notes

- **NRDelegationAttack-S01** — The single client-to-resolver query that opens the capture. The capture is from the authors' Inner Simulator (Section 5.1), not from the Figure 1 walk-through: the names are attack0.home.lan and nsNN.fakeNN.fake0, not xyz.referral.com and fooN.delegation.com.
  - filter: `dns.flags.response == 0 && dns.qry.name == "attack0.home.lan" && ip.src == 127.0.0.1 && ip.dst == 127.0.0.1 && !icmp`
- **NRDelegationAttack-S02** — ⚠ No query to a referral-zone authoritative that returns a referral. The filter matches frames 4, 28, 30 ... 80, but every one of those is answered by ICMP port unreachable, so they are the non-responsive server of arrow 11, not this arrow. Frame 4 is the ambiguous one: it is the first such query and could be this step instead. Flagged.
  - filter: `dns.flags.response == 0 && ip.dst != 127.0.0.1 && dns.qry.name == "attack0.home.lan" && !icmp`
- **NRDelegationAttack-S03** — Zero packets. No response in this capture carries more than one authority record (counts are only 0 or 1) and the largest frame is 151 bytes, so the LRR is absent. The capture begins after the resolver already holds the NS list.
  - filter: `dns.count.auth_rr > 1`
- **NRDelegationAttack-S04** — Cache and ADB lookups are internal and emit no packets, so this cannot be found on the wire by construction. The filter shows the consequence rather than the step: 46 queries for 23 distinct NS names, each asked as both A and AAAA, which is the 2-per-name shape of the 2n figure for names that miss the cache.
  - filter: `dns.flags.response == 0 && ip.dst == 127.0.0.2 && dns.qry.name contains "fake" && (dns.qry.type == 1 || dns.qry.type == 28)`
- **NRDelegationAttack-S05** — Internal state, no packets. Indirect support: the first batch of NS names resolved is exactly five (ns28, ns29, ns30, ns31, ns32, frames 6-25), matching the BIND9 referral-limit of 5 named in the figure's footnote. The paper gives this as two list items both labelled Step 5; the figure draws one box, so it is one compound step.
  - filter: `dns.flags.response == 0 && ip.dst == 127.0.0.2 && dns.qry.name contains "fake" && (dns.qry.type == 1 || dns.qry.type == 28)`
- **NRDelegationAttack-S06** — 23 A queries for NS names, issued in batches: ns28-ns32 (frames 6-24), then ns33-ns37 (frames 82-98) after the restart, and so on. The matching AAAA queries are the other half of the 2n lookups.
  - filter: `dns.flags.response == 0 && ip.dst == 127.0.0.2 && dns.qry.name contains "fake" && dns.qry.type == 1`
- **NRDelegationAttack-S07** — 23 responses, one per NS name, each handing back 127.0.0.89 - the address that answers every DNS query with ICMP port unreachable in this capture.
  - filter: `dns.flags.response == 1 && ip.src == 127.0.0.2 && dns.a == 127.0.0.89`
- **NRDelegationAttack-S08** — Internal, no packets. Indirect support: the resolver re-queries attack0.home.lan 28 times (frames 4, 28, 30 ... 80), one per restart, against the BIND9 restart limit of at most 100 quoted in Section 4.1.
  - filter: `dns.flags.response == 0 && ip.dst == 127.0.0.89 && dns.qry.name == "attack0.home.lan" && !icmp`
- **NRDelegationAttack-S09** — A flag cleared inside the resolver. Nothing in a capture can show it and no filter was run; recorded as not_found rather than unchecked because the capture cannot carry this evidence at all.
- **NRDelegationAttack-S10** — Internal, no packets. Indirect support: a fresh batch of NS names begins at frame 82 (ns33-ns37) after the first round of restarts, which is the list being walked from where it left off.
  - filter: `dns.flags.response == 0 && ip.dst == 127.0.0.2 && dns.qry.name contains "fake" && (dns.qry.type == 1 || dns.qry.type == 28)`
- **NRDelegationAttack-S11** — 28 queries to 127.0.0.89, the address handed back by arrow 7. Frame 4 is also the best candidate for arrow 2, which is why that step is flagged.
  - filter: `dns.flags.response == 0 && ip.dst == 127.0.0.89 && dns.qry.name == "attack0.home.lan" && !icmp`
- **NRDelegationAttack-S12** — ⚠ This does not match the figure. The figure draws silence; the simulator's non-responsive host answers all 28 queries with ICMP destination unreachable (port unreachable). The resolver gets no useful answer either way, but an ICMP error is a packet and silence is not, so an absence claim written from this arrow would be refuted by this capture. Flagged.
  - filter: `icmp.type == 3 && icmp.code == 3`
- **NRDelegationAttack-S13** — The last packet of the capture: SERVFAIL for attack0.home.lan back to the client, after 28 restarts.
  - filter: `dns.flags.response == 1 && dns.flags.rcode == 2 && ip.src == 127.0.0.1 && ip.dst == 127.0.0.1`
