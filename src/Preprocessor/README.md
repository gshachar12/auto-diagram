# PAnGEA — Preprocessing (Reducer + Filter Generator)

Runnable POC implementation of the Preprocessing stage, matching the
functional spec built out in design discussion.

## Files

- `schemas.py` — output dataclasses (`ReducedItem`, `AggregateRef`,
  `CompressionStats`, `ReducerOutput`).
- `fingerprint.py` — structural protocol fingerprinting (TCP/UDP/ARP/ICMP).
  Fixes two bugs found in the original prototype:
  1. TCP flags were matched via substring checks; now parsed as a bitmask.
  2. Pure-ACK detection required an exact flag match, so PSH-ACK data-transfer
     packets never collapsed into `TCP_DATA_STREAM`. Now checks the ACK bit
     generically once a stream's handshake is complete.
- `token_budget.py` — token estimation (tiktoken if available, else a
  chars-per-token heuristic). Used only for R5 budget tracking, not for any
  correctness guarantee beyond "best effort."
- `reducer.py` — the core Reducer. R1–R6 requirement mapping is documented
  inline at the top of the file.
- `filter_generator.py` — Attack Description → BPF filter string. Pluggable
  `llm_client` callable; ships with a deterministic keyword-based fallback
  so the rest of the pipeline is testable without a live LLM call.
- `test_reducer.py` — sanity test against a synthetically generated PCAP
  (scapy). Not a rigorous test suite — confirms the pipeline runs and key
  behaviors are visible in the output.

## Requirements

```
pip install pyshark scapy --break-system-packages
apt-get install -y tshark tcpdump
```

## Important implementation note: BPF filtering on offline files

`tshark`/`pyshark` cannot apply a true BPF capture filter to an
already-captured file — `-f` (capture filter, BPF syntax) only works during
live capture; on offline files tshark only accepts `-Y` (display filter,
Wireshark syntax, evaluated **after** dissection — not the cheap
pre-dissection filtering the design calls for).

To get real pre-dissection BPF filtering on a file, the Reducer pre-filters
with `tcpdump -r <input> -w <output> "<bpf>"` (which does support BPF against
`-r`), and hands pyshark the already-filtered file. If `tcpdump` fails
(malformed filter, etc.), it degrades to processing the file unfiltered
rather than failing the whole stage.

## Known open design gap (found via testing, not yet fixed)

The current fingerprint key for TCP includes `dst_port`. This means:
- **Host scans** (many source/destination IPs, same port) collapse
  correctly — IP is intentionally excluded from the key.
- **Port scans** (single source, many destination ports) do **not**
  collapse — each scanned port produces its own fingerprint key, so a
  50-port scan yields 50 separate reduced items instead of one compressed
  entry.

This was inherited from the original prototype's design and confirmed via
`test_reducer.py`. Two possible fixes discussed but not yet implemented:
1. A separate high-cardinality-port heuristic: if a single source hits many
   distinct destination ports with identical flags, key on `(src, flags)`
   instead of `(flags, dst_port)`, collapsing across ports.
2. A post-hoc pass: after fingerprinting, detect groups of fingerprints
   sharing `src` + `flags` with varying `dst_port`, and merge them into a
   single aggregated item.

Left as an open decision rather than silently patched, since it changes the
fingerprinting scheme's behavior and should be a deliberate choice.

## Not yet implemented (per agreed POC scope)

- The internal guard/self-check on Filter Generator's output (match-count
  sanity check before handing off to the Reducer) — explicitly deferred.
- Two-pass Reducer processing for even budget allocation across the full
  capture timeline — current implementation is single-pass (stops at the
  point budget is exceeded, flags it, does not silently truncate).
