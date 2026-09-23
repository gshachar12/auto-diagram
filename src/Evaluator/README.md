# PAnGEA Evaluator — Automated Parts

This implements everything classified as **automatic** or **automatic-with-a-pluggable-similarity-function**
in the earlier design discussion. What's still manual (building gold samples) is explicitly out of scope here —
see `example_gold.json` for the shape that manual work needs to produce.

## Files

- `schemas.py` — `GoldSample`/`SystemSample` data shapes.
- `alignment.py` — matches system claims/actors to gold ones by **text content** (TF-IDF cosine similarity),
  never by `actor_id`/`claim_id`/resolved IP. This is the step everything else depends on.
- `coreference_metrics.py` — MUC, B-cubed, CEAF. **Validated against the exact hand-worked fragmentation
  example from the design discussion** — all three match to 3 decimal places (see `test_coreference.py`).
- `accuracy_metrics.py` — extraction P/R, severity-weighted recall, grounding-status P/R, evidence-matching
  P/R, actor IP resolution accuracy (correctly/incorrectly resolved, unresolved, never-extracted).
- `compliance.py` — structural invariant checks that need **no gold at all** (can run on every PCAP):
  grounded-requires-evidence, resolved-IP-must-be-observed, duplicate-resolution visibility flag.
- `report.py` — ties it all together into one `EvaluationReport` per sample.
- `run_evaluator.py` — CLI that reads **this project's actual JSON output**
  (`03c_evidence_matcher_output.json` + `01_preprocessing_output.json`) directly.

## Usage

```bash
python3 -m evaluator.run_evaluator \
    --gold gold_sample.json \
    --system-output 03c_evidence_matcher_output.json \
    --fingerprint-index 01_preprocessing_output.json \
    -o report.json
```

Gold JSON shape — this is the one piece you build by hand per sample (see the "what must be manual" discussion):

```json
{
  "sample_id": "...",
  "actors": [{"entity_id": "...", "description_ref_gold": "...", "ground_truth_ip": "..." | null}],
  "claims": [{"claim_id": "...", "text": "...", "severity": "critical"|"minor",
              "references_entities": ["..."], "gold_grounding_status": "grounded"|"unsupported"|"uncertain_needs_drilldown",
              "gold_linked_fingerprint_keys": ["..."]}]
}
```

## Verified end-to-end

Ran against the exact worked example used throughout the design discussion (kali/gateway/network_nodes,
including the real "grounded with no evidence" bug) — every number matches what was derived by hand:
extraction P/R=1.0, grounding precision on "grounded"=0.5 (correctly catches the bug), actor extraction
P/R=0.5 (correctly penalizes the spurious `network_nodes` actor), compliance check correctly FAILS on the
no-evidence-but-grounded step.

## Known limitation, found while testing — not fixed, documented

**B-cubed (and to a lesser extent the others) can look artificially good when a spurious system actor has
NO gold counterpart at all** — it gets treated as a trivially "correct" self-matching singleton, rather than
penalized. Confirmed directly: in isolation, an extra actor with zero relation to gold still scored
P=1.0/R=1.0 under B-cubed alone. This is a known issue in the coreference-metrics literature itself (the
"twinless mentions" problem — Cai & Strube, 2010), not a bug in this implementation.

**This is exactly why `actor_extraction` (Precision/Recall) is reported as a separate metric, not folded
into the coreference scores** — it's the one that actually catches a spurious/unmatched actor (confirmed:
it correctly showed Precision=0.5 for the `network_nodes` case above, while B-cubed alone would have missed
it entirely). Read the coreference metrics as "given the actors that were extracted, how well was clustering
handled" — not as a complete substitute for extraction accuracy.

## Default similarity — a named limitation, not silent

`tfidf_similarity_matrix` (the default) is lexical-overlap-based, not true semantic similarity. It correctly
matched `"kali is a very evil attacker"` to `"an offensive framework host named 'kali'"` (shared token "kali"
carries it), but will under-perform on a true paraphrase with **zero shared vocabulary**. `align_by_similarity`
takes a `similarity_fn` parameter specifically so a real embedding model (e.g. via OpenAI's embeddings API)
can be substituted later without touching any other module.

## Not built here (deliberately, per the manual/automatic split already agreed)

- Gold sample construction itself (PCAP selection, description writing/sourcing, manual IP verification,
  manual claim/severity annotation, manual packet-to-claim linkage).
- The Entity Completeness Checker (NER-based) discussed earlier as a semi-automated aid for building gold —
  a separate, smaller tool, not part of this scoring core.
