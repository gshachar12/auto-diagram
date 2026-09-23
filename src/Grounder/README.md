# PANGEA Grounder

Python implementation of the **LLM Grounder** stage from the PANGEA spec
(`Network Traffic Grounding Evidence and Visualization`). This is the stage
where a free-text traffic description and packet-level evidence are first
brought together: it decomposes the description into atomic Steps and
determines, per Step, whether the evidence supports it.

Only the Grounder is implemented here (not Preprocessor / Validator /
Evaluator / visualization, which are separate pipeline stages in the spec).
The Preprocessor's output contract (`Reduced PCAP`, `Fingerprint_index`) is
defined in `fingerprint_utils.py` so this stage can be developed and tested
independently, and wired to a real Preprocessor later.

## Package layout

| File                    | Spec section                          | What it does |
|--------------------------|---------------------------------------|--------------|
| `models.py`              | "The JSON File is in the following format" | Dataclasses that serialize to exactly the `Matching JSON` schema (`actors[]`, `Steps[]`). |
| `Step_extractor.py`     | "Step Extractor"                     | Text-only, LLM-based: splits description into atomic Steps + role-only actors + two-layer `expected_indicators`. Never sees the PCAP. |
| `fingerprint_utils.py`   | "Reducer" (Preprocessor)              | Data contract for `Reduced PCAP` / `Fingerprint_index`, plus per-IP behavioral profiling used for actor resolution. |
| `evidence_matcher.py`    | "Evidence Matcher"                    | Algorithmic-first actor resolution + Step grounding, with LLM escalation only for ambiguous/unstructured cases. |
| `grounder.py`            | "LLM Grounder"                        | Orchestrates Step Extractor → Evidence Matcher → `MatchingResult`. |
| `llm_client.py`          | (mechanism for both LLM-based steps)  | `AnthropicLLMClient` (real) and `MockLLMClient` (offline/deterministic). |
| `demo.py`                | —                                      | Runnable, fully offline example (mock PCAP + mock LLM). |
| `test_grounder.py`       | —                                      | Unit tests for each branch in the spec's Actor Resolution / Step Grounding rules. |

## Design choices that map directly to spec requirements

- **Step Extractor never receives the Reduced PCAP** — its `extract()` method
  only takes `traffic_description: str`, so its output structurally cannot be
  biased by what evidence exists.
- **Actor Resolution before Step Grounding, and Steps depending on an
  unresolved actor are flagged `uncertain_needs_drilldown` immediately** —
  `_ground_Step` checks `referenced_actors` resolution before doing any
  fingerprint lookup, avoiding a wasted lookup per the spec.
- **Algorithmic-first grounding, LLM escalation only for ambiguity** —
  `_ground_Step` only calls the LLM when: (a) a Step has no usable
  structured indicators (`indicator_description`-only fallback), or (b) the
  fingerprint lookup returns multiple competing candidate buckets. Both LLM
  escalation paths (`_resolve_actor`'s multi-candidate branch and
  `_escalate_Step`) pass only the relevant slice, never the full Reduced PCAP
  or full capture.
- **Grounding statuses map 1:1 to spec cases**:
  `grounded` (single clean structural match with raw packet IDs),
  `unsupported` (no match at all), `uncertain_needs_drilldown` (match exists
  only as folded aggregate stats, or actor unresolved, or LLM couldn't decide).
- **R3 (aggregate traceability) is respected on the read side too** —
  `IPBehaviorProfile` folds in `fingerprint_index[...]["aggregate"]` data so
  actors that only appear in compressed/folded packets still contribute
  signal to actor resolution, not just raw retained packets.

## Quick start

```bash
# Runs fully offline with mock PCAP + mock LLM responses
python -m pangea_grounder.demo

# Unit tests
python -m pytest pangea_grounder/test_grounder.py -q
```

To use the real Claude API instead of the mock:

```python
from pangea_grounder import Grounder
from pangea_grounder.llm_client import AnthropicLLMClient

grounder = Grounder(llm_client=AnthropicLLMClient(model="claude-sonnet-4-6"))
result = grounder.run(traffic_description, reduced_pcap, fingerprint_index)
print(result.to_dict())
```

`reduced_pcap` and `fingerprint_index` are expected in the shape documented at
the top of `fingerprint_utils.py` — swap that module's shape (or the calls
into it from `evidence_matcher.py`) if your real Preprocessor emits a
different wire format.

## Not yet implemented (other pipeline stages, per spec)

- **Preprocessor** (Filter Generator + Reducer) — produces the
  `Reduced PCAP` / `Fingerprint_index` this package consumes.
- **Validator** — independent QA over the Grounder's own output
  (`extractor_fp/fn`, `matcher_fp/fn`), a distinct component from the
  Grounder.
- **Evaluator** — offline benchmark scoring against human-labeled ground
  truth.
- **Visualization / rendering engine.**

Happy to build any of these next in the same style.
