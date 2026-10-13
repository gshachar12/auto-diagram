# PAnGEA — Project Reference Document

> Living reference for architecture, decisions, conventions, and context. Update as the project evolves.
> Last updated: October 2026

---

## 1. Project Goal

PAnGEA is a research pipeline that takes a **text description** and a **PCAP file** as input and returns a dictionary mapping each behavioral step in the description to the packets in the PCAP that support it.

```
Input:  (text description, PCAP file)
Output: {step_id: [cluster_fingerprint_keys]}  # empty list = ungrounded step
```

The system is designed for **academic research** — every decision must be traceable, reproducible, and quantifiable. LLM components are constrained to preprocessing and dataset construction only; the core matching pipeline is deterministic.

---

## 2. System Architecture

```
text description ──→ Layer 0 (AttackContext extraction) ──────────────────────┐
                                                                               ↓
PCAP ─────────────→ Layer 1 (Dissection)                                      │
                        ↓                                                      │
                    Layer 2 (Fingerprint)                                      │
                        ↓                                                      │
                    Layer 3 (Clustering)                                       │
                        ↓                                                      │
                    Layer 4 (Analysis + Serialization) ←─────────────────────┘
                        ↓
                    Grounder
                     Stage 1: bi-encoder (candidate retrieval)
                     Stage 2: cross-encoder (final scoring)
                        ↓
                    {step_id: [GroundingResult]}
```

The two input branches — description and PCAP — never cross until Layer 4 relevance scoring. This enforces the **R2 boundary**: the PCAP is never seen by the intent extractor, and the raw description never crosses into the Reducer.

---

## 3. Module Structure

```
src/
├── Preprocessor/
│   ├── preprocessor.py           # orchestrator, exposes run_preprocessing()
│   ├── schemas.py                # all dataclasses and enums
│   ├── layer0_attack_context.py  # AttackContext extraction (LLM + keyword fallback)
│   ├── layer1_dissection.py      # PacketFeatures, L2→L3→L4→L7→entropy
│   ├── layer2_fingerprint.py     # signature tuple + temporal bucketing
│   ├── layer3_clustering.py      # Cluster construction + aggregate maintenance
│   ├── layer4_analysis.py        # TF-IDF, Z-scores, IP summary, anomalies, tiers
│   ├── layer4_serialization.py   # cluster → natural language string
│   └── token_budget.py           # token estimation (tiktoken or char heuristic)
├── Grounder/
│   ├── schemas.py                # Step, GroundingResult, StepGrounding, GrounderOutput
│   ├── step_extractor.py         # extract_steps() — LLM, saves output to disk
│   └── grounder.py               # two-stage bi-encoder + cross-encoder
└── Dataset/
    ├── dataset_builder.py        # runs preprocessor on all PCAPs, saves artifacts
    ├── annotator.py              # interactive CLI annotation tool
    └── evaluator.py              # metrics: Precision@1, Jaccard, MRR, no-match accuracy
```

---

## 4. Design Constraints (R1–R6)

| Code | Name | Meaning |
|---|---|---|
| R1 | Referential Integrity | Every output item carries `packet_id` + `timestamp` back to source PCAP |
| R2 | Description-Blindness | Attack description never crosses into Reducer; seen only by Layer 0 |
| R3 | Aggregate Traceability | Every dropped/folded packet leaves a quantitative trace; nothing vanishes silently |
| R4 | Temporal Order Preservation | Output preserves original chronological order |
| R5 | Budget Compliance | Best-effort, not silent truncation. EXCEEDED status returned with stopping point |
| R6 | Protocol Agnosticism | Fingerprint logic never branches on attack type — only structural protocol state |

---

## 5. Core Schemas

### PacketFeatures (Layer 1 output)
Fully extracted, typed representation of one packet. The only module that produces this is `layer1_dissection.py` — the only module that touches raw pyshark objects.

```python
@dataclass
class PacketFeatures:
    packet_id: int
    timestamp: float          # Unix epoch for arithmetic
    timestamp_iso: str        # ISO-8601 for display
    l2_proto, src_mac, dst_mac
    l3_proto, src_ip, dst_ip
    l4_proto, src_port, dst_port, tcp_flags, tcp_stream_id
    icmp_type, icmp_code, arp_opcode, arp_sender_mac
    l7_proto: Optional[str]   # HTTP, DNS, TLS, SSH, or None
    payload_length, payload_entropy, entropy_bucket
    total_length, highest_layer
```

### Fingerprint Key (Layer 2 output)
A JSON-encoded string with 6 positions:

```
[l4_proto, state_sig, l7_proto, dst_port, entropy_bucket, time_bucket]
```

Examples:
- SYN flood: `["TCP", "SYN", null, 80, null, 5666666]`
- DNS tunneling: `["UDP", "UDP", "DNS", 53, "very_high", 5666666]`
- Legitimate DNS: `["UDP", "UDP", "DNS", 53, "low", 5666666]`
- ICMP echo: `["ICMP", "ICMP:8:0", null, null, null, 5666666]`
- ARP reply: `["ARP", "ARP:2:aa:bb:cc", null, null, null, 5666666]`
- Same attack, second wave: `["TCP", "SYN", null, 80, null, 5666667]`

### Cluster (Layer 3 output)

```python
@dataclass
class Cluster:
    fingerprint_key: str
    representative_items: list[ReducedItem]   # up to filtering_limit raw packets
    aggregate: AggregateStats                 # always present, always up to date
    metadata: ClusterMetadata                 # populated by Layer 4

    @property
    def is_singleton(self) -> bool:           # aggregate.count == 1
```

**Key rule:** aggregate lives on the Cluster, not on the representative ReducedItem. `ReducedItem` is a pure packet record with no statistical state.

**Singletons** are Clusters with `count == 1`. They are not a separate data structure.

### AggregateStats

```python
count, total_bytes, unique_sources, unique_destinations
first_seen, last_seen             # ISO-8601
iat_mean, iat_std, iat_min, iat_max   # inter-arrival time stats
outbound_bytes, inbound_bytes     # directionality (populated in Layer 4)
```

### ClusterMetadata (Layer 4 output)

```python
tier: ClusterTier                 # PRIMARY / SECONDARY / REMNANT
traffic_share: float              # fraction of total pcap bytes
tfidf_weight: float               # rarity score (IDF in practice — see note below)
dst_port_class: PortClass         # WELL_KNOWN / REGISTERED / EPHEMERAL
dst_port_service: str             # "DNS", "SSH", "unknown", ...
zscore_anomalies: dict[str, float] # {dimension: MAD-based Z-score}
context_match: bool               # matches AttackContext protocol or behavior
cluster_text: str                 # natural language serialization for grounder
```

### AttackContext (Layer 0 output)

```python
suspected_protocols: list[SuspectedProtocol]  # enum-constrained
suspected_behaviors: list[SuspectedBehavior]  # enum-constrained
target_indicators:   list[TargetIndicator]    # enum-constrained
raw_description: str
```

Vocabulary:
- Protocols: TCP, UDP, ICMP, ARP, DNS, HTTP, TLS, SSH
- Behaviors: flood, unanswered_syn, amplification, exfiltration, scanning, tunneling, beaconing, spoofing
- Indicators: single_dst, high_rate, no_response, many_sources, single_src

### ReducerOutput

```python
clusters: list[Cluster]          # primary output, covers all tiers
compression_stats: CompressionStats
budget_status: BudgetStatus
attack_context: AttackContext
ip_summary: list[dict]           # per-IP structural profile
anomalies: list[dict]            # per-protocol cardinality fanout anomalies
filter_string_used: None         # kept for pipeline_runner.py compatibility

# Compatibility shims for pipeline_runner.py adapt_reducer_output():
@property fingerprint_index -> dict[str, AggregateStats]
@property reduced_representation -> list[ReducedItem]
```

---

## 6. Layer Details

### Layer 0 — AttackContext Extraction
- **LLM role:** classification/extraction into enum schema, not code generation
- **Temperature:** 0 (maximum determinism)
- **Fallback:** keyword matcher (`_KEYWORD_RULES`) used when no LLM client provided
- **R2 boundary:** never sees the PCAP; pcap never crosses into this layer
- **Output used:** only in Layer 4 for relevance scoring, not for filtering

### Layer 1 — Dissection Pipeline
- **Only file that touches pyshark objects**
- Sub-pipeline order: L2 → L3 → L4 → L7 → payload entropy (last)
- Entropy computed on **application payload only**, not full packet:
  - DNS → query name bytes (high entropy = tunneling signal)
  - HTTP → body field
  - TLS → `app_data` record
  - SSH → `encrypted_packet`
  - Fallback → DATA layer
  - No payload (SYN, ACK, ARP) → `entropy_bucket = null`
- L7 detection hierarchy:
  1. pyshark dissector presence
  2. Well-known dst port mapping
  3. TLS handshake byte signature (0x16, 0x17)
  4. None

### Layer 2 — Fingerprint Construction
- Fingerprint = `[l4_proto, state_sig, l7_proto, dst_port, entropy_bucket, time_bucket]`
- **TCP state machine:** SYN / SYN-ACK / ACK_HANDSHAKE / DATA / FIN / RST / OTHER
- **Temporal bucketing:** `time_bucket = int(timestamp // delta_t)` — default `delta_t = 300s`
  - Same attack, same wave → same bucket → same cluster
  - Same attack, hours later → different bucket → different cluster
- **Entropy bucketing:** LOW [0,3) / MEDIUM [3,5.5) / HIGH [5.5,7) / VERY_HIGH [7,8]
  - Purpose: separate DNS tunneling from legitimate DNS at fingerprint time

### Layer 3 — Clustering
- `process_packet()` called once per packet; updates `dict[str, Cluster]` in place
- Aggregate updated on **every packet**, even under budget pressure (R3)
- ReducedItem only added when `aggregate.count <= filtering_limit`
- IAT tracked in scratch space `_iat_scratch`, summarised at `finalise_clusters()`
- Budget exceeded → skip ReducedItem creation but continue updating aggregate

### Layer 4 — Analysis
Run in order:

1. **Traffic share** — `cluster.total_bytes / total_bytes`
2. **TF-IDF (IDF in practice)** — each packet is a "document" with one "word" (its fingerprint), so TF = 1 for all → only IDF matters: `log(total_packets / cluster.count)`. Measures fingerprint rarity within this PCAP. High score = rare fingerprint.
3. **Per-protocol Z-scores** — grouped by L4 proto. TCP vs TCP, UDP vs UDP. Log-transformed + MAD-based (robust to heavy tails). Dimensions: packet_rate, byte_volume, src_cardinality, dst_cardinality, iat_mean. **Limitation:** baseline is relative to this PCAP only — if PCAP contains only attack traffic, Z-scores may be near zero.
4. **Context match** — checks both `suspected_protocols` (protocol match) and `suspected_behaviors` (behavioral match against cluster stats):
   - flood: high packet_rate Z-score + high iat_mean Z-score
   - unanswered_syn: SYN cluster count vs SYN-ACK cluster count ratio > 10
   - scanning: many unique_dsts, few unique_srcs
   - beaconing: low IAT coefficient of variation (iat_std / iat_mean < 0.1)
   - exfiltration: outbound_bytes >> inbound_bytes
   - amplification: inbound_bytes >> outbound_bytes
5. **Port metadata** — `dst_port_class` and `dst_port_service`
6. **Tier assignment:**
   - PRIMARY: (high TF-IDF or anomalous Z-score) AND context_match
   - SECONDARY: anomalous but no context_match, or moderate signal
   - REMNANT: low TF-IDF, no anomalies, no context match
7. **IP summary** — per-IP structural profile: traffic volume, fanout cardinality, top fingerprints, anomaly involvement, sample packets. Capped to 50 IPs.
8. **Anomaly detection** — per-protocol cardinality fanout vs within-protocol median. Flags clusters with unusually high unique_srcs or unique_dsts relative to protocol peers. Complements Z-scores: Z-score finds "how much", fanout finds "how many distinct parties".
9. **Cluster serialization** — `serialize_cluster()` called last, result stored in `cluster.metadata.cluster_text`. Natural language, under 512 tokens, includes: protocol, scale, entropy, timing, anomalies, traffic share, tier.

---

## 7. Grounder

### Step Extraction
- LLM with constrained prompt: steps must describe **traffic-observable** behaviors only
- Excluded: attacker intent, system impact, anything not visible as packets
- Temperature = 0, model version pinned by caller
- **Always save to disk** (`save_path` parameter) — LLM outputs frozen as static JSON
- Load with `load_steps(path)` in evaluation to avoid re-running LLM

### Step Schema
```python
@dataclass
class Step:
    step_id: int
    text: str          # extracted traffic-observable step
    source_text: str   # original sentence(s)
    mitre_tag: Optional[str]
```

### Two-Stage Grounding
**Stage 1 — Bi-encoder** (`BAAI/bge-large-en-v1.5`)
- Embeds all cluster texts once (offline, reusable)
- Cosine similarity → top-k candidates (default k=10)

**Stage 2 — Cross-encoder** (`BAAI/bge-reranker-large`)
- Scores each `(step_text, cluster_text)` pair jointly
- Sigmoid-normalised to [0, 1]
- Deterministic given fixed model weights

### Evidence Labels and Thresholds

| Label | Score | Criteria |
|---|---|---|
| SUPPORTS | ≥ 0.75 | Fingerprint consistent + scale consistent + no contradictions |
| PARTIAL | ≥ 0.55 | Fingerprint matches but scale or direction incomplete |
| NEUTRAL | ≥ 0.40 | Plausible but too generic to discriminate |
| (not returned) | < 0.40 | Below threshold |

- **Ungrounded:** no cluster above neutral threshold → `matched_clusters = []`
- **Ambiguous:** score gap between rank-1 and rank-2 < 0.10 → `is_ambiguous = True`
- Ungrounded steps are **informative**: described behavior not visible in capture

### Step-to-Cluster Relationship
Not 1:1. Can be:
- one step → one cluster (simple case)
- one step → many clusters ("SYN sent, some answered" = SYN cluster + SYN-ACK cluster)
- many steps → one cluster (sub-steps describing the same pattern)
- one step → zero clusters (counterfactual or wrong step)

### Models to Benchmark

| Model | Role | Notes |
|---|---|---|
| BM25 | Lower bound | Fully interpretable, no neural component |
| SPLADE | Candidate | Sparse, interpretable — good for traceability |
| ColBERT | Candidate | Single-stage, good accuracy/speed trade-off |
| bi-encoder + cross-encoder | Primary system | Two-stage, highest accuracy |
| LLM baseline | Comparison only | Run once, outputs saved |

---

## 8. Dataset

### File Naming Convention
```
dataset/
├── pcaps/        pcap_[N]_[free_description].pcap
├── texts/        text_[N]_[free_description].txt
├── extracted/    extracted_[N]_[free_description].json   ← step extractor output
├── clusters/     clusters_[N]_[free_description].json    ← preprocessor output
└── ground_truth/ gt_[N]_[free_description].json          ← annotation
```

N is the **pairing key** — `pcap_001` pairs with `text_001`, `extracted_001`, `clusters_001`, `gt_001`.

`extracted/` files are JSON (not .txt) because steps need structured fields (`step_id`, `text`, `source_text`).

### Annotation Rubric

| Label | Criteria |
|---|---|
| SUPPORTS | Fingerprint consistent + scale consistent + no contradictions. All three. |
| PARTIAL | Fingerprint matches but scale inconsistent, OR only one direction of behavior present, OR L7 matches but entropy contradicts |
| NEUTRAL | Plausible but too generic; step could apply equally to many clusters |
| CONTRADICTS | Hard contradiction: wrong protocol, wrong direction, wrong scale |

Steps with no SUPPORTS or PARTIAL annotations → `no_match: true` in ground truth.

### Evaluation Metrics

| Metric | Description |
|---|---|
| Precision@1 | Is top-ranked cluster SUPPORTS (1.0) or PARTIAL (0.5)? |
| Set Jaccard | Overlap between predicted cluster set and ground truth set |
| MRR | Mean reciprocal rank of first correct cluster |
| No-match accuracy | Correct rejection rate for steps with null ground truth |
| Coverage | Fraction of steps that get any match above threshold |
| Ambiguity rate | Fraction of steps flagged as ambiguous |

---

## 9. Key Architectural Decisions and Rationale

### Filter generator removed
- **Old:** LLM generates BPF expression → hard pre-filter → silent packet discard (R3 violation). Also non-deterministic, blind to actual pcap contents.
- **New:** All packets clustered; AttackContext is a relevance signal in Layer 4, not a gate.

### Cluster owns the aggregate
- **Old:** `AggregateRef` stapled onto representative `ReducedItem`; parallel `fingerprint_index` dict. Aggregate only synced beyond `filtering_limit` → inconsistent state under budget pressure.
- **New:** `Cluster` class owns `AggregateStats`; always up to date; one source of truth.

### Entropy on application payload only
- Protocol headers have predictable byte distributions — computing on full packet is meaningless noise.
- Most discriminating for protocols whose payloads *should* be low-entropy (DNS labels, HTTP text) but are not.
- Less useful for TLS/SSH (always high entropy; expected and legitimate).

### Temporal bucketing in fingerprint
- Without it, two SYN flood waves hours apart merge into one cluster, hiding attack phases.
- Mechanism: `time_bucket = int(timestamp // delta_t)` appended to fingerprint key.

### Per-protocol Z-scores (not cross-protocol)
- Comparing ARP packet rates to TCP packet rates is meaningless — completely different distributions.
- Clusters grouped by L4 proto; MAD-based Z-scores within each group.

### Source IP excluded from fingerprint
- Including src IP causes oversegmentation — each unique attacker in a DDoS gets its own cluster, destroying the flood signal.
- Tradeoff accepted: different attackers merge into same cluster.

### Context match checks behaviors, not just protocols
- ICMP should be PRIMARY in a ping flood but SECONDARY in a SYN flood.
- Protocol match alone cannot make this distinction.
- `suspected_behaviors` from AttackContext mapped to cluster stats (IAT, cardinality ratios).

### LLM role boundaries

| Component | LLM involved? | Role | Reproducibility mechanism |
|---|---|---|---|
| AttackContext | optional | enum extraction | keyword fallback is default |
| Preprocessor layers 1-4 | no | — | fully deterministic |
| Step extraction | yes | dataset + live pipeline | outputs always saved to disk |
| Annotation | yes | proposal only | human verifies, agreement rate reported |
| Grounder | no | — | deterministic given model weights |
| LLM baseline | yes | comparison only | single run, outputs fixed |

---

## 10. Oversegmentation vs Undersegmentation Trade-off

Every fingerprint dimension added risks **oversegmentation** (splitting the same idea into many small clusters). Every dimension removed risks **undersegmentation** (merging distinct behaviors into one noisy cluster).

| Decision | Accepted risk |
|---|---|
| Include entropy bucket | May split one tunneling session if entropy varies across packets |
| Exclude source IP | Different attackers in same DDoS merge into one cluster |
| Time bucket with tunable Δt | Too small → attack wave splits; too large → distinct waves merge |
| TCP state machine (not raw flags) | Loses some flag-level granularity; reduces oversegmentation of data streams |

---

## 11. Academic Validity Requirements

- **Labeled benchmark datasets:** CIC-IDS2017/2018, UNSW-NB15, CTU-13
- **Stability analysis:** bootstrap resampling (80% subsamples), hyperparameter sweep
- **Ablation studies:** remove each fingerprint dimension, measure grounding degradation
- **Case studies:** 2-3 detailed walkthroughs including at least one failure case
- **Comparison baseline:** fully LLM-based pipeline (no code) vs structured pipeline
- **Modest, falsifiable claim:** "This fingerprint design produces clusters that align with human-meaningful attack categories better than protocol-agnostic baselines, as measured by X on datasets Y and Z."

---

## 12. Conventions and Rules for Future Code

- **Layer boundaries are strict:** `layer1_dissection.py` is the only file that imports or touches pyshark. Everything downstream receives `PacketFeatures`, never raw packets.
- **Aggregate always updated:** even when budget is exceeded or filtering_limit is reached, `cluster.aggregate` must be updated. R3 is non-negotiable.
- **Fingerprint key is always a JSON array string** — parse with `json.loads()`, never string-split.
- **Entropy is always payload-only** — never compute on the full packet.
- **Thresholds are always parameters** — never hardcode values like 0.01 for IAT or 10x for SYN/SYN-ACK ratio. Pass as arguments with documented defaults.
- **LLM outputs always saved to disk** when used in the live pipeline — never run LLM on the fly without saving the result.
- **No silent failures** — budget exceeded, parse failures, and ungrounded steps are always surfaced explicitly in output schemas, never silently dropped.
- **Compatibility shims:** `ReducerOutput.fingerprint_index` and `ReducerOutput.reduced_representation` are `@property` shims for `pipeline_runner.py` — do not remove them.
- **Model versions pinned** — any model loaded in the grounder must be specified by exact name string, not an alias like "latest".
- **`analyse_clusters()` returns a tuple** `(list[Cluster], ip_summary, anomalies)` — always unpack all three.

---

## 13. Open Items

- [ ] Integrate `layer4_serialization.serialize_cluster()` call at end of `analyse_clusters()` in `layer4_analysis.py`
- [ ] Update `adapt_reducer_output()` in `pipeline_runner.py` to consume `ip_summary` and `anomalies` from `ReducerOutput`
- [ ] Wire `step_extractor.py` and `grounder.py` into `pipeline_runner.py`
- [ ] Collect 5-10 PCAPs for initial dataset (CIC-IDS2017 recommended as starting point)
- [ ] Run `dataset_builder.build_extracted_steps()` with pinned LLM model, save all outputs
- [ ] Run `annotator.py` on first 3 entries; refine rubric from ambiguous cases found
- [ ] Calibrate grounder threshold τ once first labeled entries are available
- [ ] Benchmark BM25 / SPLADE / ColBERT / bi-encoder+cross-encoder on same evaluation set
- [ ] Migrate step extractor from API model to local open model (Llama-3 / Mistral) before publication
- [ ] Define `directionality_ratio` computation (outbound vs inbound bytes) in Layer 3 or 4
- [ ] Add `cluster_count` to `CompressionStats` in schemas (currently missing from some versions)
