# PAnGEA — Dataset Creator

Backend and (from B6) dashboard for the claim-verification dataset and the
multi-agent experiment: sources → claims → (claim × PCAP) pairs → a run of a
model panel → analysis over the stored responses.

Independent of `Preprocessor/`. The experiment asks whether a panel of models
can verify a claim against a capture; showing them the clustering pipeline's
output would make the labels depend on the algorithm under test. Clusters may
be used later by the analysis only, as a sensitivity comparison.

## Quick start

```bash
./pangea doctor     # check python, git, tshark, data dir
./pangea demo       # seed the reproducible demo dataset (no API calls, no cost)
./pangea serve      # the dashboard, on http://127.0.0.1:8800
./pangea status     # what is stored
./pangea config     # configuration, its hash, and what is still UNSET
pytest              # the suite (pytest.ini scopes it to src/Dataset/tests)
```

## Dashboard

`./pangea serve` runs a read-only FastAPI app and a single-page dashboard:
Overview (counts, run manifest, warnings), Claims (filterable, tap through to
the model-by-model matrix and from there to the stored response behind any
number), Panel, Prompt sensitivity, Controls and leakage, Evidence quality.
Mobile-first, so it is usable on a phone or tablet, with a dark mode.

Every rate is printed with its `n` and a 95% Wilson interval; verdicts are
reduced per model family before any majority is taken; nothing is called
correct or ground truth, and construction-based items are described as
"matches expected". Anything not yet computed — re-executing conditions,
verifying cited packets, sufficiency and necessity, fabricated-packet rate —
is shown as pending rather than filled in with a plausible number.

It binds loopback. `--host` with a non-loopback address is refused without
`--i-know`, because this machine sits on a shared tailnet.

### Running it in the background and reaching it from a tablet

Same pattern as the finance app on this host: pm2 keeps it running, and
Tailscale carries it to the device.

```bash
pm2 start ./pangea --name pangea-dashboard --interpreter sh -- serve --port 8800
pm2 save
```

Then open `http://finance-tau.tailfb309.ts.net:8800` (or
`http://100.99.67.33:8800`) on any device signed into the same tailnet.
`tailscale serve` — which would give HTTPS on a tidy URL — is **disabled on
this tailnet by its administrator**, so the connection relies on tailscaled's
userspace-networking mode forwarding an inbound tailnet connection to the
same port on localhost. That is the same route the finance app uses.

Note that this reaches the dashboard over plain HTTP and with no login, so
every node on that tailnet can read it. The demo data is synthetic, but real
results should get an auth gate first.

`./pangea` is the launcher: it puts `src/` on `PYTHONPATH` and points
`PANGEA_TSHARK` at the user-space Wireshark build, because tshark could not be
installed system-wide on this host (no root). An existing `PANGEA_TSHARK`
always wins.

Generated data goes to `data/dataset/` (gitignored); `PANGEA_DATA_DIR`
overrides it.

## What is here after B0

| file | what it owns |
|---|---|
| `schemas.py` | verdicts, levels, reason codes, pair types, and every stored record |
| `ids.py` | one canonical way to hash a payload, and content-derived ids |
| `config.py` + `config/` | thresholds as configuration, and the refusal to run while any is `UNSET` |
| `manifest.py` | the run manifest: git commit, config hash, prompt hashes, capture hashes |
| `storage/db.py` | the SQLite schema, and the append-only triggers |
| `storage/repository.py` | typed append-only writers; a call goes to both the DB and `results.jsonl` |
| `models/base.py` | the provider-agnostic adapter interface and the answer parser |
| `models/mock.py` | MockModel: correct, wrong, abstaining, malformed, fabricating, failing |
| `demo/` | the seeded synthetic dataset |
| `cli.py` | `init`, `demo`, `status`, `config`, `doctor` |

## The rules this code enforces, not just documents

**Raw data is append-only.** `sources`, `pcaps`, `claims`, `pairs`, `prompts`,
`runs` and `calls` reject `UPDATE` and `DELETE` through SQLite triggers, so a
stray script or a future migration hits the same wall the Python layer does. A
correction is a new row with `supersedes` set. Derived tables
(`analysis_*`, the tshark cache) are recomputable and therefore rewritable;
`clear_derived()` refuses anything else.

**Status is append-only too.** A run has no mutable `status` column, it has a
stream of `run_events`. "Paused at 14:02, resumed at 14:40" stays recoverable.

**Thresholds are pre-registered.** δ, τ, the quantity thresholds and the
equivalence margin ship as the literal `UNSET` in `config/experiment.yaml`, and
`Config.require_frozen()` raises until the project owner sets them — choosing
them after seeing results is what the sentinel exists to prevent. The demo
config under `config/demo/` fills them with arbitrary values so the demo and
the tests can run; nothing measured with it may be reported.

**A config change is a new run.** `config_hash` feeds the run id, so editing a
threshold produces a different run and leaves the old one intact.

**No silent failures.** Malformed JSON, refusals, tool errors and schema
violations are stored as records with `format_error` set. An answer rescued by
JSON repair still counts as a format error — repairing it and then calling it
well formed would erase the signal the format-error rate measures.

**Keys never get written down.** A model config names an environment variable;
the value is read at call time and never reaches a config, a manifest or a
result row.

## Demo dataset

`./pangea demo` builds 3 sources, 3 captures, 11 claims (levels 1–5), 25 pairs
across all four types, 3 prompt variants, 3 mock panel members, and 450 calls —
reproducibly: ids are content-derived and every scripted behaviour comes from a
hash of (seed, call key), so seeding twice is byte-identical.

The claims are **synthetic** and are not quoted from, or attributed to, any
publication (`demo/scenarios.py`). The captures referenced are real files
already in `pcaps/`, so the hashes, sizes and paths are the ones the PCAP
service will meet. Their packet counts stay `NULL` and a
`verification_checks` row records them as unverified, because nothing has
opened the files yet — that is B1.

## Not here yet

B1 PCAP service · B2 source registry, extraction agent, claims review ·
B3 pair builder and mutation validation · B4 prompt builder, real model
adapters, runner · B5 analysis · B6 dashboard · B7 pilot and full run.
