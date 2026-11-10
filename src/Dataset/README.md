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
./pangea ingest     # register pcaps/datasets/ (real captures, counted with tshark)
./pangea extract    # steps -> atomic claims, conditions run on the source capture
./pangea review     # the claims review queue
./pangea set-password   # the dashboard password (--generate to make one up)
./pangea models     # which panel members can actually be called
./pangea prompts    # the frozen prompt variants (--show <label> renders one)
./pangea run --dry-run   # the plan and an estimate; calls nothing
./pangea run        # models x prompts x pairs x repeats
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
| `pcap/service.py` | the only thing that runs tshark: `summary`, `query`, and the limits |
| `ingest.py` | `pcaps/datasets/` → sources, verbatim steps, counted captures, checklist |
| `extraction.py` | steps → atomic claims, levels, conditions; conditions run on the capture |
| `review.py` | accept / edit / split / merge / reject, as new versions |
| `prompts/` | the frozen variants, the criteria text, and the leak scanner |
| `models/providers.py` | Anthropic / OpenAI / Google over httpx, with the tool loop |
| `runner.py` | the plan, the leak gate, resume, pause, retries, cost estimates |
| `web/` | the read-only dashboard, its read model and its login |
| `cli.py` | `init`, `demo`, `ingest`, `set-password`, `serve`, `status`, `config`, `doctor` |

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

## PCAP service (B1)

`pcap/service.py` is the only place that runs tshark. The display filter it
runs is, in the experiment, written by a model — untrusted input reaching a
subprocess — so:

- **No shell, ever.** tshark is invoked with an argument list, so there is
  nothing for `;`, backticks or `$( )` to break out of.
- **Filters are compiled, not inspected.** Rather than denylisting
  characters (`;` and `"` are legal in display filters), the filter is
  compiled against an empty capture; anything tshark exits non-zero on is
  refused, whatever wording it used. A filter starting with `-` is also
  refused, since it would be read as an option.
- **Captures live in a jail.** Paths are resolved through symlinks and must
  land inside the configured roots.
- **Everything is bounded.** Timeout, a cap on bytes read and a cap on
  packets returned; a truncated scan says it is truncated rather than
  lying about the count.

Results are cached by (capture sha256, filter, limit) — by content, so two
names for one file share an entry and an edited file never hits a stale one.

## Source registry (`./pangea ingest`)

Registers every folder under `pcaps/datasets/`: the steps transcribed
verbatim into `source_steps` (never into `claims` — turning a step into an
atomic claim with a condition is the extraction agent's job), the captures
with a real packet count read by the PCAP service, and a verification
checklist per source.

It does not improve on its sources. Licences are `UNVERIFIED` unless stated;
`both_directions` stays unknown rather than being guessed, because absence
claims are judged against it; a folder with no capture is still registered
with a failed "sample capture obtained" check. Where `source.md` states a
packet count, it is cross-checked against tshark's — currently 3 for 3.

## Steps files (`sources/<paper_id>/steps.json`)

The uniform replacement for the per-paper CSVs under `pcaps/datasets/`, which
had a different column set in every folder and so could not be validated,
diffed or joined.

```bash
pangea steps validate          # every file, against the schema and the capture
pangea steps render --csv      # regenerate steps.md (and steps.csv) from the JSON
pangea steps schema            # the JSON Schema, generated from the model
```

One file per paper: `paper`, `pcap`, and `steps[]`. Each step carries the
paper's own numbering and phase name, where it came from, the paper's wording,
one paraphrase in a fixed template, and a check against the capture.

| rule | how it is enforced |
|---|---|
| the paper's wording wins | `verbatim` is a diagram label or a sentence, copied; the paraphrase lives only in `normalized`, as `ACTOR -> TARGET: action [protocol; fields]` |
| one step is one arrow | a step that does several things stays one step with `compound: true`; splitting into atomic claims is `extract`'s job |
| unknown is a value | every field is always present; `null` plus `needs_review`, never an omission and never a guess |
| the capture decides | a `pcap_check` of `found` is rejected unless it carries the packet numbers **and** the display filter that found them |
| the format is uniform | field order is part of the schema, so a reordered file fails |

The validator also rejects a duplicate `step_id`, a gap in `seq`, a `step_id`
that does not follow `<paper_id>-S%02d`, a value outside the closed lists, a
packet number past the capture's `packet_count`, a missing capture, a size
mismatch, and a **`sha256` mismatch** — without which every cited packet number
could be about a different file.

`steps.schema.json` under `schemas_json/` is generated from the pydantic model
and a test fails if the committed copy has drifted from it.

**JSON is the source of truth.** `steps.md` carries a generated-by banner and
is rewritten by `steps render`; `render` validates first and refuses to write a
table from a file that does not pass. A CSV, if one is wanted, is derived with
the same columns rather than maintained.

Captures are referenced by path and `sha256`, never copied into
`sources/`, and `.gitignore` keeps captures out of that tree.


## Login

The dashboard asks for one password (PBKDF2-SHA256, 600k rounds, stdlib) and
issues an HMAC-signed session cookie. It **fails closed**: with no password
file, every data endpoint returns 503. Five wrong attempts from one address
start a doubling lockout. Changing the password rotates the session secret,
signing every device out.

The cookie is not `Secure`, because this host has no HTTPS (`tailscale
serve` is disabled by the tailnet administrator) and a Secure cookie would
never be sent. The password therefore crosses the tailnet in clear text.
That is a real limitation, not an oversight.

## Extraction and review (B2)

`./pangea extract` turns each verbatim step into atomic claims: a level
(1–5), a reason code for the abstention levels, and for levels 1–3 an
executable condition. Every call is written to `llm_calls` before its output
is used.

The agent writes conditions; the capture decides. Each level 1–3 condition
is immediately run against the source's own captures and the result stored
in `claim_condition_checks` (derived — re-running recomputes it). A
condition that finds nothing on the very capture it came from is **flagged,
not dropped and not kept**: exactly one of three things is wrong — the
condition is too narrow, the step was misread, or that capture is not the
one the step describes — and only a reviewer can say which. Those items sort
to the top of the queue.

Today the extractor is `HeuristicExtractionClient`: a keyword table, not a
model, and it does not pretend otherwise. It exists so the pipeline, the
checks and the review queue are testable and demonstrable with no API key;
its claim wording is crude and its output goes through exactly the same
review a model's would. A real extraction model arrives with the adapters
(B4).

**Review never overwrites.** An edit, a split or a merge appends new claim
versions whose `supersedes` points at what they replace, marked `human`; the
agent's original stays readable forever. The queue's state is derived from
`claim_reviews` rows, not from a flag. A rejected claim keeps its row and
simply never becomes a pair.

## Prompts, adapters and the run (B4)

**Prompt variants are frozen and hashed.** Six of them, each changing
exactly one dimension away from `base` (wording, structure, role, label
order) plus the control with no criteria at all. The criteria text is
byte-identical wherever it appears — only its presentation changes, which
is the only way "the prompt effect" means anything. Editing `criteria.md`
changes every hash, and therefore produces a new run.

**The leak gate runs before every run, not only in the tests.** Each
(pair, variant) that would be sent is rendered and scanned for the expected
verdict, the pair type, the claim's provenance, the source paper and any
Preprocessor cluster; one hit refuses the whole run. The template is
innocent until an item is interpolated into it, which is why the check is
on rendered text.

**Adapters** for Anthropic, OpenAI and Google over plain `httpx` — one
endpoint each, no vendor SDKs, so the pinned model string is the only thing
that decides what ran. Keys are read per call from the environment and never
written to a config, a manifest, a result row or a log line; a transport
error reports only the exception class, because a URL can carry a key. A
missing key, an UNSET model name, an HTTP error, a tool failure and a
refusal are all *results* with `error` set, never crashes.

**The run** is idempotent (keyed by run × pair × model × prompt × repeat,
enforced by the database), resumable, pausable between units, shuffled with
the run seed so order effects cannot line up with any model or item, and
dry-runnable: `--dry-run` prints the plan with token estimates and leaves
cost `null` for any model with no configured price.

### Giving the system an API key

Keys go in `.env` at the repo root — gitignored, and sourced by `./pangea`:

```bash
printf 'ANTHROPIC_API_KEY=...\n' >> .env && chmod 600 .env   # one line per provider
./pangea models              # which members are configured
./pangea models --discover   # ask each provider which model ids it accepts
```

`./pangea models` saying "ready" means a key is present and a model name is
pinned — not that the key is valid. Only a call can tell you that.

For OpenAI and Google, two things are needed: the key in `.env`
(`OPENAI_API_KEY`, `GEMINI_API_KEY`) and a real `model_name` in
`config/models.yaml`, which ships as `UNSET`. Use `--discover` to get the
provider's own current list rather than a published one, which goes stale,
and set `version` to the same exact string so the manifest records what ran.

Google deprecates sampling parameters on its newer models; set
`omit_temperature: true` on that entry if the provider rejects or ignores
`temperature`.

`config/models.yaml` ships the OpenAI and Google entries with
`model_name: UNSET`, because their current identifiers were not verified
here and an invented or aliased name makes a run unreproducible. Fill them
in before using those providers.

## Not here yet

B3 pair builder and mutation
validation · B4 prompt builder, real model adapters, runner · B5 analysis ·
B7 pilot and full run.
