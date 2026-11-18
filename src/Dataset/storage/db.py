"""
SQLite schema and connection.

  Responsibility: the durable shape of the dataset, and the enforcement of
  the append-only rule.

  Raw tables (RAW_TABLES) carry what was observed or decided: sources,
  captures, claims, pairs, prompts, runs and model calls. They are
  append-only, and that is enforced by SQLite triggers rather than by
  discipline in the Python layer -- a trigger also stops a stray sqlite3
  shell, a future migration script or a careless ORM. A correction is a new
  row that supersedes the old one; nothing is updated or deleted.

  Derived tables (DERIVED_TABLES) carry what analysis computed: they are
  recomputable by definition and so may be rewritten, which is exactly why
  they are kept apart from the raw ones.

  Status is append-only too: a run does not have a mutable `status` column,
  it has a stream of `run_events`. The current status is the latest event.
  That keeps "paused at 14:02, resumed at 14:40" recoverable, which a column
  overwritten in place would not.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 6

RAW_TABLES: tuple[str, ...] = (
    "sources",
    "pcaps",
    "verification_checks",
    "source_steps",
    "claims",
    "claim_reviews",
    "pairs",
    "discards",
    "prompt_variants",
    "model_specs",
    "config_changes",
    "runs",
    "run_events",
    "calls",
    "llm_calls",
)

DERIVED_TABLES: tuple[str, ...] = (
    "analyses",
    "analysis_call_facts",
    "analysis_metrics",
    "pcap_query_cache",
    "claim_condition_checks",
)


class AppendOnlyViolation(sqlite3.IntegrityError):
    """Raised (as a SQLite error) when something tries to rewrite raw data."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------- sources
CREATE TABLE IF NOT EXISTS sources (
    source_id  TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    authors    TEXT NOT NULL DEFAULT '[]',
    venue      TEXT NOT NULL DEFAULT '',
    year       INTEGER,
    urls       TEXT NOT NULL DEFAULT '[]',
    license    TEXT NOT NULL DEFAULT 'UNVERIFIED',
    origin     TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- Captures are referenced, never redistributed: path + hash + origin only.
CREATE TABLE IF NOT EXISTS pcaps (
    pcap_id          TEXT PRIMARY KEY,
    source_id        TEXT REFERENCES sources(source_id),
    path             TEXT NOT NULL,
    sha256           TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    -- NULL until the PCAP service has actually opened the file.
    packet_count     INTEGER,
    capture_metadata TEXT NOT NULL,
    license          TEXT NOT NULL DEFAULT 'UNVERIFIED',
    origin           TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);

-- One row per checklist tick. A dead link or a mismatch is recorded here,
-- it is never resolved by deleting the row that reported it.
CREATE TABLE IF NOT EXISTS verification_checks (
    check_id   TEXT PRIMARY KEY,
    source_id  TEXT REFERENCES sources(source_id),
    pcap_id    TEXT REFERENCES pcaps(pcap_id),
    item       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('pass','fail','unverified','keep','drop')),
    notes      TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL DEFAULT 'agent',
    created_at TEXT NOT NULL
);

-- Steps exactly as the source states them, one row per row/arrow/bullet.
-- Raw input to the extraction agent, kept apart from `claims`: a claim is
-- an atomic, checkable statement the agent derived, a step is what the
-- authors wrote. Conflating them would lose the ability to show both.
CREATE TABLE IF NOT EXISTS source_steps (
    step_id     TEXT PRIMARY KEY,
    source_id   TEXT NOT NULL REFERENCES sources(source_id),
    origin_file TEXT NOT NULL,
    row_number  INTEGER NOT NULL,
    step_order  TEXT NOT NULL DEFAULT '',
    text        TEXT NOT NULL,
    fields      TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_source_steps_source ON source_steps(source_id, origin_file, row_number);

-- ----------------------------------------------------------------- claims
CREATE TABLE IF NOT EXISTS claims (
    claim_id          TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL REFERENCES sources(source_id),
    source_location   TEXT NOT NULL,
    source_step_text  TEXT NOT NULL,
    atomic_text       TEXT NOT NULL,
    level             INTEGER NOT NULL CHECK (level BETWEEN 1 AND 5),
    kind              TEXT NOT NULL,
    reason_code       TEXT,
    condition         TEXT,
    mutation_of       TEXT REFERENCES claims(claim_id),
    mutation_type     TEXT,
    provenance        TEXT NOT NULL DEFAULT 'agent',
    version           INTEGER NOT NULL DEFAULT 1,
    supersedes        TEXT REFERENCES claims(claim_id),
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claim_reviews (
    review_id    TEXT PRIMARY KEY,
    claim_id     TEXT NOT NULL REFERENCES claims(claim_id),
    action       TEXT NOT NULL CHECK (action IN ('accept','edit','split','merge','reject')),
    result_claim_ids TEXT NOT NULL DEFAULT '[]',
    notes        TEXT NOT NULL DEFAULT '',
    reviewer     TEXT NOT NULL DEFAULT 'human',
    created_at   TEXT NOT NULL
);

-- ------------------------------------------------------------------ pairs
CREATE TABLE IF NOT EXISTS pairs (
    pair_id        TEXT PRIMARY KEY,
    claim_id       TEXT NOT NULL REFERENCES claims(claim_id),
    pair_type      TEXT NOT NULL CHECK (pair_type IN ('source','mutation','swap','no_pcap')),
    pcap_id        TEXT REFERENCES pcaps(pcap_id),
    expected       TEXT,
    expected_basis TEXT NOT NULL CHECK (expected_basis IN ('construction','author','none')),
    level          INTEGER NOT NULL,
    notes          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);

-- Anything thrown away and why: a mutation that stayed true, a swap that
-- turned out supported, a claim whose condition failed on its own capture.
CREATE TABLE IF NOT EXISTS discards (
    discard_id TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    ref_id     TEXT NOT NULL,
    reason     TEXT NOT NULL,
    details    TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

-- --------------------------------------------------------- prompts/models
CREATE TABLE IF NOT EXISTS prompt_variants (
    prompt_id   TEXT PRIMARY KEY,
    dimension   TEXT NOT NULL,
    label       TEXT NOT NULL,
    template    TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    config_version INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_specs (
    model_id       TEXT PRIMARY KEY,
    family         TEXT NOT NULL,
    version        TEXT NOT NULL,
    adapter        TEXT NOT NULL,
    supports_tools INTEGER NOT NULL,
    temperature    REAL NOT NULL,
    max_output_tokens INTEGER NOT NULL DEFAULT 2048,
    created_at     TEXT NOT NULL
);

-- Every change to a pre-registered parameter, with what it was and what it
-- became. The dashboard lets these be moved with a slider, which is only
-- defensible because the move is recorded: the one failure mode that would
-- invalidate the whole experiment is a threshold quietly tuned after the
-- results came in, and this table is what makes that visible afterwards.
CREATE TABLE IF NOT EXISTS config_changes (
    change_id    TEXT PRIMARY KEY,
    path         TEXT NOT NULL,
    old_value    TEXT,
    new_value    TEXT,
    config_hash_before TEXT NOT NULL DEFAULT '',
    config_hash_after  TEXT NOT NULL DEFAULT '',
    runs_existing INTEGER NOT NULL DEFAULT 0,
    changed_by   TEXT NOT NULL DEFAULT 'human',
    note         TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);

-- ------------------------------------------------------------------- runs
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    manifest   TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_events (
    event_id   TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL REFERENCES runs(run_id),
    status     TEXT NOT NULL CHECK (status IN ('created','started','paused','resumed','finished','failed')),
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- One row per model call, successful or not. Mirrored to results.jsonl.
CREATE TABLE IF NOT EXISTS calls (
    call_id       TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL REFERENCES runs(run_id),
    pair_id       TEXT NOT NULL REFERENCES pairs(pair_id),
    model_id      TEXT NOT NULL,
    model_family  TEXT NOT NULL,
    model_version TEXT NOT NULL,
    prompt_id     TEXT NOT NULL,
    prompt_hash   TEXT NOT NULL,
    repeat        INTEGER NOT NULL,
    temperature   REAL NOT NULL,
    -- Exactly what was sent, not a template plus the hope of re-rendering
    -- it the same way later. prompt_hash identifies the variant; this is
    -- the bytes the model actually saw.
    prompt_rendered TEXT NOT NULL DEFAULT '',
    raw_response  TEXT NOT NULL,
    parsed        TEXT,
    tool_calls    TEXT NOT NULL DEFAULT '[]',
    format_error  INTEGER NOT NULL DEFAULT 0,
    error         TEXT,
    latency_ms    INTEGER NOT NULL DEFAULT 0,
    tokens_in     INTEGER NOT NULL DEFAULT 0,
    tokens_out    INTEGER NOT NULL DEFAULT 0,
    timestamp     TEXT NOT NULL,
    -- Idempotency key: re-running a run never duplicates a call.
    UNIQUE (run_id, pair_id, model_id, prompt_id, repeat)
);

-- Every LLM call made while BUILDING the dataset (extraction agent, prompt
-- paraphrase review). Stored for the same reason as solver calls: an output
-- that was never written down cannot be audited.
CREATE TABLE IF NOT EXISTS llm_calls (
    llm_call_id TEXT PRIMARY KEY,
    purpose     TEXT NOT NULL,
    ref_id      TEXT NOT NULL DEFAULT '',
    model_id    TEXT NOT NULL,
    model_version TEXT NOT NULL,
    prompt      TEXT NOT NULL,
    raw_response TEXT NOT NULL,
    parsed      TEXT,
    error       TEXT,
    tokens_in   INTEGER NOT NULL DEFAULT 0,
    tokens_out  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);

-- --------------------------------------------------------------- derived
-- Recomputable from the raw tables; safe to rewrite, hence not append-only.
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    params      TEXT NOT NULL,
    params_hash TEXT NOT NULL,
    code_version TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- One row per model call in the analysed run. Every column that a
-- capture could not answer is NULL, and `status` plus `note` say why --
-- a 0 where the question could not be put would read as a measurement.
CREATE TABLE IF NOT EXISTS analysis_call_facts (
    analysis_id       TEXT NOT NULL REFERENCES analyses(analysis_id),
    call_id           TEXT NOT NULL REFERENCES calls(call_id),
    reexecuted_packets TEXT NOT NULL DEFAULT '[]',
    reexecuted_count  INTEGER,
    truncated         INTEGER NOT NULL DEFAULT 0,
    cited_verified    TEXT NOT NULL DEFAULT '[]',
    cited_unverified  TEXT NOT NULL DEFAULT '[]',
    fabricated_count  INTEGER,
    sufficiency_ok    INTEGER,
    necessity_ok      INTEGER,
    status            TEXT NOT NULL DEFAULT 'ok',
    note              TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (analysis_id, call_id)
);

CREATE TABLE IF NOT EXISTS analysis_metrics (
    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
    scope       TEXT NOT NULL,
    scope_id    TEXT NOT NULL,
    metric      TEXT NOT NULL,
    value       REAL,
    n           INTEGER,
    ci_low      REAL,
    ci_high     REAL,
    detail      TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (analysis_id, scope, scope_id, metric)
);

-- Did a claim's condition hold on the capture it was extracted from?
-- Derived: re-running the condition recomputes it exactly, so this is a
-- cache of an answer the capture gives, not a record of a decision.
CREATE TABLE IF NOT EXISTS claim_condition_checks (
    claim_id       TEXT NOT NULL REFERENCES claims(claim_id),
    pcap_id        TEXT NOT NULL REFERENCES pcaps(pcap_id),
    display_filter TEXT NOT NULL,
    match_count    INTEGER,
    holds          INTEGER,
    error          TEXT,
    checked_at     TEXT NOT NULL,
    PRIMARY KEY (claim_id, pcap_id)
);

-- tshark results, keyed by (capture hash, filter, limit): a cache, so it is
-- derived and may be cleared at any time without losing anything.
CREATE TABLE IF NOT EXISTS pcap_query_cache (
    cache_key  TEXT PRIMARY KEY,
    pcap_sha256 TEXT NOT NULL,
    filter     TEXT NOT NULL,
    limit_n    INTEGER NOT NULL,
    result     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_calls_run ON calls(run_id);
CREATE INDEX IF NOT EXISTS idx_calls_pair ON calls(run_id, pair_id);
CREATE INDEX IF NOT EXISTS idx_pairs_claim ON pairs(claim_id);
CREATE INDEX IF NOT EXISTS idx_claims_source ON claims(source_id);
CREATE INDEX IF NOT EXISTS idx_run_events_run ON run_events(run_id, created_at);
"""


def _append_only_triggers(tables: Iterable[str]) -> str:
    """
    One UPDATE and one DELETE trigger per raw table.

    The message is matched by the tests; it names the table so a violation
    in a future module is immediately locatable.
    """
    statements = []
    for table in tables:
        for verb in ("UPDATE", "DELETE"):
            statements.append(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{verb.lower()} "
                f"BEFORE {verb} ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'append-only: {table} rows cannot be {verb.lower()}d'); END;"
            )
    return "\n".join(statements)


class Database:
    """A connection to one dataset database."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")

    # -- lifecycle --------------------------------------------------------

    #: Columns added after a database may already exist. Adding a column is
    #: additive -- it rewrites no row -- so it is compatible with the
    #: append-only rule in a way that changing one would not be.
    _ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
        ("calls", "prompt_rendered", "TEXT NOT NULL DEFAULT ''"),
    )

    def _add_missing_columns(self) -> None:
        for table, column, definition in self._ADDED_COLUMNS:
            existing = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    #: Derived tables whose shape changed in a given schema version. They
    #: are recomputable by definition, so the migration for them is to drop
    #: and rebuild rather than to preserve rows written under an older
    #: definition -- which is exactly the licence the raw/derived split buys.
    _REBUILT_DERIVED: dict[int, tuple[str, ...]] = {
        6: ("analysis_call_facts", "analysis_metrics", "analyses"),
    }

    def _stored_schema_version(self) -> int | None:
        try:
            row = self.conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        except sqlite3.OperationalError:
            return None  # a fresh file: no meta table yet
        return int(row["value"]) if row else None

    def _rebuild_changed_derived(self, previous: int | None) -> None:
        if previous is None or previous >= SCHEMA_VERSION:
            return
        for version, tables in sorted(self._REBUILT_DERIVED.items()):
            if previous < version:
                for table in tables:
                    self.conn.execute(f"DROP TABLE IF EXISTS {table}")

    def initialise(self) -> "Database":
        with self.conn:
            self._rebuild_changed_derived(self._stored_schema_version())
            self.conn.executescript(_SCHEMA)
            self._add_missing_columns()
            self.conn.executescript(_append_only_triggers(RAW_TABLES))
            self.conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        return self

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- access -----------------------------------------------------------

    def insert(self, table: str, row: dict[str, Any]) -> None:
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        with self.conn:
            self.conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(row.values()))

    def insert_many(self, table: str, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            self.insert(table, row)

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, params))

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def count(self, table: str) -> int:
        return int(self.conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"])

    def clear_derived(self, table: str) -> None:
        """
        Wipe a derived table. Refuses a raw one -- the point of the split.
        """
        if table not in DERIVED_TABLES:
            raise ValueError(f"{table!r} is not a derived table; raw data is append-only")
        with self.conn:
            self.conn.execute(f"DELETE FROM {table}")
