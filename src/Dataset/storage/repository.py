"""
Typed accessors over the database.

  Responsibility: translate between the record types in schemas.py and the
  rows in db.py, and own the two places where the same fact is written
  twice -- a model call goes into both `calls` and the append-only
  `results.jsonl`, because the JSONL is what survives a lost database and
  what the dashboard and the exports are generated from.

  Every writer here is an append. There is no `update_*` and no `delete_*`
  by design; a correction is `add_claim(..., supersedes=old_id)`.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..ids import content_id, event_id
from ..schemas import (
    CallRecord,
    Claim,
    ModelSpec,
    Pair,
    Pcap,
    Source,
)
from .db import Database


def utc_now() -> str:
    """One timestamp format everywhere: ISO-8601, UTC, second precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


class Repository:
    """Append-only writers and the read helpers the views need."""

    def __init__(self, db: Database, results_path: str | Path | None = None) -> None:
        self.db = db
        self.results_path = Path(results_path) if results_path else None

    # -- sources and captures --------------------------------------------

    def add_source(self, source: Source) -> str:
        self.db.insert(
            "sources",
            dict(
                source_id=source.source_id,
                title=source.title,
                authors=_json(source.authors),
                venue=source.venue,
                year=source.year,
                urls=_json(source.urls),
                license=source.license,
                origin=source.origin,
                notes=source.notes,
                created_at=utc_now(),
            ),
        )
        return source.source_id

    def add_pcap(self, pcap: Pcap) -> str:
        self.db.insert(
            "pcaps",
            dict(
                pcap_id=pcap.pcap_id,
                source_id=pcap.source_id,
                path=pcap.path,
                sha256=pcap.sha256,
                size_bytes=pcap.size_bytes,
                packet_count=pcap.packet_count,
                capture_metadata=_json(pcap.capture_metadata.model_dump()),
                license=pcap.license,
                origin=pcap.origin,
                created_at=utc_now(),
            ),
        )
        return pcap.pcap_id

    def add_verification_check(
        self,
        *,
        item: str,
        status: str,
        source_id: str | None = None,
        pcap_id: str | None = None,
        notes: str = "",
        decided_by: str = "agent",
    ) -> str:
        check_id = event_id("chk")
        self.db.insert(
            "verification_checks",
            dict(
                check_id=check_id,
                source_id=source_id,
                pcap_id=pcap_id,
                item=item,
                status=status,
                notes=notes,
                decided_by=decided_by,
                created_at=utc_now(),
            ),
        )
        return check_id

    # -- claims and pairs -------------------------------------------------

    def add_claim(self, claim: Claim) -> str:
        self.db.insert(
            "claims",
            dict(
                claim_id=claim.claim_id,
                source_id=claim.source_id,
                source_location=claim.source_location,
                source_step_text=claim.source_step_text,
                atomic_text=claim.atomic_text,
                level=claim.level,
                kind=str(claim.kind),
                reason_code=str(claim.reason_code) if claim.reason_code else None,
                condition=_json(claim.condition.model_dump()) if claim.condition else None,
                mutation_of=claim.mutation_of,
                mutation_type=str(claim.mutation_type) if claim.mutation_type else None,
                provenance=str(claim.provenance),
                version=claim.version,
                supersedes=claim.supersedes,
                created_at=utc_now(),
            ),
        )
        return claim.claim_id

    def add_pair(self, pair: Pair) -> str:
        self.db.insert(
            "pairs",
            dict(
                pair_id=pair.pair_id,
                claim_id=pair.claim_id,
                pair_type=str(pair.pair_type),
                pcap_id=pair.pcap_id,
                expected=str(pair.expected) if pair.expected else None,
                expected_basis=str(pair.expected_basis),
                level=pair.level,
                notes=pair.notes,
                created_at=utc_now(),
            ),
        )
        return pair.pair_id

    def add_discard(self, *, kind: str, ref_id: str, reason: str, details: dict[str, Any] | None = None) -> str:
        discard_id = event_id("dsc")
        self.db.insert(
            "discards",
            dict(
                discard_id=discard_id,
                kind=kind,
                ref_id=ref_id,
                reason=reason,
                details=_json(details or {}),
                created_at=utc_now(),
            ),
        )
        return discard_id

    # -- panel, runs and calls -------------------------------------------

    def add_model_spec(self, spec: ModelSpec) -> str:
        self.db.insert(
            "model_specs",
            dict(
                model_id=spec.model_id,
                family=spec.family,
                version=spec.version,
                adapter=spec.adapter,
                supports_tools=int(spec.supports_tools),
                temperature=spec.temperature,
                max_output_tokens=spec.max_output_tokens,
                created_at=utc_now(),
            ),
        )
        return spec.model_id

    def add_run(self, run_id: str, manifest: dict[str, Any]) -> str:
        self.db.insert("runs", dict(run_id=run_id, manifest=_json(manifest), created_at=utc_now()))
        self.add_run_event(run_id, "created")
        return run_id

    def add_run_event(self, run_id: str, status: str, detail: str = "") -> str:
        # Named `row_id` rather than `event_id`: the latter is the helper
        # this calls, and shadowing it made every run event raise.
        row_id = event_id("evt")
        self.db.insert(
            "run_events",
            dict(event_id=row_id, run_id=run_id, status=status, detail=detail, created_at=utc_now()),
        )
        return row_id

    def run_status(self, run_id: str) -> str | None:
        row = self.db.one(
            "SELECT status FROM run_events WHERE run_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (run_id,),
        )
        return row["status"] if row else None

    def add_call(self, call: CallRecord) -> str:
        """
        Store one model call, in the database and in results.jsonl.

        The JSONL line is written first: if the process dies between the two
        writes, the surviving artefact is the one that carries the raw
        response, and the database can be rebuilt from it.
        """
        payload = call.model_dump()
        if self.results_path is not None:
            self.results_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.results_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
        self.db.insert(
            "calls",
            dict(
                call_id=call.call_id,
                run_id=call.run_id,
                pair_id=call.pair_id,
                model_id=call.model_id,
                model_family=call.model_family,
                model_version=call.model_version,
                prompt_id=call.prompt_id,
                prompt_hash=call.prompt_hash,
                prompt_rendered=call.prompt_rendered,
                repeat=call.repeat,
                temperature=call.temperature,
                raw_response=call.raw_response,
                parsed=_json(call.parsed) if call.parsed is not None else None,
                tool_calls=_json(call.tool_calls),
                format_error=int(call.format_error),
                error=call.error,
                latency_ms=call.latency_ms,
                tokens_in=call.tokens_in,
                tokens_out=call.tokens_out,
                timestamp=call.timestamp or utc_now(),
            ),
        )
        return call.call_id

    def add_llm_call(
        self,
        *,
        purpose: str,
        model_id: str,
        model_version: str,
        prompt: str,
        raw_response: str,
        ref_id: str = "",
        parsed: Any = None,
        error: str | None = None,
        tokens_in: int = 0,
        tokens_out: int = 0,
    ) -> str:
        llm_call_id = event_id("llm")
        self.db.insert(
            "llm_calls",
            dict(
                llm_call_id=llm_call_id,
                purpose=purpose,
                ref_id=ref_id,
                model_id=model_id,
                model_version=model_version,
                prompt=prompt,
                raw_response=raw_response,
                parsed=_json(parsed) if parsed is not None else None,
                error=error,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                created_at=utc_now(),
            ),
        )
        return llm_call_id

    # -- reads ------------------------------------------------------------

    def pairs(self, pair_type: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM pairs"
        params: tuple[Any, ...] = ()
        if pair_type:
            sql += " WHERE pair_type = ?"
            params = (pair_type,)
        return [dict(row) for row in self.db.query(sql + " ORDER BY pair_id", params)]

    def calls(self, run_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.db.query("SELECT * FROM calls WHERE run_id = ? ORDER BY call_id", (run_id,))]

    def counts(self) -> dict[str, int]:
        tables = ("sources", "pcaps", "claims", "pairs", "runs", "calls", "discards", "llm_calls")
        return {table: self.db.count(table) for table in tables}


def read_results_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """Stream results.jsonl. One malformed line must not hide the rest."""
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                yield {"_parse_error": str(exc), "_line_number": number, "_raw": line}
