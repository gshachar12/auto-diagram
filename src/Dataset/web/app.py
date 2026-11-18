"""
The dashboard server.

  Responsibility: serve the single-page dashboard and the JSON it reads.
  Read-only by construction -- every endpoint opens the database, queries,
  and closes it. Nothing here writes a row, so the dashboard can never
  become a way to edit raw data (the review actions in B2 will be their own
  endpoints, writing new versions rather than updates).

  It binds to loopback. Reaching it from a tablet goes through
  `tailscale serve`, which terminates TLS and proxies to this port, rather
  than through this process listening on a shared network interface.

  A connection per request rather than a pooled one: SQLite connections are
  not shareable across threads, the dataset is small, and a short-lived
  read connection cannot hold a lock open against the writers.
"""
from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ..config import Config
from ..manifest import REPO_ROOT
from ..paths import data_dir, db_path
from ..pcap import FilterError, PcapService, PcapServiceError, PcapTimeout
from ..storage.db import Database
from . import views
from .auth import COOKIE_NAME, Auth, AuthError

STATIC_DIR = Path(__file__).resolve().parent / "static"

#: Reachable without a session. The page itself is an empty shell -- it
#: holds no data and fetches everything through /api, which is gated -- so
#: serving it to an unauthenticated visitor gives nothing away and lets the
#: login form be the page's own gate rather than a redirect dance.
PUBLIC_PATHS = frozenset({"/", "/healthz", "/api/login", "/api/session", "/favicon.ico"})


def auth_store() -> Auth:
    return Auth(data_dir() / "auth.json")


def _db() -> Database:
    path = db_path()
    if not path.exists():
        raise HTTPException(status_code=503, detail=f"no dataset at {path}; run `./pangea demo` first")
    return Database(path)


def _read(fn, *args, **kwargs) -> Any:
    db = _db()
    try:
        return fn(db, *args, **kwargs)
    finally:
        db.close()


def create_app(auth: Auth | None = None) -> FastAPI:
    app = FastAPI(title="PAnGEA Dataset Creator", docs_url="/api/docs", redoc_url=None)
    app.state.auth = auth

    def current_auth() -> Auth:
        # Resolved per request rather than at import: `set-password` may run
        # while the server is up, and the next request should see it.
        return app.state.auth or auth_store()

    @app.middleware("http")
    async def require_session(request: Request, call_next):
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/static/"):
            return await call_next(request)
        store = current_auth()
        if not store.configured:
            # Fail closed: an unconfigured deployment serves no data at all.
            return JSONResponse(
                {"detail": "no password set on the server; run `./pangea set-password`", "configured": False},
                status_code=503,
            )
        if not store.check_token(request.cookies.get(COOKIE_NAME)):
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        return await call_next(request)

    @app.get("/api/session")
    def session(request: Request) -> dict[str, bool]:
        store = current_auth()
        return {
            "configured": store.configured,
            "authenticated": store.configured and store.check_token(request.cookies.get(COOKIE_NAME)),
        }

    @app.post("/api/login")
    def login(request: Request, response: Response, password: str = Body(..., embed=True)) -> dict[str, bool]:
        store = current_auth()
        client = request.client.host if request.client else "-"
        try:
            ok = store.verify_password(password, client=client)
        except AuthError as exc:
            # A lockout and an unconfigured server are different problems,
            # and the page says which rather than a generic failure.
            status = 429 if "attempts" in str(exc) else 503
            raise HTTPException(status_code=status, detail=str(exc))
        if not ok:
            raise HTTPException(status_code=401, detail="wrong password")
        response.set_cookie(
            COOKIE_NAME, store.issue_token(), httponly=True, samesite="lax",
            max_age=14 * 24 * 3600, path="/",
        )
        return {"authenticated": True}

    @app.post("/api/logout")
    def logout(response: Response) -> dict[str, bool]:
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"authenticated": False}

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/overview")
    def overview(run_id: str | None = None) -> dict[str, Any]:
        return _read(views.overview, run_id)

    @app.get("/api/claims")
    def claims(
        run_id: str | None = None,
        pair_type: str | None = None,
        level: int | None = None,
        flag: str | None = None,
        pcap_id: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = _read(views.claims_table, run_id)
        if pair_type:
            rows = [r for r in rows if r["pair_type"] == pair_type]
        if level:
            rows = [r for r in rows if r["level"] == level]
        if flag:
            rows = [r for r in rows if flag in r["flags"]]
        if pcap_id:
            # The Captures section's "its claims and pairs" link: one
            # capture, and the items derived from it.
            rows = [r for r in rows if r["pcap_id"] == pcap_id]
        return rows

    @app.get("/api/pair/{pair_id}")
    def pair(pair_id: str, run_id: str | None = None) -> dict[str, Any]:
        detail = _read(views.pair_detail, pair_id, run_id)
        if not detail:
            raise HTTPException(status_code=404, detail=f"no pair {pair_id}")
        return detail

    @app.get("/api/call/{call_id}")
    def call(call_id: str) -> dict[str, Any]:
        row = _read(views.raw_call, call_id)
        if not row:
            raise HTTPException(status_code=404, detail=f"no call {call_id}")
        return row

    @app.get("/api/sources")
    def sources() -> list[dict[str, Any]]:
        return _read(views.sources)

    @app.get("/api/source/{source_id}/steps")
    def source_steps(source_id: str) -> list[dict[str, Any]]:
        steps = _read(views.source_steps, source_id)
        if not steps:
            raise HTTPException(status_code=404, detail=f"no steps for {source_id}")
        return steps

    @app.get("/api/source/{source_id}/files")
    def source_files(source_id: str) -> list[dict[str, Any]]:
        return _read(views.source_files, source_id)

    @app.get("/api/file")
    def read_file(path: str, max_bytes: int = 400_000) -> dict[str, Any]:
        """
        Serve a text file the dataset refers to.

        The allowlist is the database itself: a path is readable only if a
        row already names it. That keeps this from becoming a way to read
        arbitrary files off the host through the dashboard, which a plain
        `?path=` endpoint otherwise is.
        """
        allowed = _read(views.readable_paths)
        if path not in allowed:
            raise HTTPException(status_code=404, detail="not a file this dataset refers to")
        resolved = (REPO_ROOT / path).resolve()
        if not resolved.is_relative_to(REPO_ROOT) or not resolved.is_file():
            raise HTTPException(status_code=404, detail="file missing on disk")
        if resolved.suffix.lower() in (".pcap", ".pcapng", ".cap"):
            raise HTTPException(status_code=415, detail="captures are read through /api/pcap/{pcap_id}")
        raw = resolved.read_bytes()[: max_bytes + 1]
        truncated = len(raw) > max_bytes
        return {
            "path": path,
            "kind": "csv" if resolved.suffix.lower() == ".csv" else "text",
            "size_bytes": resolved.stat().st_size,
            "truncated": truncated,
            "content": raw[:max_bytes].decode("utf-8", errors="replace"),
        }

    @app.get("/api/pcaps")
    def pcaps() -> dict[str, Any]:
        """
        Every registered capture and every file the dataset refers to.

        The Captures section is built from this: one list of openable
        samples, each one already named by a row in the database, which is
        also the allowlist the readers below enforce.
        """
        return _read(views.samples)

    @app.get("/api/file/download")
    def download_file(path: str):
        """
        The raw bytes of a file the dataset refers to, as a download.

        Same allowlist as the reader above -- a path is served only because
        a row already names it -- and captures are still refused: they go
        through the PCAP service, which bounds what it reads.
        """
        allowed = _read(views.readable_paths)
        if path not in allowed:
            raise HTTPException(status_code=404, detail="not a file this dataset refers to")
        resolved = (REPO_ROOT / path).resolve()
        if not resolved.is_relative_to(REPO_ROOT) or not resolved.is_file():
            raise HTTPException(status_code=404, detail="file missing on disk")
        if resolved.suffix.lower() in (".pcap", ".pcapng", ".cap"):
            raise HTTPException(status_code=415, detail="captures are read through /api/pcap/{pcap_id}")
        return FileResponse(resolved, filename=resolved.name, media_type="text/plain")

    @app.get("/api/pcap/{pcap_id}")
    def pcap(pcap_id: str, limit: int = 40) -> dict[str, Any]:
        """The registry row plus the capture's first packets."""
        db = _db()
        try:
            row = db.one("SELECT * FROM pcaps WHERE pcap_id = ?", (pcap_id,))
            if row is None:
                raise HTTPException(status_code=404, detail=f"no capture {pcap_id}")
            record = dict(row)
            record["capture_metadata"] = json.loads(record["capture_metadata"])
            try:
                service = PcapService.from_config(Config.load(), db=db)
                record["head"] = service.head(REPO_ROOT / record["path"], limit=limit)
                record["head_error"] = None
            except PcapServiceError as exc:
                # The row is still worth showing; the reason the packets are
                # missing is data too.
                record["head"] = []
                record["head_error"] = str(exc)
            return record
        finally:
            db.close()

    @app.get("/api/pcap/{pcap_id}/summary")
    def pcap_summary(pcap_id: str) -> dict[str, Any]:
        """
        The capture's own account of itself: protocols, endpoints, window.

        Reading the protocol hierarchy means dissecting every packet, so a
        capture over the configured size is told apart rather than left to
        tie up tshark while someone waits for a page.
        """
        db = _db()
        try:
            row = db.one("SELECT * FROM pcaps WHERE pcap_id = ?", (pcap_id,))
            if row is None:
                raise HTTPException(status_code=404, detail=f"no capture {pcap_id}")
            config = Config.load()
            cap_mb = float(config.get("pcap_tool.max_summary_mb", 80))
            if row["size_bytes"] > cap_mb * 1_000_000:
                return {
                    "available": False,
                    "reason": (
                        f"this capture is {row['size_bytes'] / 1e6:.0f} MB and the summary reads every "
                        f"packet; the limit is {cap_mb:.0f} MB (pcap_tool.max_summary_mb). Filters below "
                        f"still work -- they are bounded by the same timeout and output cap."
                    ),
                    "packet_count": row["packet_count"],
                    "size_bytes": row["size_bytes"],
                }
            try:
                service = PcapService.from_config(config, db=db)
                summary = service.summary(REPO_ROOT / row["path"]).as_dict()
            except PcapServiceError as exc:
                return {"available": False, "reason": str(exc), "packet_count": row["packet_count"],
                        "size_bytes": row["size_bytes"]}
            # The registry's own relative path, not the resolved one: the
            # dashboard has no use for this host's directory layout.
            return {"available": True, **summary, "path": row["path"]}
        finally:
            db.close()

    #: When the last scan was started, per capture. A display filter on a
    #: 680k-packet capture is a full read of the file, so the explorer gets
    #: a ceiling rather than an invitation to start one per keystroke.
    app.state.last_query: dict[str, float] = {}

    @app.get("/api/pcap/{pcap_id}/query")
    def pcap_query(pcap_id: str, filter: str, limit: int = 40) -> dict[str, Any]:
        db = _db()
        try:
            row = db.one("SELECT path FROM pcaps WHERE pcap_id = ?", (pcap_id,))
            if row is None:
                raise HTTPException(status_code=404, detail=f"no capture {pcap_id}")
            config = Config.load()
            per_minute = float(config.get("pcap_tool.max_queries_per_minute", 20) or 0)
            gap = (60.0 / per_minute) if per_minute > 0 else 0.0
            waited = time.monotonic() - app.state.last_query.get(pcap_id, 0.0)
            if gap and waited < gap:
                raise HTTPException(
                    status_code=429,
                    detail=f"one scan per {gap:.1f}s on a capture; {gap - waited:.1f}s to go. "
                           f"Each filter is a full read of the file.",
                )
            service = PcapService.from_config(config, db=db)
            try:
                result = service.query(REPO_ROOT / row["path"], filter, limit=limit).as_dict()
                # Only a scan that actually ran counts against the budget: a
                # filter tshark refused never touched the capture, and
                # charging for it would make a typo cost the next few seconds.
                app.state.last_query[pcap_id] = time.monotonic()
                return result
            except FilterError as exc:
                # tshark's own words, not a paraphrase and not an empty
                # table: a refused filter must never look like a result.
                raise HTTPException(status_code=400, detail=f"tshark refused this filter: {exc}")
            except PcapTimeout as exc:
                raise HTTPException(status_code=504, detail=str(exc))
            except PcapServiceError as exc:
                raise HTTPException(status_code=503, detail=str(exc))
        finally:
            db.close()

    @app.get("/api/prompts/variants")
    def prompt_variants() -> list[dict[str, Any]]:
        """Every prompt variant, with its full text."""
        db = _db()
        try:
            return [dict(row) for row in db.query("SELECT * FROM prompt_variants ORDER BY dimension, label")]
        finally:
            db.close()

    @app.get("/api/models")
    def models() -> list[dict[str, Any]]:
        """The panel as registered: who answered, which version, with tools."""
        db = _db()
        try:
            rows = [dict(row) for row in db.query("SELECT * FROM model_specs ORDER BY family, model_id")]
            for row in rows:
                row["supports_tools"] = bool(row["supports_tools"])
                row["calls"] = db.one(
                    "SELECT COUNT(*) n FROM calls WHERE model_id = ?", (row["model_id"],)
                )["n"]
            return rows
        finally:
            db.close()

    @app.get("/api/review/queue")
    def review_queue(include_reviewed: bool = False) -> dict[str, Any]:
        from ..review import queue, review_stats

        db = _db()
        try:
            return {"stats": review_stats(db), "items": queue(db, include_reviewed=include_reviewed)}
        finally:
            db.close()

    @app.post("/api/review/{claim_id}")
    def review_claim(claim_id: str, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """
        Record one review decision.

        This is the only endpoint in the web layer that writes, and it
        still never updates a row: an edit, a split or a merge appends new
        claim versions that supersede the old one.
        """
        from ..review import ReviewError, apply_action

        db = _db()
        try:
            return apply_action(
                db,
                claim_id=claim_id,
                action=body.get("action", ""),
                reviewer=body.get("reviewer") or "human",
                notes=body.get("notes") or "",
                edits=body.get("edits"),
                parts=body.get("parts"),
                merge_with=body.get("merge_with"),
            )
        except ReviewError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            db.close()

    @app.get("/api/parameters")
    def parameters() -> dict[str, Any]:
        from ..parameters import PARAMETERS, change_log, runs_with_results

        db = _db()
        try:
            config = Config.load()
            return {
                "config_hash": config.config_hash,
                "runs_with_results": runs_with_results(db),
                "unset": config.unset(),
                "parameters": [
                    {**parameter.as_dict(), "value": config.get(parameter.path)} for parameter in PARAMETERS
                ],
                "changes": change_log(db),
            }
        finally:
            db.close()

    @app.post("/api/parameters")
    def set_parameters(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """
        Move one or more pre-registered parameters.

        Allowed, and logged. Changing a threshold cannot alter a run that
        already happened -- thresholds feed the config hash, which feeds the
        run id -- but changing one *after* results exist is the failure mode
        that would invalidate the experiment, so the count of runs with
        stored calls is written into every change record.
        """
        from ..config import ConfigError, set_override
        from ..parameters import BY_PATH, record_change

        values = body.get("values") or {}
        if not isinstance(values, dict) or not values:
            raise HTTPException(status_code=400, detail="send {\"values\": {\"<path>\": <number>}}")

        db = _db()
        try:
            before = Config.load()
            applied = []
            for path, raw_value in values.items():
                parameter = BY_PATH.get(path)
                if parameter is None:
                    raise HTTPException(status_code=400, detail=f"unknown parameter {path!r}")
                try:
                    value = int(raw_value) if parameter.integer else float(raw_value)
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail=f"{path} must be a number")
                if not (parameter.minimum <= value <= parameter.maximum):
                    raise HTTPException(
                        status_code=400,
                        detail=f"{path} must be between {parameter.minimum} and {parameter.maximum}",
                    )
                old = before.get(path)
                try:
                    set_override(path, value)
                except ConfigError as exc:
                    raise HTTPException(status_code=400, detail=str(exc))
                applied.append((path, old, value))

            after = Config.load()
            for path, old, value in applied:
                record_change(
                    db, path=path, old_value=old, new_value=value,
                    config_hash_before=before.config_hash, config_hash_after=after.config_hash,
                    changed_by=body.get("changed_by") or "human", note=body.get("note") or "",
                )
            return {
                "config_hash": after.config_hash,
                "unset": after.unset(),
                "changed": [{"path": p, "from": o, "to": v} for p, o, v in applied],
            }
        finally:
            db.close()

    @app.get("/api/pairs")
    def pairs_overview() -> dict[str, Any]:
        return _read(views.pairs_overview)

    @app.get("/api/panel")
    def panel(run_id: str | None = None) -> dict[str, Any]:
        return _read(views.panel, run_id)

    @app.get("/api/prompts")
    def prompts(run_id: str | None = None) -> dict[str, Any]:
        return _read(views.prompt_sensitivity, run_id)

    @app.get("/api/controls")
    def controls(run_id: str | None = None) -> dict[str, Any]:
        return _read(views.controls, run_id)

    @app.get("/api/evidence")
    def evidence(run_id: str | None = None) -> dict[str, Any]:
        return _read(views.evidence_quality, run_id)

    @app.get("/api/export/claims.json")
    def export_json(run_id: str | None = None) -> JSONResponse:
        rows = _read(views.claims_table, run_id)
        return JSONResponse(rows, headers={"Content-Disposition": "attachment; filename=claims.json"})

    @app.get("/api/export/claims.csv")
    def export_csv(run_id: str | None = None) -> PlainTextResponse:
        rows = _read(views.claims_table, run_id)
        buffer = io.StringIO()
        if rows:
            columns = [k for k in rows[0] if k not in ("votes", "per_prompt_verdict", "flags")]
            writer = csv.DictWriter(buffer, fieldnames=columns + ["flags"], extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({**{c: row[c] for c in columns}, "flags": " ".join(row["flags"])})
        return PlainTextResponse(
            buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=claims.csv"},
        )

    # -- the analysis ----------------------------------------------------
    #
    # Reading one is read-only like everything else here. Creating one is
    # not a dashboard action: `./pangea analyze` re-executes conditions
    # against captures, which is a job with a time budget, not a request.

    @app.get("/api/analyses")
    def analyses(run_id: str | None = None) -> dict[str, Any]:
        from ..analysis import list_analyses

        db = _db()
        try:
            rows = list_analyses(db, run_id)
            return {
                "analyses": rows,
                "latest": rows[0]["analysis_id"] if rows else None,
                "note": "An analysis is identified by its run, its parameters and the analysis code "
                        "version. The same three give the same numbers, by replay test.",
            }
        finally:
            db.close()

    @app.get("/api/analysis")
    def analysis(run_id: str | None = None, analysis_id: str | None = None, scope: str | None = None,
                 metric: str | None = None) -> dict[str, Any]:
        """One stored analysis: its header and its metrics, filterable."""
        db = _db()
        try:
            context = views.analysis_context(db, run_id, analysis_id)
            if not context["analysis"]:
                raise HTTPException(status_code=404, detail="no analysis is stored; run `./pangea analyze`")
            rows = [
                {"scope": key[0], "scope_id": key[1], "metric": key[2],
                 "value": row["value"], "n": row["n"], "ci_low": row["ci_low"], "ci_high": row["ci_high"],
                 "detail": row["detail"]}
                for key, row in sorted(context["metrics"].items())
                if (scope is None or key[0] == scope) and (metric is None or key[2] == metric)
            ]
            return {"analysis": views._analysis_header(context), "metrics": rows}
        finally:
            db.close()

    @app.post("/api/analysis/what-if")
    def analysis_what_if(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """
        Recompute with different parameters and store nothing.

        The one place the dashboard runs an analysis, and it is explicitly
        not an analysis of record: the response says so, and no row is
        written. The result is returned with the stored analysis beside it
        so the caller can see exactly what the change moved.
        """
        from ..analysis import AnalysisError, what_if

        overrides = body.get("params") or body.get("overrides") or {}
        if not isinstance(overrides, dict) or not overrides:
            raise HTTPException(status_code=400, detail='send {"params": {"<name>": <value>}}')
        db = _db()
        try:
            try:
                result = what_if(db, run_id=body.get("run_id"), overrides=overrides)
            except AnalysisError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            stored = views.analysis_context(db, result.run_id)
            changes = []
            for row in result.metrics:
                before = stored["metrics"].get(row.key())
                if before is None or before["value"] != row.value:
                    changes.append(
                        {"scope": row.scope, "scope_id": row.scope_id, "metric": row.metric,
                         "stored": before["value"] if before else None, "what_if": row.value,
                         "n": row.n, "ci_low": row.ci_low, "ci_high": row.ci_high}
                    )
            return {
                "persisted": False,
                "summary": result.summary(),
                "compared_with": stored["analysis"]["analysis_id"] if stored["analysis"] else None,
                "changed": changes,
                "note": "Nothing was stored. A what-if is for asking what the numbers would look "
                        "like, not for changing what they are.",
            }
        finally:
            db.close()

    @app.get("/api/analysis/diff")
    def analysis_diff(left: str, right: str) -> dict[str, Any]:
        from ..analysis import AnalysisError, diff

        db = _db()
        try:
            return diff(db, left, right)
        except AnalysisError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        finally:
            db.close()

    # -- exports ----------------------------------------------------------
    #
    # Four things, as the spec asks: the raw answers, the derived scores,
    # the consensus table and the run snapshot. Everything is a flat table
    # keyed by ids that appear in the other three, so a spreadsheet can
    # join them back together without this server.

    def _csv(rows: list[dict[str, Any]], filename: str, columns: list[str] | None = None) -> PlainTextResponse:
        buffer = io.StringIO()
        if rows:
            fieldnames = columns or list(rows[0])
            writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({
                    key: (json.dumps(value, default=str) if isinstance(value, (dict, list)) else value)
                    for key, value in row.items() if key in fieldnames
                })
        return PlainTextResponse(
            buffer.getvalue(), media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    def _raw_answers(run_id: str | None) -> list[dict[str, Any]]:
        """Every call of the run, exactly as stored -- the raw answers."""
        db = _db()
        try:
            run = views.load_run(db, run_id)
            if not run:
                raise HTTPException(status_code=404, detail="no run stored")
            return [dict(row) for row in db.query(
                "SELECT * FROM calls WHERE run_id = ? ORDER BY call_id", (run["run_id"],))]
        finally:
            db.close()

    def _derived_scores(run_id: str | None) -> dict[str, Any]:
        """The analysis's own output: per-call facts and every metric."""
        db = _db()
        try:
            run = views.load_run(db, run_id)
            context = views.analysis_context(db, run["run_id"] if run else None)
            if not context["analysis"]:
                raise HTTPException(status_code=404, detail="no analysis stored; run `./pangea analyze`")
            analysis_id = context["analysis"]["analysis_id"]
            facts = views.load_call_facts(db, analysis_id)
            calls = {row["call_id"]: dict(row) for row in db.query(
                "SELECT call_id, pair_id, model_id, model_family, prompt_id, repeat FROM calls WHERE run_id = ?",
                (context["analysis"]["run_id"],))}
            rows = []
            for call_id, fact in sorted(facts.items()):
                rows.append({**calls.get(call_id, {"call_id": call_id}), **fact})
            metrics = [
                {"scope": key[0], "scope_id": key[1], "metric": key[2], "value": row["value"], "n": row["n"],
                 "ci_low": row["ci_low"], "ci_high": row["ci_high"], "detail": row["detail"]}
                for key, row in sorted(context["metrics"].items())
            ]
            return {"analysis": views._analysis_header(context), "call_facts": rows, "metrics": metrics}
        finally:
            db.close()

    @app.get("/api/export/calls.json")
    def export_calls_json(run_id: str | None = None) -> JSONResponse:
        return JSONResponse(_raw_answers(run_id),
                            headers={"Content-Disposition": "attachment; filename=calls.json"})

    @app.get("/api/export/calls.csv")
    def export_calls_csv(run_id: str | None = None) -> PlainTextResponse:
        return _csv(_raw_answers(run_id), "calls.csv")

    @app.get("/api/export/scores.json")
    def export_scores_json(run_id: str | None = None) -> JSONResponse:
        return JSONResponse(_derived_scores(run_id),
                            headers={"Content-Disposition": "attachment; filename=scores.json"})

    @app.get("/api/export/scores.csv")
    def export_scores_csv(run_id: str | None = None) -> PlainTextResponse:
        return _csv(_derived_scores(run_id)["call_facts"], "scores.csv")

    @app.get("/api/export/metrics.csv")
    def export_metrics_csv(run_id: str | None = None) -> PlainTextResponse:
        return _csv(_derived_scores(run_id)["metrics"], "metrics.csv")

    @app.get("/api/export/consensus.json")
    def export_consensus_json(run_id: str | None = None) -> JSONResponse:
        return JSONResponse(_read(views.claims_table, run_id),
                            headers={"Content-Disposition": "attachment; filename=consensus.json"})

    @app.get("/api/export/manifest.json")
    def export_manifest(run_id: str | None = None) -> JSONResponse:
        run = _read(views.load_run, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="no run stored")
        return JSONResponse(run, headers={"Content-Disposition": "attachment; filename=run-manifest.json"})

    @app.get("/api/manifest")
    def manifest(run_id: str | None = None) -> dict[str, Any]:
        run = _read(views.load_run, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="no run stored")
        return run

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
