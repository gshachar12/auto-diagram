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
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ..paths import db_path
from ..storage.db import Database
from . import views

STATIC_DIR = Path(__file__).resolve().parent / "static"


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


def create_app() -> FastAPI:
    app = FastAPI(title="PAnGEA Dataset Creator", docs_url="/api/docs", redoc_url=None)

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
    ) -> list[dict[str, Any]]:
        rows = _read(views.claims_table, run_id)
        if pair_type:
            rows = [r for r in rows if r["pair_type"] == pair_type]
        if level:
            rows = [r for r in rows if r["level"] == level]
        if flag:
            rows = [r for r in rows if flag in r["flags"]]
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
