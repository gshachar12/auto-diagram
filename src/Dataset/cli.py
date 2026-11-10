"""
Command line entry point.

  Responsibility: the handful of operations that are useful before a server
  exists -- create the database, seed the demo dataset, show what is stored
  and report whether the environment can actually run the experiment.

  `demo` refuses to write into an existing database rather than topping it
  up: raw tables are append-only, so a second seed would leave two
  overlapping datasets in one file with no way to tell them apart. Deleting
  the file is an explicit act (--force), not a silent one.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .config import CONFIG_DIR, Config
from .demo import seed_demo
from .manifest import git_commit
from .paths import data_dir, db_path, results_path
from .storage.db import Database
from .storage.repository import Repository


def _resolve_tshark() -> str | None:
    """PANGEA_TSHARK, then the config, then PATH. Mirrors the PCAP service."""
    candidate = os.environ.get("PANGEA_TSHARK") or Config.load().get("pcap_tool.tshark_path")
    if candidate and Path(candidate).exists():
        return str(candidate)
    return shutil.which("tshark")


def cmd_init(args: argparse.Namespace) -> int:
    Database(args.db).initialise().close()
    print(f"initialised {args.db}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    db_file, results_file = Path(args.db), Path(args.results)
    if db_file.exists() or results_file.exists():
        if not args.force:
            print(
                f"refusing to seed on top of existing data ({db_file}).\n"
                "Raw tables are append-only, so re-seeding would merge two datasets.\n"
                "Pass --force to delete and rebuild.",
                file=sys.stderr,
            )
            return 2
        db_file.unlink(missing_ok=True)
        results_file.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            Path(str(db_file) + suffix).unlink(missing_ok=True)

    # The demo needs thresholds to exist at all, so it defaults to the demo
    # config. An explicit --config-dir still wins.
    config = Config.load(args.config_dir or CONFIG_DIR / "demo")
    summary = seed_demo(db_path=db_file, results_path=results_file, config=config, seed=args.seed)
    print(json.dumps(summary, indent=2))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    if not Path(args.db).exists():
        print(f"no database at {args.db}; run `pangea demo` first", file=sys.stderr)
        return 2
    db = Database(args.db)
    repo = Repository(db)
    print(f"database: {args.db}")
    print("counts:  " + ", ".join(f"{k}={v}" for k, v in repo.counts().items()))
    for row in db.query("SELECT run_id, created_at FROM runs ORDER BY created_at"):
        manifest = json.loads(db.one("SELECT manifest FROM runs WHERE run_id = ?", (row["run_id"],))["manifest"])
        print(
            f"run {row['run_id']}  label={manifest.get('label','')!r}  "
            f"status={repo.run_status(row['run_id'])}  "
            f"calls={db.one('SELECT COUNT(*) n FROM calls WHERE run_id = ?', (row['run_id'],))['n']}  "
            f"git={manifest['code']['git_commit'][:12]}"
        )
    db.close()
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    config = Config.load(args.config_dir)
    print(f"config dir:  {args.config_dir or CONFIG_DIR}")
    print(f"config hash: {config.config_hash}")
    print(f"models:      {', '.join(m.model_id + ' (' + m.family + ')' for m in config.models)}")
    unset = config.unset()
    if unset:
        print("NOT READY TO RUN -- these must be set by the project owner first:")
        for path in unset:
            print(f"  {path}")
    else:
        print("all pre-registered parameters are set")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check the things that silently break this experiment on a new host."""
    tshark = _resolve_tshark()
    version = ""
    if tshark:
        try:
            version = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=15).stdout.splitlines()[0]
        except (subprocess.SubprocessError, OSError, IndexError) as exc:
            version = f"present but not runnable: {exc}"
    checks = [
        ("python", sys.version.split()[0], True),
        ("git commit", git_commit(), True),
        ("tshark", version or "NOT FOUND -- the PCAP service cannot run", bool(tshark)),
        ("data dir", str(data_dir()), True),
    ]
    width = max(len(name) for name, _, _ in checks)
    for name, detail, ok in checks:
        print(f"[{'ok' if ok else '!!'}] {name:<{width}}  {detail}")
    return 0 if all(ok for _, _, ok in checks) else 1


def cmd_serve(args: argparse.Namespace) -> int:
    """
    Run the dashboard.

    Binds loopback by default and refuses a non-loopback bind without
    --i-know: this host sits on a shared tailnet, and the right way to reach
    the dashboard from a tablet is `tailscale serve` proxying to this port,
    not a socket open to every machine on the network.
    """
    import uvicorn

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.i_know:
        print(
            f"refusing to bind {args.host}: that exposes the dashboard to the whole network.\n"
            "Use `tailscale serve` to reach it from another device, or pass --i-know.",
            file=sys.stderr,
        )
        return 2
    print(f"dashboard on http://{args.host}:{args.port}  (db: {args.db})")
    uvicorn.run("Dataset.web.app:app", host=args.host, port=args.port, reload=args.reload, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pangea", description="PAnGEA Dataset Creator")
    parser.add_argument("--db", default=str(db_path()), help="dataset database (default: %(default)s)")
    parser.add_argument("--results", default=str(results_path()), help="append-only results.jsonl")
    parser.add_argument("--config-dir", default=None, help="configuration directory (default: the package's config/)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create an empty database").set_defaults(func=cmd_init)

    demo = sub.add_parser("demo", help="seed the reproducible demo dataset (MockModel, no API calls)")
    demo.add_argument("--seed", type=int, default=None)
    demo.add_argument("--force", action="store_true", help="delete an existing database first")
    demo.set_defaults(func=cmd_demo)

    serve = sub.add_parser("serve", help="run the dashboard")
    serve.add_argument("--port", type=int, default=8800)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--reload", action="store_true")
    serve.add_argument("--i-know", action="store_true", help="allow a non-loopback bind")
    serve.set_defaults(func=cmd_serve)

    sub.add_parser("status", help="what is stored").set_defaults(func=cmd_status)
    sub.add_parser("config", help="show the configuration and what is still unset").set_defaults(func=cmd_config)
    sub.add_parser("doctor", help="check the environment").set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
