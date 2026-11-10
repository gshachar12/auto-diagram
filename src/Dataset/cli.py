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
from .steps_file import (SOURCES_DIR, json_schema, render_csv, render_markdown,
                         steps_files, validate_file)
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


def cmd_ingest(args: argparse.Namespace) -> int:
    """Register the dataset folders under pcaps/datasets/."""
    from .ingest import ingest_datasets
    from .pcap import PcapService, PcapServiceError

    db = Database(args.db).initialise()
    config = Config.load(args.config_dir)
    try:
        service = PcapService.from_config(config, db=db)
    except PcapServiceError as exc:
        print(f"warning: {exc}\n  captures will be registered without a packet count.", file=sys.stderr)
        service = None
    try:
        summary = ingest_datasets(db=db, datasets_dir=args.datasets_dir, service=service)
    finally:
        db.close()
    print(json.dumps(summary, indent=2))
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    """Run the extraction agent over the registered sources."""
    from .extraction import extract_all
    from .pcap import PcapService, PcapServiceError

    db = Database(args.db).initialise()
    config = Config.load(args.config_dir)
    try:
        service = PcapService.from_config(config, db=db)
        # Conditions are validated by a full scan of the capture, which on a
        # few hundred megabytes takes far longer than a model's tool call.
        service.timeout_seconds = args.validation_timeout
    except PcapServiceError as exc:
        print(f"warning: {exc}\n  claims will be extracted but no condition can be checked.", file=sys.stderr)
        service = None
    try:
        summary = extract_all(
            db=db, service=service,
            source_ids=[args.source] if args.source else None,
            limit_per_source=args.limit,
        )
    finally:
        db.close()
    for entry in summary["sources"]:
        print(
            f"{entry['source_id']}  steps={entry['steps_processed']:>3}  claims={entry['claims']:>3}  "
            f"conditions finding nothing={entry['claims_without_support']}"
        )
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    from .review import queue, review_stats

    db = Database(args.db)
    try:
        print(json.dumps(review_stats(db), indent=2))
        for item in queue(db)[: args.limit]:
            flags = (" [" + " ".join(item["flags"]) + "]") if item["flags"] else ""
            print(f"  L{item['level']} {item['claim_id']}  {item['atomic_text'][:72]}{flags}")
    finally:
        db.close()
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    """Which panel members could actually be called right now."""
    import httpx

    from .models.providers import ProviderError, build_adapter, list_remote_models

    config = Config.load(args.config_dir)
    if args.discover:
        # One entry per provider is enough: the catalogue is per key, not
        # per configured model.
        seen: set[str] = set()
        for spec in config.models:
            if spec.adapter == "mock" or spec.adapter in seen:
                continue
            seen.add(spec.adapter)
            raw = config.model_raw.get(spec.model_id, {})
            print(f"\n{spec.adapter}:")
            try:
                adapter = build_adapter(spec, {**raw, "model_name": raw.get("model_name") or "discover"})
                adapter.api_key()
                for name in list_remote_models(adapter):
                    print(f"  {name}")
            except (ProviderError, httpx.HTTPError) as exc:
                print(f"  unavailable: {exc}")
        return 0

    for spec in config.models:
        raw = config.model_raw.get(spec.model_id, {})
        if spec.adapter == "mock":
            state = "ready (scripted, no API call)"
        else:
            try:
                adapter = build_adapter(spec, raw)
                adapter.check_ready()
                state = f"ready ({raw.get('model_name')})"
            except ProviderError as exc:
                state = f"NOT READY -- {exc}"
        print(f"{spec.model_id:16s} {spec.family:10s} {spec.adapter:10s} {state}")
    return 0


def cmd_prompts(args: argparse.Namespace) -> int:
    from .prompts import PromptBuilder

    builder = PromptBuilder()
    print(f"prompt set version {builder.set_version}, hash {builder.set_hash[:16]}")
    for variant in builder.variants:
        print(f"  {variant.label:22s} {variant.dimension:12s} hash {builder.prompt_hash(variant)[:16]}")
    if args.show:
        rendered = builder.render(
            builder.variant(args.show),
            claim_text="<the claim goes here>",
            capture={"packet_count": 0, "closed_world": {"both_directions": None}},
            thresholds=Config.load(args.config_dir).get("thresholds"),
        )
        print("\n--- system ---\n" + rendered.system + "\n--- user ---\n" + rendered.user)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from .pcap import PcapService, PcapServiceError
    from .paths import results_path
    from .runner import RunPaused, Runner

    db = Database(args.db).initialise()
    config = Config.load(args.config_dir)
    try:
        service = PcapService.from_config(config, db=db)
    except PcapServiceError as exc:
        print(f"warning: {exc}; models will get no tool results.", file=sys.stderr)
        service = None

    runner = Runner(db=db, config=config, results_path=args.results, service=service)
    try:
        models = args.models.split(",") if args.models else None
        prompts = args.prompts.split(",") if args.prompts else None
        units = runner.plan(models=models, prompts=prompts)

        if args.pause:
            from .storage.repository import Repository

            if not args.run_id:
                print("--pause needs --run-id", file=sys.stderr)
                return 2
            Repository(db).add_run_event(args.run_id, "paused", "asked to pause")
            print(f"run {args.run_id} will stop after the call in flight")
            return 0

        # The leak gate runs before anything is sent, every time -- not
        # only in the test suite.
        leaks = runner.check_no_leaks(units)
        if leaks:
            print(f"refusing to run: {len(leaks)} rendered prompt(s) leak", file=sys.stderr)
            for problem in leaks[:5]:
                print(f"  {problem['pair_id']} / {problem['prompt']}: {problem['leaks']}", file=sys.stderr)
            return 3

        if args.dry_run:
            print(json.dumps(runner.estimate(units), indent=2))
            return 0

        run_id, _ = runner.create_run(label=args.label, units=units)
        print(f"run {run_id}: {len(units)} units planned")
        try:
            summary = runner.execute(
                run_id, units,
                min_interval_seconds=args.min_interval,
                on_progress=lambda i, n: print(f"  {i}/{n}", end="\r", flush=True),
            )
        except RunPaused as exc:
            print(f"\n{exc}")
            return 0
        print("\n" + json.dumps(summary, indent=2))
        return 0
    finally:
        db.close()


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


def cmd_set_password(args: argparse.Namespace) -> int:
    """
    Set the dashboard password.

    Read from $PANGEA_PASSWORD when set (so it can be scripted without the
    password appearing in a command line, where `ps` would show it),
    otherwise prompted for. `--generate` makes one up and prints it once.
    """
    import getpass

    from .paths import data_dir
    from .web.auth import Auth, AuthError, generate_passphrase

    store = Auth(data_dir() / "auth.json")
    if args.generate:
        password = generate_passphrase()
    elif os.environ.get("PANGEA_PASSWORD"):
        password = os.environ["PANGEA_PASSWORD"]
    else:
        password = getpass.getpass("new dashboard password: ")
        if password != getpass.getpass("repeat: "):
            print("passwords did not match", file=sys.stderr)
            return 2
    try:
        store.set_password(password)
    except AuthError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"password set in {store.path} (mode 0600)")
    if args.generate:
        print(f"\n    {password}\n")
        print("Shown once. Existing sessions on every device have been signed out.")
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
        ("dashboard password", *_password_state()),
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


def cmd_steps(args: argparse.Namespace) -> int:
    """Validate, render or print the schema for sources/<paper>/steps.json.

    `validate` is the gate: JSON is the source of truth, so a file that does
    not pass it has no business being rendered into a table someone reads.
    `render` therefore validates first and refuses to write from a bad file.
    """
    root = Path(args.repo_root) if args.repo_root else None

    if args.steps_command == "schema":
        print(json.dumps(json_schema(), indent=2))
        return 0

    paths = [Path(p) for p in args.paths] if args.paths else steps_files(root)
    if not paths:
        print(f"no steps.json found under {SOURCES_DIR}/")
        return 1

    failed = 0
    for path in paths:
        doc, problems = validate_file(path, root)
        if problems:
            failed += 1
            print(f"FAIL {path}  ({len(problems)} problem{'s' if len(problems) != 1 else ''})")
            for problem in problems:
                print(f"       {problem.where}: {problem.message}")
            continue

        assert doc is not None
        flagged = sum(1 for step in doc.steps if step.needs_review)
        found = sum(1 for step in doc.steps if step.pcap_check.status == "found")
        print(f"OK   {path}  {len(doc.steps)} steps, {found} found in the capture, "
              f"{flagged} flagged for review")

        if args.steps_command == "render":
            out = path.with_name("steps.md")
            out.write_text(render_markdown(doc), encoding="utf-8")
            print(f"       wrote {out}")
            if args.csv:
                csv_out = path.with_name("steps.csv")
                csv_out.write_text(render_csv(doc), encoding="utf-8")
                print(f"       wrote {csv_out}")

    if failed:
        print(f"\n{failed} of {len(paths)} file(s) failed validation")
    return 1 if failed else 0


def _password_state() -> tuple[str, bool]:
    from .paths import data_dir
    from .web.auth import Auth

    if Auth(data_dir() / "auth.json").configured:
        return "set", True
    return "NOT SET -- the dashboard will serve no data; run `./pangea set-password`", False


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

    ingest = sub.add_parser("ingest", help="register the dataset folders under pcaps/datasets/")
    ingest.add_argument("--datasets-dir", default="pcaps/datasets")
    ingest.set_defaults(func=cmd_ingest)

    extract = sub.add_parser("extract", help="run the extraction agent over the registered sources")
    extract.add_argument("--source", default=None, help="one source_id (default: all)")
    extract.add_argument("--limit", type=int, default=None, help="steps per source")
    extract.add_argument("--validation-timeout", type=float, default=300.0)
    extract.set_defaults(func=cmd_extract)

    review = sub.add_parser("review", help="show the claims review queue")
    review.add_argument("--limit", type=int, default=20)
    review.set_defaults(func=cmd_review)

    models_cmd = sub.add_parser("models", help="which panel members can be called")
    models_cmd.add_argument(
        "--discover", action="store_true",
        help="ask each provider which model ids it accepts (needs that provider's key)",
    )
    models_cmd.set_defaults(func=cmd_models)

    prompts_cmd = sub.add_parser("prompts", help="the frozen prompt variants")
    prompts_cmd.add_argument("--show", default=None, help="render one variant")
    prompts_cmd.set_defaults(func=cmd_prompts)

    run = sub.add_parser("run", help="run models x prompts x pairs x repeats")
    run.add_argument("--dry-run", action="store_true", help="print the plan and an estimate; call nothing")
    run.add_argument("--label", default="pilot")
    run.add_argument("--models", default=None, help="comma-separated model ids")
    run.add_argument("--prompts", default=None, help="comma-separated variant labels")
    run.add_argument("--min-interval", type=float, default=0.0, help="seconds between calls to one model")
    run.add_argument("--pause", action="store_true")
    run.add_argument("--run-id", default=None)
    run.set_defaults(func=cmd_run)

    sub.add_parser("status", help="what is stored").set_defaults(func=cmd_status)
    password = sub.add_parser("set-password", help="set the dashboard password")
    password.add_argument("--generate", action="store_true", help="generate one and print it once")
    password.set_defaults(func=cmd_set_password)

    sub.add_parser("config", help="show the configuration and what is still unset").set_defaults(func=cmd_config)
    steps = sub.add_parser("steps", help="validate and render the per-paper steps.json files")
    steps.add_argument("--repo-root", default=None, help="repository root (default: the package's)")
    steps_sub = steps.add_subparsers(dest="steps_command", required=True)
    for name, helptext in (("validate", "check every steps.json against the schema and the capture"),
                           ("render", "regenerate steps.md from steps.json")):
        one = steps_sub.add_parser(name, help=helptext)
        one.add_argument("paths", nargs="*", help="steps.json files (default: all of them)")
        if name == "render":
            one.add_argument("--csv", action="store_true", help="also derive steps.csv")
    steps_sub.add_parser("schema", help="print the JSON Schema").set_defaults(paths=[])
    steps.set_defaults(func=cmd_steps, csv=False)

    sub.add_parser("doctor", help="check the environment").set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
