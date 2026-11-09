"""
Run manifests.

  Responsibility: write down, before a run starts, everything that could
  change its results -- the code it ran, the config it read, the prompts it
  rendered, the models it called and the captures it read.

  A manifest is what makes "why this number?" answerable months later. It is
  built once, stored with the run, and never edited: a different manifest is
  a different run.

  `git_commit` carries a `-dirty` suffix when the working tree has
  uncommitted changes, because a run from an unrecorded edit is not
  reproducible and saying so is more useful than a clean-looking lie.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .ids import content_id, file_sha256
from .storage.repository import utc_now

REPO_ROOT = Path(__file__).resolve().parents[2]


def git_commit(repo_root: Path | None = None) -> str:
    """The current commit, marked dirty if the tree has local changes."""
    root = repo_root or REPO_ROOT
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return "UNKNOWN"
    return f"{commit}-dirty" if status else commit


def build_manifest(
    *,
    config: Config,
    pcaps: list[dict[str, Any]],
    prompts: list[dict[str, Any]],
    models: list[dict[str, Any]],
    label: str = "",
    repo_root: Path | None = None,
) -> tuple[str, dict[str, Any]]:
    """
    Build (run_id, manifest). The run id is derived from the manifest, so
    two runs with identical inputs collide by design -- which is how a
    resumed run finds its own rows again.
    """
    manifest = {
        "label": label,
        "created_at": utc_now(),
        "code": {"dataset_version": __version__, "git_commit": git_commit(repo_root)},
        "config": {
            "config_hash": config.config_hash,
            "config_version": config.get("config_version"),
            "thresholds": config.get("thresholds"),
            "run": config.get("run"),
            "pcap_tool": config.get("pcap_tool"),
            "analysis": config.get("analysis"),
        },
        "pcaps": sorted(
            [{"pcap_id": p["pcap_id"], "sha256": p["sha256"], "packet_count": p.get("packet_count")} for p in pcaps],
            key=lambda p: p["pcap_id"],
        ),
        "prompts": sorted(
            [{"prompt_id": p["prompt_id"], "prompt_hash": p["prompt_hash"]} for p in prompts],
            key=lambda p: p["prompt_id"],
        ),
        "models": sorted(
            [
                {
                    "model_id": m["model_id"],
                    "family": m["family"],
                    "version": m["version"],
                    "temperature": m["temperature"],
                    "supports_tools": bool(m["supports_tools"]),
                }
                for m in models
            ],
            key=lambda m: m["model_id"],
        ),
    }
    # The timestamp is excluded from the id: the same inputs must produce the
    # same run_id whether they are assembled now or tomorrow.
    identity = {k: v for k, v in manifest.items() if k != "created_at"}
    return content_id("run", identity), manifest


def pcap_fingerprint(path: str | Path) -> dict[str, Any]:
    """Hash and size of a capture, for the registry and the manifest."""
    file_path = Path(path)
    return {"path": str(file_path), "sha256": file_sha256(file_path), "size_bytes": file_path.stat().st_size}
