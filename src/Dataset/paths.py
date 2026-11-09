"""
Where the dataset's files live.

  One place that answers "which database, which results file", so the CLI,
  the service and the tests cannot disagree. PANGEA_DATA_DIR overrides the
  default, which keeps generated data out of the repo (data/ is gitignored)
  and lets a test redirect everything into a temp directory.
"""
from __future__ import annotations

import os
from pathlib import Path

from .manifest import REPO_ROOT


def data_dir() -> Path:
    return Path(os.environ.get("PANGEA_DATA_DIR") or REPO_ROOT / "data" / "dataset")


def db_path() -> Path:
    return data_dir() / "dataset.db"


def results_path() -> Path:
    return data_dir() / "results.jsonl"
