"""
Fixtures for the Dataset Creator suite.

Everything is built in a temp directory against the demo config, so the
tests never touch the repo's data/ directory and never need an API key.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from Dataset.config import CONFIG_DIR, Config
from Dataset.schemas import ModelSpec
from Dataset.storage.db import Database
from Dataset.storage.repository import Repository


@pytest.fixture
def demo_config() -> Config:
    return Config.load(CONFIG_DIR / "demo")


@pytest.fixture
def shipped_config() -> Config:
    """
    The packaged config: the pre-registration, still carrying its UNSET
    sentinels.

    Loaded without overrides on purpose. Overrides are what this deployment
    currently intends to run with and live in the data directory; reading
    them here would make these tests depend on whatever the dashboard's
    sliders were last set to.
    """
    return Config.load(apply_overrides=False)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "test.db").initialise()
    yield database
    database.close()


@pytest.fixture
def repo(db: Database, tmp_path: Path) -> Repository:
    return Repository(db, results_path=tmp_path / "results.jsonl")


@pytest.fixture
def mock_spec() -> ModelSpec:
    return ModelSpec(
        model_id="mock-a",
        family="mock-alpha",
        version="mock-alpha-1.0",
        adapter="mock",
        supports_tools=True,
        temperature=0.0,
    )
