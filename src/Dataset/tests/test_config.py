"""
Thresholds are pre-registered parameters, so the config layer has one job
beyond loading: refusing to let a run start before they are chosen.
"""
from __future__ import annotations

import pytest
import yaml

from Dataset.config import Config, ConfigError


def test_shipped_config_still_has_unset_thresholds(shipped_config):
    # If this ever starts failing, someone has filled in delta/tau/N. That is
    # the owner's decision to record in git, not something to slip into a run.
    unset = shipped_config.unset()
    assert "thresholds.delta_seconds" in unset
    assert "thresholds.tau_seconds" in unset
    assert "thresholds.equivalence_margin.flip_rate" in unset


def test_shipped_config_refuses_to_run(shipped_config):
    with pytest.raises(ConfigError) as error:
        shipped_config.require_frozen()
    assert "thresholds.delta_seconds" in str(error.value)


def test_demo_config_is_complete(demo_config):
    assert demo_config.unset() == []
    demo_config.require_frozen()


def test_config_hash_changes_with_any_threshold(demo_config, tmp_path):
    before = demo_config.config_hash
    changed = Config(
        experiment={**demo_config.experiment, "thresholds": {**demo_config.experiment["thresholds"], "tau_seconds": 99}},
        models=demo_config.models_raw,
    )
    assert changed.config_hash != before


def test_api_keys_are_read_from_the_environment_not_stored(tmp_path, monkeypatch):
    (tmp_path / "experiment.yaml").write_text("config_version: 1\n", encoding="utf-8")
    (tmp_path / "models.yaml").write_text(
        yaml.safe_dump(
            {
                "models": [
                    {
                        "model_id": "x",
                        "family": "f",
                        "version": "v1",
                        "adapter": "http",
                        "supports_tools": True,
                        "temperature": 0.0,
                        "api_key_env": "PANGEA_TEST_KEY",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config = Config.load(tmp_path)

    monkeypatch.setenv("PANGEA_TEST_KEY", "secret-value")
    assert config.api_key("x") == "secret-value"
    # The key must not reach anything that gets written down.
    assert "secret-value" not in config.config_hash
    assert "secret-value" not in str(config.models_raw)
    assert "secret-value" not in str(config.models)

    monkeypatch.delenv("PANGEA_TEST_KEY")
    with pytest.raises(ConfigError):
        config.api_key("x")
