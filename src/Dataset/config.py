"""
Configuration loading and freezing.

  Responsibility: read the YAML configs, refuse the ones that are not ready
  to run on, and hash what was read.

  Two rules this module exists to enforce:

    Thresholds are configuration.  delta, tau, the quantity thresholds and
      the equivalence margin are never hard-coded and never chosen after
      results are seen. They ship as the literal sentinel `UNSET`, and
      `require_frozen()` raises until the owner sets them -- so an
      unparameterised run cannot be started by accident.
    A config change is a new run.  `config_hash` goes into the run manifest;
      editing a threshold produces a different hash and therefore a
      different run, leaving the old one intact.

  API keys are not configuration: a model entry names an environment
  variable, and the value is read at call time and never stored.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .ids import content_hash
from .schemas import ModelSpec

#: Literal written in the YAML where the owner must supply a value.
UNSET = "UNSET"

CONFIG_DIR = Path(__file__).resolve().parent / "config"


class ConfigError(RuntimeError):
    """Raised for a config that cannot be used as it stands."""


def _unset_paths(node: Any, trail: str = "") -> list[str]:
    """Every dotted path in the config whose value is still the sentinel."""
    if isinstance(node, dict):
        return [p for key, value in node.items() for p in _unset_paths(value, f"{trail}.{key}" if trail else str(key))]
    if isinstance(node, list):
        return [p for i, value in enumerate(node) for p in _unset_paths(value, f"{trail}[{i}]")]
    return [trail] if node == UNSET else []


class Config:
    """
    One loaded configuration: the experiment settings plus the panel.

    Kept as plain dicts rather than a deep pydantic tree on purpose -- the
    config grows a key per milestone, and a schema that has to be edited in
    lockstep would be the thing people work around.
    """

    def __init__(self, experiment: dict[str, Any], models: dict[str, Any]) -> None:
        self.experiment = experiment
        self.models_raw = models
        self.models = [ModelSpec(**{k: v for k, v in m.items() if k != "api_key_env"}) for m in models.get("models", [])]
        self._api_key_envs = {m["model_id"]: m.get("api_key_env") for m in models.get("models", [])}

    @classmethod
    def load(cls, config_dir: str | Path | None = None) -> "Config":
        directory = Path(config_dir) if config_dir else CONFIG_DIR
        return cls(
            experiment=yaml.safe_load((directory / "experiment.yaml").read_text(encoding="utf-8")),
            models=yaml.safe_load((directory / "models.yaml").read_text(encoding="utf-8")),
        )

    # -- access -----------------------------------------------------------

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.experiment
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def model(self, model_id: str) -> ModelSpec:
        for spec in self.models:
            if spec.model_id == model_id:
                return spec
        raise ConfigError(f"no model {model_id!r} in the panel")

    def api_key(self, model_id: str) -> str | None:
        """
        Read a model's key from the environment.

        Returned to the caller for one call and never written anywhere --
        not into a manifest, a log line or a result row.
        """
        env_name = self._api_key_envs.get(model_id)
        if not env_name:
            return None
        key = os.environ.get(env_name)
        if not key:
            raise ConfigError(f"model {model_id!r} needs ${env_name}, which is not set")
        return key

    # -- freezing ---------------------------------------------------------

    def unset(self) -> list[str]:
        """Dotted paths still carrying the UNSET sentinel."""
        return sorted(_unset_paths(self.experiment))

    def require_frozen(self) -> None:
        """
        Refuse to proceed while any pre-registered parameter is missing.

        Called by the runner, not by the loaders: the dataset can be built
        and reviewed before the thresholds are chosen, but nothing may be
        *measured* until they are.
        """
        missing = self.unset()
        if missing:
            raise ConfigError(
                "these parameters must be set before a run (and must not be chosen "
                "after seeing results): " + ", ".join(missing)
            )

    @property
    def config_hash(self) -> str:
        """Hash of everything that can change a result, keys excluded."""
        return content_hash({"experiment": self.experiment, "models": self.models_raw})
