"""Model adapters: one provider-agnostic interface, plus the MockModel."""
from __future__ import annotations

from .base import ModelAdapter, ModelRequest, ModelResult, ParsedAnswer, parse_answer  # noqa: F401
from .mock import MockModel, ScriptedBehaviour  # noqa: F401
