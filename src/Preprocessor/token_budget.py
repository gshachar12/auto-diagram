"""
PAnGEA — Token estimation for budget tracking (R5).

Uses a real tokenizer if available (tiktoken), falling back to a
chars-per-token heuristic otherwise. Either way, this is an ESTIMATE, not
an exact count — callers should apply a safety margin when computing the
budget passed into the Reducer (see prior spec discussion: available budget
= model context window − system prompt − description − expected output −
safety margin). The Reducer only sees the final number, never the components.
"""
from __future__ import annotations

try:
    import tiktoken
    _ENCODING = tiktoken.get_encoding("cl100k_base")
except Exception:
    _ENCODING = None

# Fallback heuristic: ~4 chars per token for English/technical text.
_CHARS_PER_TOKEN = 4.0


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    if _ENCODING is not None:
        return len(_ENCODING.encode(text))
    return max(1, int(len(text) / _CHARS_PER_TOKEN))


def estimate_item_tokens(item_dict: dict) -> int:
    """Rough token cost of a single reduced-representation item once serialized."""
    # Cheap approximation: stringify and estimate, rather than a full JSON
    # dump per item on every packet (perf-sensitive inner loop).
    approx_str = str(item_dict)
    return estimate_tokens(approx_str)
