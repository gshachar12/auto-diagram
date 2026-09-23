"""
Filter Generator (Preprocessing sub-component).

Responsibility: translate a free-text Attack Description into a coarse BPF
filter, narrowing scope before the Reducer's structural work.

This is the ONLY component in Preprocessing that sees the Attack
Description — that's the whole point of the R2 boundary. Its output
(a plain filter string) is what crosses into the Reducer, never the
description itself.

Design constraints (per spec discussion):
  - Should be biased toward OVER-inclusion. A too-narrow filter silently
    drops traffic with no trace at all — a worse failure mode than the
    Reducer's compression, which at least leaves aggregate stats behind.
  - Should degrade gracefully: if the description is too vague to infer a
    meaningful scope, fall back to a no-op filter (match everything) rather
    than guessing narrowly.

For the POC, this ships with a pluggable `llm_client` callable so it can run
against any model backend, plus a deterministic keyword-based fallback so
the rest of the pipeline is testable without any live LLM call.
"""
from __future__ import annotations

import logging
import re
import subprocess
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# A conservative, over-inclusive default: never filters anything out.
NO_OP_FILTER = "ip or arp"

# Keyword -> BPF fragment, used only by the deterministic fallback generator.
# Deliberately coarse (protocol/port level), matching the "over-inclusive by
# design" requirement — this is NOT meant to be a precise classifier.
_KEYWORD_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bdns\b|\btunnel(l)?ing\b", re.I), "udp port 53 or tcp port 53"),
    (re.compile(r"\bhttp\b|\bweb\b", re.I), "tcp port 80 or tcp port 443"),
    (re.compile(r"\bscan\b|\brecon", re.I), "tcp"),
    (re.compile(r"\barp\b|\bspoof", re.I), "arp"),
    (re.compile(r"\bicmp\b|\bping\b", re.I), "icmp"),
    (re.compile(r"\bsmb\b|\b445\b", re.I), "tcp port 445"),
    (re.compile(r"\bssh\b", re.I), "tcp port 22"),
]

# prompt -> raw filter string response. Any backend (OpenAI, Anthropic,
# local model, ...) can be plugged in as long as it conforms to this shape —
# this abstraction is what keeps generate_filter() backend-agnostic.
LLMClient = Callable[[str], str]


def generate_filter(
    attack_description: str,
    llm_client: Optional[LLMClient] = None,
) -> str:
    """
    Produce a BPF filter string from a free-text description.
    
    Args:
        attack_description: the raw text. This function is the only place
            in Preprocessing allowed to see it.
        llm_client: optional callable (prompt -> response text). If not
            provided, falls back to the deterministic keyword matcher below.

    Returns:
        A BPF filter string, syntactically validated against tcpdump before
        being returned. Falls back to NO_OP_FILTER if nothing can be
        inferred, if the LLM call fails, or if the result doesn't compile
        as a valid BPF expression — matching the "over-inclusive and
        gracefully-degrading by default" requirement.
    """
    if not attack_description or not attack_description.strip():
        return NO_OP_FILTER

    if llm_client is not None:
        candidate = _generate_via_llm(attack_description, llm_client)
    else:
        candidate = _generate_via_keywords(attack_description)

    if not _is_valid_bpf(candidate):
        logger.warning(
            "Filter Generator produced an invalid BPF expression (%r); "
            "falling back to NO_OP_FILTER", candidate,
        )
        return NO_OP_FILTER

    return candidate


def _generate_via_llm(attack_description: str, llm_client: LLMClient) -> str:
    prompt = _build_prompt(attack_description)
    try:
        raw = llm_client(prompt).strip()
    except Exception as e:
        # LLM call failed — degrade to the safe default rather than
        # propagating an exception that would stall the whole pipeline.
        logger.warning("Filter Generator LLM call failed: %s", e)
        return NO_OP_FILTER

    return _extract_filter_from_response(raw)


def _build_prompt(attack_description: str) -> str:
    return (
        "You are generating a coarse BPF (Berkeley Packet Filter) capture "
        "filter to narrow a PCAP before detailed analysis.\n\n"
        "Rules:\n"
        "- Bias toward OVER-inclusion. If uncertain between two protocol "
        "scopes, include both. A too-narrow filter silently discards "
        "traffic with no way to recover it later.\n"
        "- Output ONLY a valid BPF filter expression, nothing else. No "
        "explanation, no markdown, no quotes.\n"
        "- If the description gives no usable protocol/port signal at all, "
        f"output exactly: {NO_OP_FILTER}\n\n"
        f"Description:\n{attack_description}\n\nBPF filter:"
    )


def _extract_filter_from_response(raw: str) -> str:
    # Strip common wrapping the model might add despite instructions.
    cleaned = raw.strip().strip("`").strip()
    if cleaned.lower().startswith("bpf filter:"):
        cleaned = cleaned.split(":", 1)[1].strip()
    return cleaned or NO_OP_FILTER


def _generate_via_keywords(attack_description: str) -> str:
    """Deterministic fallback: OR together every matching keyword hint.
    Over-inclusive by construction (multiple matches combine with `or`)."""
    fragments = [
        bpf for pattern, bpf in _KEYWORD_HINTS
        if pattern.search(attack_description)
    ]
    if not fragments:
        return NO_OP_FILTER
    unique_fragments = list(dict.fromkeys(fragments))  # de-dupe, preserve order
    return " or ".join(f"({frag})" for frag in unique_fragments)


def _is_valid_bpf(filter_string: str) -> bool:
    """Syntactic validation using tcpdump's compile-only mode (-d).

    Catches malformed filters here, at generation time, rather than
    discovering the failure downstream in the Reducer (which currently
    degrades to unfiltered on a bad filter — better to never hand it a bad
    filter in the first place).
    """
    if not filter_string or not filter_string.strip():
        return False
    try: 
        result = subprocess.run(
            ["tcpdump", "-d", filter_string],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # If tcpdump itself is unavailable/hangs, don't block the pipeline
        # on a validation step that can't run — treat as unvalidated-but-
        # accepted rather than failing generation entirely.
        logger.warning("Could not validate BPF filter (tcpdump unavailable); "
                        "accepting %r unvalidated", filter_string)
        return True





def main():
    
    # --------------------------------------------------------------------------
    # Example: wiring an OpenAI backend through the LLMClient abstraction.
    # Kept separate from the core module logic so the module has no hard
    # dependency on the openai package unless this path is actually used.
    # --------------------------------------------------------------------------

    def make_openai_client(api_key: str, model: str) -> LLMClient:
        """Returns an LLMClient callable backed by the OpenAI Responses API."""
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        def _call(prompt: str) -> str:
            response = client.responses.create(
                model=model,
                input=prompt,
            )
            return response.output_text

        return _call

    import os

    logging.basicConfig(level=logging.INFO)
    with open("example_attack_description.txt") as f:
        attack_desc = f.read().strip()

    api_key = os.environ.get("OPENAI_API_KEY")
    print(f"\nOPENAI_API_KEY: {'set' if api_key else 'not set'}")
    
    if api_key:
        print("\n--- LLM-backed ---")
        client = make_openai_client(api_key, model="gpt-5")
    
        print(generate_filter(attack_desc, llm_client=client))
    else:
        print("\n(set OPENAI_API_KEY to also test the LLM-backed path)")


if __name__ == "__main__":
    main()