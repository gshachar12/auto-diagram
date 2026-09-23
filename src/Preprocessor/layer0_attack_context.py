"""
PAnGEA — Layer 0: Attack Context Extraction.

Responsibility: translate a free-text Attack Description into a structured,
enum-constrained AttackContext object.

Design constraints:
  - This is the ONLY module that sees the Attack Description (R2 boundary).
  - Output is enum-constrained — the LLM extracts into a fixed vocabulary,
    it does not generate free text or code.
  - Deterministic: temperature=0 minimises variance across runs.
  - Graceful degradation: if extraction fails for any reason, returns an
    empty AttackContext (all fields empty). The pipeline continues with
    TF-IDF weighting only — no context_match boost, but no hard failure.
  - The pcap is NEVER passed here. AttackContext is derived solely from
    the description (avoiding circular logic and enforcing R2 isolation).
"""
from __future__ import annotations

import json
import logging
from typing import Callable, Optional

from Preprocessor.schemas import (
    AttackContext,
    SuspectedProtocol,
    SuspectedBehavior,
    TargetIndicator,
)

logger = logging.getLogger(__name__)

# Type alias matching the existing LLMClient abstraction in the codebase
LLMClient = Callable[[str], str]

# Enum vocabularies exposed to the LLM as the extraction target.
# Defined once here so the prompt and the parser stay in sync automatically.
_PROTOCOL_VALUES  = [e.value for e in SuspectedProtocol]
_BEHAVIOR_VALUES  = [e.value for e in SuspectedBehavior]
_INDICATOR_VALUES = [e.value for e in TargetIndicator]


def extract_attack_context(
    description: str,
    llm_client: Optional[LLMClient] = None,
) -> AttackContext:
    """
    Extract structured AttackContext from a free-text attack description.

    Args:
        description:  raw attack description text.
        llm_client:   optional LLM callable (prompt -> response text).
                      If None, falls back to the deterministic keyword
                      matcher — useful for testing without a live LLM.

    Returns:
        AttackContext with enum-constrained fields populated.
        On any failure, returns an empty AttackContext (all lists empty).
    """
    if not description or not description.strip():
        return AttackContext(raw_description=description)

    if llm_client is not None:
        return _extract_via_llm(description, llm_client)
    else:
        return _extract_via_keywords(description)


# ---------------------------------------------------------------------------
# LLM path
# ---------------------------------------------------------------------------

def _extract_via_llm(description: str, llm_client: LLMClient) -> AttackContext:
    prompt = _build_prompt(description)
    try:
        raw = llm_client(prompt)
    except Exception as exc:
        logger.warning("AttackContext LLM call failed (%s); returning empty context", exc)
        return AttackContext(raw_description=description)

    return _parse_llm_response(raw, description)


def _build_prompt(description: str) -> str:
    return f"""You are extracting structured metadata from a network attack description.

Your output must be a single JSON object with exactly these three keys:
  "suspected_protocols" : list of strings, each from {_PROTOCOL_VALUES}
  "suspected_behaviors" : list of strings, each from {_BEHAVIOR_VALUES}
  "target_indicators"   : list of strings, each from {_INDICATOR_VALUES}

Rules:
- Only include values you are confident apply to the description.
- Use ONLY values from the lists above — no free text, no new values.
- If nothing applies to a key, use an empty list [].
- Output ONLY the JSON object. No explanation, no markdown, no preamble.

Description:
{description}

JSON:"""


def _parse_llm_response(raw: str, description: str) -> AttackContext:
    """
    Parse the LLM's JSON response into an AttackContext.
    Validates every value against the enum vocabulary; silently drops
    any value not in the allowed set rather than raising.
    """
    cleaned = raw.strip().strip("```").strip()
    if cleaned.lower().startswith("json"):
        cleaned = cleaned[4:].strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning("AttackContext: failed to parse LLM response as JSON (%s); "
                       "raw=%r; returning empty context", exc, raw[:200])
        return AttackContext(raw_description=description)

    def _safe_enum_list(key, enum_class):
        raw_list = data.get(key, [])
        if not isinstance(raw_list, list):
            return []
        valid_values = {e.value for e in enum_class}
        result = []
        for v in raw_list:
            if v in valid_values:
                result.append(enum_class(v))
            else:
                logger.debug("AttackContext: dropping unknown %s value %r", key, v)
        return result

    return AttackContext(
        suspected_protocols=_safe_enum_list("suspected_protocols", SuspectedProtocol),
        suspected_behaviors=_safe_enum_list("suspected_behaviors", SuspectedBehavior),
        target_indicators=_safe_enum_list("target_indicators", TargetIndicator),
        raw_description=description,
    )


# ---------------------------------------------------------------------------
# Keyword fallback path (no LLM)
# ---------------------------------------------------------------------------

import re

# Each entry: (pattern, protocols, behaviors, indicators)
_KEYWORD_RULES: list[tuple[
    re.Pattern,
    list[SuspectedProtocol],
    list[SuspectedBehavior],
    list[TargetIndicator],
]] = [
    (
        re.compile(r"\bsyn\s*flood\b|\bsyn\s*attack\b", re.I),
        [SuspectedProtocol.TCP],
        [SuspectedBehavior.FLOOD, SuspectedBehavior.UNANSWERED_SYN],
        [TargetIndicator.HIGH_RATE, TargetIndicator.NO_RESPONSE, TargetIndicator.SINGLE_DST],
    ),
    (
        re.compile(r"\bping\s*flood\b|\bicmp\s*flood\b", re.I),
        [SuspectedProtocol.ICMP],
        [SuspectedBehavior.FLOOD],
        [TargetIndicator.HIGH_RATE, TargetIndicator.SINGLE_DST],
    ),
    (
        re.compile(r"\bdns\s*tunnel(l?ing)?\b", re.I),
        [SuspectedProtocol.DNS, SuspectedProtocol.UDP],
        [SuspectedBehavior.TUNNELING, SuspectedBehavior.EXFILTRATION],
        [TargetIndicator.SINGLE_DST],
    ),
    (
        re.compile(r"\bport\s*scan\b|\brecon(naissance)?\b", re.I),
        [SuspectedProtocol.TCP, SuspectedProtocol.UDP],
        [SuspectedBehavior.SCANNING],
        [TargetIndicator.SINGLE_DST, TargetIndicator.SINGLE_SRC],
    ),
    (
        re.compile(r"\barp\s*spoof\b|\barp\s*poison", re.I),
        [SuspectedProtocol.ARP],
        [SuspectedBehavior.SPOOFING],
        [TargetIndicator.SINGLE_DST],
    ),
    (
        re.compile(r"\bddos\b|\bdistributed\s*denial", re.I),
        [SuspectedProtocol.TCP, SuspectedProtocol.UDP],
        [SuspectedBehavior.FLOOD],
        [TargetIndicator.MANY_SOURCES, TargetIndicator.HIGH_RATE, TargetIndicator.SINGLE_DST],
    ),
    (
        re.compile(r"\bbeacon(ing)?\b|\bc2\b|\bcommand.and.control\b", re.I),
        [SuspectedProtocol.TCP, SuspectedProtocol.HTTP],
        [SuspectedBehavior.BEACONING],
        [TargetIndicator.SINGLE_DST],
    ),
    (
        re.compile(r"\bexfiltrat(e|ion)\b|\bdata\s*theft\b", re.I),
        [SuspectedProtocol.TCP, SuspectedProtocol.DNS],
        [SuspectedBehavior.EXFILTRATION],
        [TargetIndicator.SINGLE_SRC],
    ),
    (
        re.compile(r"\bamplif(y|ication)\b|\breflect(ion)?\b", re.I),
        [SuspectedProtocol.UDP, SuspectedProtocol.DNS],
        [SuspectedBehavior.AMPLIFICATION],
        [TargetIndicator.MANY_SOURCES, TargetIndicator.SINGLE_DST],
    ),
    (
        re.compile(r"\bssh\b", re.I),
        [SuspectedProtocol.SSH],
        [],
        [],
    ),
    (
        re.compile(r"\bhttp\b|\bweb\b", re.I),
        [SuspectedProtocol.HTTP],
        [],
        [],
    ),
    (
        re.compile(r"\btls\b|\bssl\b|\bhttps\b", re.I),
        [SuspectedProtocol.TLS],
        [],
        [],
    ),
]


def _extract_via_keywords(description: str) -> AttackContext:
    """
    Deterministic keyword matcher. OR-combines all matching rules.
    Over-inclusive by design — if uncertain, include rather than exclude.
    """
    protocols: set[SuspectedProtocol]  = set()
    behaviors: set[SuspectedBehavior]  = set()
    indicators: set[TargetIndicator]   = set()

    for pattern, proto_list, behav_list, ind_list in _KEYWORD_RULES:
        if pattern.search(description):
            protocols.update(proto_list)
            behaviors.update(behav_list)
            indicators.update(ind_list)

    return AttackContext(
        suspected_protocols=list(protocols),
        suspected_behaviors=list(behaviors),
        target_indicators=list(indicators),
        raw_description=description,
    )
