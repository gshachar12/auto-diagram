"""
PAnGEA — Validator shared models.

No numeric confidence/suspicion score, for the same reason as the
Grounder's models (see grounder/models.py): a heuristic-derived score
isn't indicative of anything until it's been checked against labeled
ground truth, which is the Evaluator's job, not the Validator's. Flags
carry a reason string instead.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ExtractionFlag:
    """A suspected Extractor failure -- Step Extractor either invented a
    step not supported by the source text (FP) or missed a step that is
    present in the text (FN).

    related_actors/candidate_evidence_refs added after real testing showed
    an FN flag with only step_id=None and a text_span is not actionable --
    it tells you WHAT was missed but not WHERE to look to fix it or verify
    it. For an FN, the Validator now attempts a speculative mini-grounding
    of the missed content itself: which already-resolved actor(s) does it
    plausibly involve, and does anything in the evidence summary look like
    it could support it, if it had been extracted as a real step."""
    kind: str          # "fp" or "fn"
    step_id: str | None    # populated for fp (the invented step); None for fn
    text_span: str | None  # populated for fn (the missed span of source text); None for fp
    reason: str
    related_actors: list[str] = field(default_factory=list)       # fn only -- best-guess actor_ids this text concerns
    candidate_evidence_refs: list[str] = field(default_factory=list)  # fn only -- fingerprint_keys that might support it, if any found


@dataclass
class LinkageFlag:
    """A suspected Evidence Matcher failure -- a step's grounding.status
    doesn't actually match what the evidence supports (FP: marked grounded
    but shouldn't be; FN: marked unsupported/uncertain but evidence exists
    that was missed)."""
    kind: str          # "fp" or "fn"
    step_id: str
    reason: str
    candidate_evidence_ref: str | None = None  # for fn: a fingerprint_key that may have been missed
    currently_linked_evidence: list[str] = field(default_factory=list)  # for fp: what WAS linked, so the flag is directly checkable


@dataclass
class ValidatorAssessment:
    extraction_flags: list[ExtractionFlag] = field(default_factory=list)
    linkage_flags: list[LinkageFlag] = field(default_factory=list)
    total_steps_reviewed: int = 0