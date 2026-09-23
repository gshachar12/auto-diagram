"""
Validator.

  Responsibility: independent QA on the Grounder's output. Does NOT
  re-derive claims or grounding from scratch -- checks whether the
  Grounder (Step Extractor + Evidence Matcher) did its job faithfully.

  Checks "did the Grounder do its job correctly?" -- NOT "is the user's
  description accurate?". That second question is already answered by the
  Grounder itself: a step marked `unsupported` IS the system's finding
  that the description made an unsupported claim. The Validator doesn't
  repeat that judgment; it only checks whether the Grounder's judgment
  (whatever it was) is trustworthy.

  Two independent failure surfaces, checked together in one LLM call for
  the POC (their inputs overlap enough that splitting into two calls
  isn't justified yet -- see the module note below):

    Extraction fidelity  -- did Step Extractor invent steps not in the
                             source text (FP), or miss steps that are (FN)?
                             Text-only judgment; does not need the evidence.
    Linkage fidelity     -- did Evidence Matcher's grounding.status for
                             each step actually match what the evidence
                             supports? FP: marked grounded but shouldn't be
                             (the "hidden hallucination" case -- a
                             structural match that isn't a real match). FN:
                             marked unsupported/uncertain but evidence
                             exists that was missed.

  This component is always LLM-based -- there's no algorithmic substitute
  for judging text-fidelity or evidence-relevance (same reasoning as Step
  Extractor: these require semantic understanding, not lookup). Unlike
  Evidence Matcher's step grounding, there's no algorithmic-first path
  here to fall back to.

  Depends on grounder.models (GroundedStep, Actor, ...) deliberately --
  Validator's entire job is reviewing the Grounder's output, so depending
  on its output types is the actual point, not a boundary violation like
  Preprocessing/Grounder coupling would be (see evidence_matcher.py's
  docstring for that distinction). Validator does NOT depend on
  preprocessing at all, same as Evidence Matcher -- it only needs the
  generic EvidenceItem/EvidenceAggregate shapes, adapted upstream by the
  orchestrator.

  NOTE on confidence: no numeric confidence/suspicion score, for the same
  reason as the Grounder (see grounder/models.py and validator/models.py).

  NOTE on actionability (fixed after real testing): an ex_fn flag that
  only names the missed text span, with no pointer to which actor or
  which evidence it concerns, is not actionable -- confirmed directly: a
  real run against a DNS-tunneling scenario produced four ex_fn flags that
  each said only "this text was missed," with step_id=null and no other
  pointer back into the pipeline. Ex_fn flags now also carry
  related_actors and candidate_evidence_refs (a genuine, evidence-aware
  attempt at grounding the omission itself); ma_fp flags now also carry
  currently_linked_evidence, so a flag is directly checkable against what
  was actually linked rather than only described.
"""
from __future__ import annotations

import logging
from typing import Optional

try:
    from .models import ExtractionFlag, LinkageFlag, ValidatorAssessment
except ImportError:
    from models import ExtractionFlag, LinkageFlag, ValidatorAssessment

try:
    from shared.llm_client import LLMClient
except ImportError:
    from ..shared.llm_client import LLMClient

try:
    from Grounder.models import Actor, GroundedStep, EvidenceItem, EvidenceAggregate
except ImportError:
    from ..Grounder.models import Actor, GroundedStep, EvidenceItem, EvidenceAggregate

logger = logging.getLogger(__name__)


VALIDATOR_SYSTEM_PROMPT = """\
You are the Validator stage of a network-traffic grounding pipeline. Your
job is QA on a prior stage's work -- NOT re-deriving claims or grounding
from scratch, and NOT judging whether the original description itself was
accurate (that question is already answered by each step's grounding
status; a step marked "unsupported" is already the system's finding that
the description overclaimed).

You check two independent things:

1. EXTRACTION FIDELITY (text-only for the initial judgment, evidence-aware
   for follow-up on ex_fn -- see below):
   Compare the original description against the extracted steps.
   - Flag "ex_fp" if a step exists that isn't actually supported by the
     source text -- i.e. Step Extractor invented or over-interpreted
     something not stated.
   - Flag "ex_fn" if the source text contains a meaningful statement with
     no corresponding step at all -- i.e. Step Extractor dropped something
     it should have captured. Reference the specific text span missed.

     An ex_fn flag that ONLY names the missed text is not actionable on
     its own -- it does not say where in the pipeline to look to fix or
     verify it. For EVERY ex_fn flag, ALSO provide:
       - related_actors: which of the RESOLVED ACTORS listed below this
         missed text plausibly concerns (by actor_id). Use the actors'
         roles/resolved IPs to judge this from the text itself, not from
         any step that already references them.
       - candidate_evidence_refs: scan the EVIDENCE OVERVIEW below for any
         fingerprint_key that looks like it could plausibly support this
         missed text, if it had been extracted as a real step (e.g. a
         missed claim about "network configuration returned by the
         server" plausibly corresponds to a UDP:53 or similar fingerprint
         between the same two hosts already mentioned in the text). This
         is a genuine attempt at grounding the omission itself, not a
         guess -- return an empty list if nothing in the evidence overview
         plausibly matches, rather than forcing a match.

2. LINKAGE FIDELITY (compare each step's grounding against the evidence
   summary provided):
   - Flag "ma_fp" if a step is marked "grounded" but the linked evidence
     doesn't actually, semantically support what the step claims -- a
     structural match (right protocol/port) that doesn't mean what the
     step says it means. ALSO include currently_linked_evidence: copy the
     exact fingerprint_key(s)/evidence already shown as linked to that
     step, so the flag can be checked directly against what was actually
     linked, not just your description of the problem.
   - Flag "ma_fn" if a step is marked "unsupported" or
     "uncertain_needs_drilldown" but the evidence summary suggests
     traffic that should have been linked and wasn't. Include
     candidate_evidence_ref: the specific fingerprint_key you believe was
     missed.

Only flag genuine suspected errors -- if a step's extraction and grounding
both look correct, do not flag it. Most steps in a well-functioning
pipeline should have NO flags.

Return ONLY JSON, no prose, no markdown fences:
{
  "extraction_flags": [
    {"kind": "fp", "step_id": "...", "text_span": null, "reason": "..."},
    {"kind": "fn", "step_id": null, "text_span": "...", "reason": "...",
     "related_actors": ["actor_id", ...], "candidate_evidence_refs": ["fingerprint_key", ...]}
  ],
  "linkage_flags": [
    {"kind": "fp", "step_id": "...", "reason": "...", "currently_linked_evidence": ["fingerprint_key", ...]},
    {"kind": "fn", "step_id": "...", "reason": "...", "candidate_evidence_ref": "fingerprint_key or null"}
  ]
}
"""


def _summarize_step_for_validator(gs: GroundedStep) -> str:
    g = gs.grounding
    agg_summary = ", ".join(
        f"{a.fingerprint_key}(count={a.count})" for a in g.linked_aggregate_refs
    ) or "none"
    packet_summary = f"{len(g.linked_packets)} raw packet(s) linked" if g.linked_packets else "no raw packets linked"
    return (
        f"- step_id={gs.step.step_id}\n"
        f"  text: {gs.step.text}\n"
        f"  status: {g.status.value}\n"
        f"  evidence: {packet_summary}; aggregates: {agg_summary}\n"
        f"  notes: {g.notes}"
    )


def _summarize_actors(actors: list[Actor]) -> str:
    lines = [
        f"- {a.actor_id} ({a.role}): {a.resolved_endpoints or 'UNRESOLVED'}"
        for a in actors
    ]
    return "\n".join(lines) if lines else "(no actors)"


def _summarize_available_evidence(
    fingerprint_index: dict[str, EvidenceAggregate], limit: int = 30,
) -> str:
    """Compact overview of what evidence exists at all, so the Validator
    can spot ma_fn cases (evidence present but no step references it) --
    without dumping the full reduced_representation into the prompt."""
    items = sorted(fingerprint_index.values(), key=lambda a: -a.count)[:limit]
    lines = [
        f"- {a.fingerprint_key}: count={a.count}, "
        f"srcs={a.unique_sources[:3]}, dsts={a.unique_destinations[:3]}"
        for a in items
    ]
    suffix = f"\n  ... ({len(fingerprint_index) - limit} more, truncated)" if len(fingerprint_index) > limit else ""
    return ("\n".join(lines) if lines else "(no evidence)") + suffix


class Validator:
    """
    Always LLM-based -- llm_client is required, not optional (unlike
    Evidence Matcher's step grounding, which has an algorithmic-first
    path). There is no fallback for text-fidelity or evidence-relevance
    judgment.
    """

    def __init__(self, llm_client: LLMClient):
        if llm_client is None:
            raise ValueError(
                "Validator requires an llm_client -- there is no algorithmic "
                "substitute for text-fidelity or evidence-relevance judgment "
                "(see module docstring)."
            )
        self.llm_client = llm_client

    def validate(
        self,
        attack_description: str,
        actors: list[Actor],
        grounded_steps: list[GroundedStep],
        fingerprint_index: dict[str, EvidenceAggregate],
    ) -> ValidatorAssessment:
        steps_summary = "\n".join(_summarize_step_for_validator(gs) for gs in grounded_steps)
        actors_summary = _summarize_actors(actors)
        evidence_summary = _summarize_available_evidence(fingerprint_index)

        user_prompt = (
            f"Original description:\n\"\"\"\n{attack_description}\n\"\"\"\n\n"
            f"Resolved actors:\n{actors_summary}\n\n"
            f"Extracted and grounded steps:\n{steps_summary}\n\n"
            f"Overview of all available evidence (top {min(30, len(fingerprint_index))} "
            f"by count, for spotting missed/unreferenced evidence):\n{evidence_summary}\n"
        )

        try:
            result = self.llm_client.complete_json(VALIDATOR_SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            logger.warning("Validator LLM call failed: %s", e)
            # Fail loud in the returned structure rather than raising --
            # a failed validation pass shouldn't crash the whole pipeline,
            # but it must not look like "everything checked out clean"
            # either (an empty ValidatorAssessment would be indistinguishable
            # from a genuinely clean run -- silently misleading).
            return ValidatorAssessment(
                extraction_flags=[ExtractionFlag(
                    kind="fp", step_id=None, text_span=None,
                    reason=f"VALIDATOR RUN FAILED, results not trustworthy: {e}",
                )],
                linkage_flags=[],
                total_steps_reviewed=len(grounded_steps),
            )

        extraction_flags = [
            ExtractionFlag(
                kind=f.get("kind", "fp"),
                step_id=f.get("step_id"),
                text_span=f.get("text_span"),
                reason=f.get("reason", ""),
                related_actors=f.get("related_actors", []) or [],
                candidate_evidence_refs=f.get("candidate_evidence_refs", []) or [],
            )
            for f in result.get("extraction_flags", [])
        ]
        linkage_flags = [
            LinkageFlag(
                kind=f.get("kind", "fp"),
                step_id=f.get("step_id", ""),
                reason=f.get("reason", ""),
                candidate_evidence_ref=f.get("candidate_evidence_ref"),
                currently_linked_evidence=f.get("currently_linked_evidence", []) or [],
            )
            for f in result.get("linkage_flags", [])
        ]

        return ValidatorAssessment(
            extraction_flags=extraction_flags,
            linkage_flags=linkage_flags,
            total_steps_reviewed=len(grounded_steps),
        )