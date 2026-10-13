"""
PAnGEA — Grounder schemas.

Defines the data contracts for:
  - Step          : a single extracted behavioral step from input text
  - GroundingResult: a cluster matched to a step with a score and evidence label
  - GrounderOutput : the full mapping {step_id -> list[GroundingResult]}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EvidenceLabel(str, Enum):
    """
    Rubric for annotating and interpreting grounding matches.

    SUPPORTS     — fingerprint consistent with step, scale consistent,
                   no contradictions. All three conditions met.
    PARTIAL      — fingerprint matches but scale inconsistent, or only
                   one direction of described behavior present, or L7
                   matches but entropy contradicts.
    NEUTRAL      — cluster is plausible but too generic to discriminate;
                   step could apply to many clusters equally.
    CONTRADICTS  — at least one hard contradiction between step and cluster
                   (wrong protocol, wrong direction, wrong scale).
    NO_MATCH     — no cluster scored above threshold; step is ungrounded.
    """
    SUPPORTS    = "SUPPORTS"
    PARTIAL     = "PARTIAL"
    NEUTRAL     = "NEUTRAL"
    CONTRADICTS = "CONTRADICTS"
    NO_MATCH    = "NO_MATCH"


@dataclass
class Step:
    """
    A single behavioral step extracted from the input text.
    Each step describes one observable traffic pattern.
    """
    step_id:       int
    text:          str            # extracted step text, traffic-observable language
    source_text:   str            # original sentence(s) the step was drawn from
    mitre_tag:     Optional[str] = None   # optional MITRE ATT&CK technique ID


@dataclass
class GroundingResult:
    """
    A single cluster matched to a step, with scoring and evidence metadata.
    """
    cluster_fingerprint_key: str
    cluster_text:            str      # serialized cluster summary
    score:                   float    # cross-encoder score in [0, 1]
    rank:                    int      # rank within results for this step (1 = best)
    evidence_label:          EvidenceLabel  # assigned by threshold logic
    score_gap:               float = 0.0   # gap between this score and next-best candidate
    bi_encoder_score:        Optional[float] = None  # stage-1 cosine similarity, for traceability


@dataclass
class StepGrounding:
    """
    All grounding results for one step.
    matched_clusters is empty if no cluster scored above threshold.
    """
    step:              Step
    matched_clusters:  list[GroundingResult] = field(default_factory=list)
    is_ambiguous:      bool = False    # True if top score gap < ambiguity_threshold
    is_ungrounded:     bool = False    # True if matched_clusters is empty
    top_candidate_score: Optional[float] = None  # best cross-encoder score, even if below threshold


@dataclass
class GrounderOutput:
    """
    Full output of the grounder for one (text, PCAP) pair.
    Primary output is the grounding_dict for downstream consumption.
    """
    step_groundings:   list[StepGrounding]
    threshold_used:    float
    model_bi_encoder:  str
    model_cross_encoder: str
    parameters:        dict = field(default_factory=dict)   # thresholds/top_k used, for reproducibility
    clusters_scored:   int = 0
    clusters_skipped_no_text: int = 0   # clusters without cluster_text (surfaced, not silent)

    @property
    def grounding_dict(self) -> dict[int, list[dict]]:
        """
        Convenience property returning the final mapping:
            {step_id: [{fingerprint_key, score, evidence, rank}, ...]}
        Empty list means the step is ungrounded.
        """
        result = {}
        for sg in self.step_groundings:
            result[sg.step.step_id] = [
                {
                    "fingerprint_key":  gr.cluster_fingerprint_key,
                    "score":            gr.score,
                    "evidence":         gr.evidence_label.value,
                    "rank":             gr.rank,
                }
                for gr in sg.matched_clusters
            ]
        return result

    @property
    def ungrounded_steps(self) -> list[Step]:
        return [sg.step for sg in self.step_groundings if sg.is_ungrounded]

    @property
    def ambiguous_steps(self) -> list[Step]:
        return [sg.step for sg in self.step_groundings if sg.is_ambiguous]
