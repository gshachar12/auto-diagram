"""
PAnGEA — Evaluator.

Responsibility: compute grounding quality metrics by comparing
GrounderOutput against annotated ground truth.

Metrics computed:
  Primary:
    Precision@1       — is the top-ranked cluster correct (SUPPORTS/PARTIAL)?
    Set Jaccard       — overlap between predicted cluster set and ground truth set
    No-match accuracy — correct rejection rate for steps with no SUPPORTS/PARTIAL label
    MRR               — mean reciprocal rank of first correct cluster

  Secondary:
    Score correlation — Spearman correlation between cross-encoder score
                        and human label (SUPPORTS=1, PARTIAL=0.5, NEUTRAL=0)
    Coverage          — fraction of steps that get any match above threshold
    Ambiguity rate    — fraction of steps flagged as ambiguous

All metrics are computed per-step and aggregated. Results include
per-step breakdowns for error analysis.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from Grounder.schemas import EvidenceLabel, GrounderOutput


# Label → numeric score for correlation
_LABEL_SCORE = {
    "SUPPORTS":    1.0,
    "PARTIAL":     0.5,
    "NEUTRAL":     0.0,
    "CONTRADICTS": -1.0,
}


# ---------------------------------------------------------------------------
# Result schemas
# ---------------------------------------------------------------------------

@dataclass
class StepEvalResult:
    step_id:          int
    step_text:        str
    precision_at_1:   Optional[float]   # 1.0 / 0.5 / 0.0 / None (ungrounded)
    jaccard:          float             # set overlap with ground truth
    reciprocal_rank:  float             # 1/rank of first correct, 0 if not found
    is_correct_no_match: Optional[bool] # True if ungrounded AND should be ungrounded
    predicted_keys:   list[str]
    gt_keys:          list[str]


@dataclass
class EvaluationReport:
    model_cross_encoder: str
    threshold_used:      float
    n_steps:             int
    n_grounded_steps:    int
    n_ungrounded_steps:  int
    n_ambiguous_steps:   int

    # Aggregated metrics
    precision_at_1:      float
    mean_jaccard:        float
    mrr:                 float
    no_match_accuracy:   Optional[float]   # None if no steps have null gt
    coverage:            float
    ambiguity_rate:      float

    # Per-step breakdown
    step_results:        list[StepEvalResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "model_cross_encoder": self.model_cross_encoder,
            "threshold_used":      self.threshold_used,
            "n_steps":             self.n_steps,
            "metrics": {
                "precision_at_1":    round(self.precision_at_1, 4),
                "mean_jaccard":      round(self.mean_jaccard, 4),
                "mrr":               round(self.mrr, 4),
                "no_match_accuracy": round(self.no_match_accuracy, 4)
                                     if self.no_match_accuracy is not None else None,
                "coverage":          round(self.coverage, 4),
                "ambiguity_rate":    round(self.ambiguity_rate, 4),
            },
            "counts": {
                "grounded":   self.n_grounded_steps,
                "ungrounded": self.n_ungrounded_steps,
                "ambiguous":  self.n_ambiguous_steps,
            },
            "per_step": [
                {
                    "step_id":       r.step_id,
                    "step_text":     r.step_text,
                    "precision_at_1":r.precision_at_1,
                    "jaccard":       r.jaccard,
                    "mrr":           r.reciprocal_rank,
                    "predicted":     r.predicted_keys,
                    "ground_truth":  r.gt_keys,
                }
                for r in self.step_results
            ],
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def evaluate(
    grounder_output: GrounderOutput,
    ground_truth_path: str,
) -> EvaluationReport:
    """
    Evaluate GrounderOutput against annotated ground truth.

    Args:
        grounder_output:    output from grounder.ground()
        ground_truth_path:  path to gt_N_*.json produced by annotator.py

    Returns:
        EvaluationReport with all metrics.
    """
    return evaluate_against(grounder_output, _load_ground_truth(ground_truth_path))


def evaluate_against(
    grounder_output: GrounderOutput,
    gt: dict[int, dict],
) -> EvaluationReport:
    """
    Evaluate against an already-loaded ground truth
    ({step_id: {"SUPPORTS": [...], "PARTIAL": [...], "no_match": bool}}).

    Steps absent from gt have not been reviewed by an annotator and are
    excluded from every metric rather than scored as no-match.
    """
    step_results: list[StepEvalResult] = []
    p1_scores:    list[float] = []
    jaccard_scores: list[float] = []
    rr_scores:    list[float] = []
    no_match_correct: list[bool] = []

    reviewed = [sg for sg in grounder_output.step_groundings if sg.step.step_id in gt]

    for sg in reviewed:
        step_id   = sg.step.step_id
        step_text = sg.step.text

        # Ground truth for this step
        gt_entry = gt[step_id]
        gt_supports = set(gt_entry.get("SUPPORTS", []))
        gt_partial  = set(gt_entry.get("PARTIAL",  []))
        gt_correct  = gt_supports | gt_partial       # any positive label
        gt_is_null  = gt_entry.get("no_match", False)

        predicted_keys = [gr.cluster_fingerprint_key for gr in sg.matched_clusters]

        # Precision@1
        p1: Optional[float] = None
        if sg.is_ungrounded:
            p1 = None
        elif predicted_keys:
            top_key = predicted_keys[0]
            if top_key in gt_supports:
                p1 = 1.0
            elif top_key in gt_partial:
                p1 = 0.5
            else:
                p1 = 0.0
            p1_scores.append(p1)

        # Jaccard
        predicted_set = set(predicted_keys)
        if not gt_correct and not predicted_set:
            jaccard = 1.0   # both empty = correct no-match
        elif not gt_correct or not predicted_set:
            jaccard = 0.0
        else:
            jaccard = len(predicted_set & gt_correct) / len(predicted_set | gt_correct)
        jaccard_scores.append(jaccard)

        # Reciprocal rank
        rr = 0.0
        for rank, key in enumerate(predicted_keys, start=1):
            if key in gt_correct:
                rr = 1.0 / rank
                break
        rr_scores.append(rr)

        # No-match accuracy
        if gt_is_null:
            no_match_correct.append(sg.is_ungrounded)

        step_results.append(StepEvalResult(
            step_id=step_id,
            step_text=step_text,
            precision_at_1=p1,
            jaccard=jaccard,
            reciprocal_rank=rr,
            is_correct_no_match=sg.is_ungrounded if gt_is_null else None,
            predicted_keys=predicted_keys,
            gt_keys=list(gt_correct),
        ))

    n_steps     = len(reviewed)
    n_grounded  = sum(1 for sg in reviewed if not sg.is_ungrounded)
    n_ungrounded= sum(1 for sg in reviewed if sg.is_ungrounded)
    n_ambiguous = sum(1 for sg in reviewed if sg.is_ambiguous)

    return EvaluationReport(
        model_cross_encoder=grounder_output.model_cross_encoder,
        threshold_used=grounder_output.threshold_used,
        n_steps=n_steps,
        n_grounded_steps=n_grounded,
        n_ungrounded_steps=n_ungrounded,
        n_ambiguous_steps=n_ambiguous,
        precision_at_1=_mean(p1_scores) if p1_scores else 0.0,
        mean_jaccard=_mean(jaccard_scores) if jaccard_scores else 0.0,
        mrr=_mean(rr_scores) if rr_scores else 0.0,
        no_match_accuracy=_mean([float(b) for b in no_match_correct])
                          if no_match_correct else None,
        coverage=n_grounded / n_steps if n_steps > 0 else 0.0,
        ambiguity_rate=n_ambiguous / n_steps if n_steps > 0 else 0.0,
        step_results=step_results,
    )


def save_report(report: EvaluationReport, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Ground truth loader
# ---------------------------------------------------------------------------

def _load_ground_truth(path: str) -> dict[int, dict]:
    """
    Load annotator output and return a dict:
      {step_id: {"SUPPORTS": [fkey,...], "PARTIAL": [...], "no_match": bool}}
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return ground_truth_from_dict(data)


def ground_truth_from_dict(data: dict) -> dict[int, dict]:
    """
    Same as _load_ground_truth, from the parsed JSON.

    If the file lists "reviewed_steps", those steps are included even with
    no annotations (an explicit no-match); otherwise every step with at
    least one annotation counts as reviewed.
    """
    result: dict[int, dict] = {
        int(sid): {"SUPPORTS": [], "PARTIAL": [], "no_match": False}
        for sid in data.get("reviewed_steps", [])
    }
    for ann in data.get("annotations", []):
        step_id = ann["step_id"]
        if step_id not in result:
            result[step_id] = {"SUPPORTS": [], "PARTIAL": [], "no_match": False}

        label = ann.get("label", "")
        fkey  = ann.get("fingerprint_key", "")

        if label == "SUPPORTS":
            result[step_id]["SUPPORTS"].append(fkey)
        elif label == "PARTIAL":
            result[step_id]["PARTIAL"].append(fkey)

    # Steps with no SUPPORTS or PARTIAL annotations are treated as no-match
    for step_id, entry in result.items():
        if not entry["SUPPORTS"] and not entry["PARTIAL"]:
            entry["no_match"] = True

    return result


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0
