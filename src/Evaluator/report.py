"""
PAnGEA Evaluator -- main report generator.

Usage (programmatic):
    from evaluator.report import evaluate_sample
    report = evaluate_sample(gold_sample, system_sample)
    print(report.to_text())

Usage (CLI): see run_evaluator.py for loading from the pipeline's actual
JSON output files.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict

from .schemas import GoldSample, SystemSample
from .alignment import align_by_similarity, tfidf_similarity_matrix, SimilarityFn
from .coreference_metrics import build_clusters_from_alignment, muc_score, b_cubed_score, ceaf_score
from .accuracy_metrics import (
    extraction_prf1, grounding_status_accuracy,
    evidence_matching_accuracy, actor_ip_resolution_accuracy,
)
from .compliance import run_all_compliance_checks


def build_alignment_audit(
    system_texts: list[str], gold_texts: list[str], alignment: AlignmentResult,
    borderline_margin: float = 0.1,
) -> list[dict]:
    """
    Produces a human-readable record of every alignment decision, so a
    reviewer can catch spurious matches BEFORE trusting an aggregate P/R/F1
    number. Confirmed necessary on a real, concrete case: a fabricated
    claim ("kali sends a phishing email to the victim" -- a completely
    different, invented event) matched to a real gold claim ("kali sends
    spoofed ARP replies to the victim") at score=0.38, comfortably above a
    0.2 threshold, purely because of shared vocabulary (kali, sends,
    victim) -- despite describing an entirely unrelated, false event.
    Similarity-threshold matching cannot distinguish "the same underlying
    fact, worded differently" from "a different fact that happens to share
    words" -- no similarity function (TF-IDF or embeddings) fully escapes
    this. Making every match visible, with its score, is the mitigation:
    not a fix to the matching itself, but a way to make the risk
    reviewable instead of silently hidden inside an aggregate metric.

    confidence is "high" (well clear of threshold), "borderline" (within
    borderline_margin of threshold -- worth a manual look), or "none" (no
    match at all, correctly or incorrectly).

    HONEST LIMITATION, confirmed directly: this confidence tiering does
    NOT catch the "kali phishing email" case above -- that match scored
    0.381, comfortably clear of a 0.2 threshold (margin 0.181, above the
    default 0.1 borderline_margin), so it is marked "high confidence"
    despite being a confident, wrong match. Near-threshold flagging only
    catches matches that are ALREADY close to failing -- it cannot catch
    a confidently-wrong match caused by coincidental shared vocabulary
    (same actor names, same common verbs) describing a genuinely
    different event. There is no similarity function (TF-IDF or
    embeddings) that fully escapes this. The only fully reliable
    mitigation is manual review of the COMPLETE audit list (available in
    full via EvaluationReport.claim_alignment_audit /
    actor_alignment_audit, not just the "flagged" subset to_text() prints)
    -- for a small sample count like this project's (~16), that is
    genuinely feasible, not a theoretical suggestion.
    """
    audit = []
    for i, sys_text in enumerate(system_texts):
        gold_idx = alignment.system_to_gold.get(i)
        if gold_idx is None:
            best_score = float(alignment.similarity_matrix[i].max()) if alignment.similarity_matrix.shape[1] > 0 else 0.0
            audit.append({
                "system_text": sys_text, "matched_gold_text": None,
                "score": round(best_score, 3), "confidence": "none",
            })
        else:
            score = float(alignment.similarity_matrix[i, gold_idx])
            margin = score - alignment.threshold
            confidence = "borderline" if margin < borderline_margin else "high"
            audit.append({
                "system_text": sys_text, "matched_gold_text": gold_texts[gold_idx],
                "score": round(score, 3), "confidence": confidence,
            })
    return audit


@dataclass
class EvaluationReport:
    sample_id: str
    # Claims
    claim_extraction: dict
    grounding_accuracy_per_status: dict
    evidence_matching: dict
    claim_alignment_audit: list
    # Actors
    actor_extraction: dict
    actor_ip_resolution: dict
    coreference_muc: dict
    coreference_bcubed: dict
    coreference_ceaf: dict
    actor_alignment_audit: list
    # Compliance (no gold needed, included for completeness of one report)
    compliance: list

    def to_text(self) -> str:
        lines = [f"=== Evaluation Report: {self.sample_id} ===", ""]
        lines.append("-- Claim Extraction --")
        lines.append(f"  Precision={self.claim_extraction['precision']:.3f} "
                      f"Recall={self.claim_extraction['recall']:.3f} "
                      f"F1={self.claim_extraction['f1']:.3f}")
        lines.append("")
        lines.append("-- Grounding Accuracy per Status --")
        for status, scores in self.grounding_accuracy_per_status.items():
            lines.append(f"  {status}: P={scores['precision']:.3f} R={scores['recall']:.3f} F1={scores['f1']:.3f}")
        lines.append("")
        lines.append("-- Evidence Matching (aligned claims) --")
        lines.append(f"  P={self.evidence_matching['precision']:.3f} "
                      f"R={self.evidence_matching['recall']:.3f} "
                      f"F1={self.evidence_matching['f1']:.3f}")
        lines.append("")
        lines.append("-- Actor Extraction --")
        lines.append(f"  Precision={self.actor_extraction['precision']:.3f} "
                      f"Recall={self.actor_extraction['recall']:.3f} "
                      f"F1={self.actor_extraction['f1']:.3f}")
        lines.append("")
        lines.append("-- Actor IP Resolution --")
        for k, v in self.actor_ip_resolution.items():
            lines.append(f"  {k}: {v}")
        lines.append("")
        lines.append("-- Coreference Metrics (actor coreference) --")
        lines.append(f"  MUC:     P={self.coreference_muc['precision']:.3f} R={self.coreference_muc['recall']:.3f} F1={self.coreference_muc['f1']:.3f}")
        lines.append(f"  B-cubed: P={self.coreference_bcubed['precision']:.3f} R={self.coreference_bcubed['recall']:.3f} F1={self.coreference_bcubed['f1']:.3f}")
        lines.append(f"  CEAF:    P={self.coreference_ceaf['precision']:.3f} R={self.coreference_ceaf['recall']:.3f} F1={self.coreference_ceaf['f1']:.3f}")
        lines.append("")
        lines.append("-- Alignment Audit (review anything not 'high') --")
        for label, audit in [("Claims", self.claim_alignment_audit), ("Actors", self.actor_alignment_audit)]:
            flagged = [a for a in audit if a["confidence"] != "high"]
            if flagged:
                lines.append(f"  {label} -- {len(flagged)} entr{'y' if len(flagged)==1 else 'ies'} to review:")
                for a in flagged:
                    if a["matched_gold_text"] is None:
                        lines.append(f"    [NO MATCH, best score={a['score']}] \"{a['system_text'][:70]}\"")
                    else:
                        lines.append(f"    [BORDERLINE, score={a['score']}] \"{a['system_text'][:60]}\" "
                                      f"<-> \"{a['matched_gold_text'][:60]}\"")
            else:
                lines.append(f"  {label} -- all matches high-confidence.")
        lines.append("")
        lines.append("-- Compliance Checks (no gold needed) --")
        for c in self.compliance:
            status = "PASS" if c["passed"] else "FAIL"
            lines.append(f"  [{status}] {c['check_name']}")
            for v in c["violations"]:
                lines.append(f"      - {v}")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def evaluate_sample(
    gold: GoldSample, system: SystemSample, alignment_threshold: float = 0.15,
    similarity_fn: SimilarityFn = tfidf_similarity_matrix,
) -> EvaluationReport:
    """
    similarity_fn defaults to TF-IDF -- confirmed empirically (not just
    theoretically) to fail on true paraphrases with zero shared
    vocabulary. Pass evaluator.alignment.embedding_similarity_matrix for
    real semantic similarity (requires an OpenAI API key); not the
    default here since it makes a real API call per evaluation run and
    this module should work with no external dependency by default.
    """
    # --- Claims ---
    claim_alignment = align_by_similarity(
        [c.text for c in system.claims], [c.text for c in gold.claims],
        threshold=alignment_threshold, similarity_fn=similarity_fn,
    )
    
    
    print(f"Claim alignment similarity matrix:\n{claim_alignment.similarity_matrix}"
          )
    print(f"Claim alignment system_to_gold: {claim_alignment.system_to_gold}")
    print(f"Claim alignment gold_to_system: {claim_alignment.gold_to_systems}")
    claim_extraction = extraction_prf1(
        claim_alignment, len(system.claims), len(gold.claims),
        [c.text for c in system.claims], [c.text for c in gold.claims],
        alignment_threshold, similarity_fn,
    )
    grounding_acc = grounding_status_accuracy(system.claims, gold.claims, claim_alignment)
    evidence_acc = evidence_matching_accuracy(system.claims, gold.claims, claim_alignment)

    # --- Actors ---
    actor_alignment = align_by_similarity(
        [a.description_ref for a in system.actors],
        [a.description_ref_gold for a in gold.actors],
        threshold=alignment_threshold, similarity_fn=similarity_fn,
    )
    actor_extraction = extraction_prf1(
        actor_alignment, len(system.actors), len(gold.actors),
        [a.description_ref for a in system.actors], [a.description_ref_gold for a in gold.actors],
        alignment_threshold, similarity_fn,
    )
    ip_resolution = actor_ip_resolution_accuracy(
        [a.resolved_endpoints for a in system.actors],
        [a.ground_truth_ips for a in gold.actors],
        actor_alignment,
    )
    system_clusters, gold_clusters = build_clusters_from_alignment(
        len(system.actors), len(gold.actors), actor_alignment,
    )
    muc = muc_score(system_clusters, gold_clusters)
    bcubed = b_cubed_score(system_clusters, gold_clusters)
    ceaf = ceaf_score(system_clusters, gold_clusters)

    # --- Compliance (independent of gold) ---
    compliance = [asdict(c) for c in run_all_compliance_checks(system)]
    claim_audit = build_alignment_audit([c.text for c in system.claims], [c.text for c in gold.claims], claim_alignment)
    actor_audit = build_alignment_audit(
        [a.description_ref for a in system.actors], [a.description_ref_gold for a in gold.actors], actor_alignment,
    )

    return EvaluationReport(
        sample_id=gold.sample_id,
        claim_extraction=asdict(claim_extraction),
        grounding_accuracy_per_status={k: asdict(v) for k, v in grounding_acc.items()},
        evidence_matching=asdict(evidence_acc),
        claim_alignment_audit=claim_audit,
        actor_extraction=asdict(actor_extraction),
        actor_ip_resolution=ip_resolution,
        coreference_muc=asdict(muc),
        coreference_bcubed=asdict(bcubed),
        coreference_ceaf=asdict(ceaf),
        actor_alignment_audit=actor_audit,
        compliance=compliance,
    )