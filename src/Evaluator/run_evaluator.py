"""
PAnGEA Evaluator -- CLI.

Adapts THIS PROJECT's actual JSON output (03c_evidence_matcher_output.json
/ 05_final_pipeline_output.json shape, plus a fingerprint_index for the
observed-IPs compliance check) into the Evaluator's generic schema, loads
a hand-authored gold JSON file, and runs the full report.

Usage:
    python3 -m evaluator.run_evaluator \
        --gold gold_sample.json \
        --system-output 03c_evidence_matcher_output.json \
        --fingerprint-index 01_preprocessing_output.json \
        -o report.json

Gold JSON shape expected (author this by hand per sample -- see the
worked example in evaluator_build/example_gold.json):
{
  "sample_id": "...",
  "actors": [{"entity_id": "...", "description_ref_gold": "...", "ground_truth_ip": "..." | null}],
  "claims": [{"claim_id": "...", "text": "...", "severity": "critical"|"minor",
              "references_entities": [...], "gold_grounding_status": "...",
              "gold_linked_fingerprint_keys": [...]}]
}
"""
from __future__ import annotations

import argparse
import json
import sys

from .schemas import GoldSample, GoldActor, GoldClaim, GoldEvidenceRef, SystemSample, SystemActor, SystemClaim
from .report import evaluate_sample
from .alignment import tfidf_similarity_matrix, embedding_similarity_matrix


def gold_sample_from_dict(data: dict) -> GoldSample:
    """
    Pure dict -> GoldSample construction, split out of load_gold so it can
    be reused directly on a dict produced by xlsx_to_gold_json.convert()
    (in-memory, no intermediate JSON file needed) as well as on a JSON
    file already on disk.
    """
    def _claim(c: dict) -> GoldClaim:
        evidence = [GoldEvidenceRef(**e) for e in c.get("gold_linked_evidence", [])]
        c = {k: v for k, v in c.items() if k != "gold_linked_evidence"}
        return GoldClaim(**c, gold_linked_evidence=evidence)

    return GoldSample(
        sample_id=data["sample_id"],
        actors=[GoldActor(**a) for a in data.get("actors", [])],
        claims=[_claim(c) for c in data.get("claims", [])],
    )


def load_gold(path: str) -> GoldSample:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return gold_sample_from_dict(data)


def load_system_output_from_pipeline_json(
    evidence_matcher_output_path: str,
    fingerprint_index_path: str | None = None,
    sample_id: str = "unnamed_sample",
) -> SystemSample:
    """
    Adapts 03c_evidence_matcher_output.json's actual shape
    ({"resolved_actors": [...], "grounded_steps": [{"step": ..., "grounding": ...}]})
    into a SystemSample. fingerprint_index_path (from
    01_preprocessing_output.json) is optional -- only needed for the
    'resolved_ip_is_observed' compliance check; without it that check is
    skipped (observed_ips left empty, per compliance.py's own guard).
    """
    with open(evidence_matcher_output_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    actors = [
        SystemActor(
            actor_id=a["actor_id"],
            description_ref=a.get("description_ref", ""),
            resolved_endpoints=a.get("resolved_endpoints", []),
        )
        for a in data.get("resolved_actors", [])
    ]

    claims = []
    for gs in data.get("grounded_steps", []):
        step = gs["step"]
        grounding = gs["grounding"]
        linked_keys = [r["fingerprint_key"] for r in grounding.get("linked_aggregate_refs", [])]
        linked_dests = {
            r["fingerprint_key"]: r.get("unique_destinations", [])
            for r in grounding.get("linked_aggregate_refs", [])
        }
        claims.append(SystemClaim(
            step_id=step["step_id"],
            text=step["text"],
            actor_refs=step.get("actor_refs", []),
            grounding_status=grounding.get("status", "uncertain_needs_drilldown"),
            linked_fingerprint_keys=linked_keys,
            linked_fingerprint_destinations=linked_dests,
        ))

    observed_ips = set()
    if fingerprint_index_path:
        with open(fingerprint_index_path, "r", encoding="utf-8") as f:
            prep_data = json.load(f)
        for agg in prep_data.get("fingerprint_index", {}).values():
            observed_ips.update(agg.get("unique_sources", []))
            observed_ips.update(agg.get("unique_destinations", []))

    return SystemSample(sample_id=sample_id, actors=actors, claims=claims, observed_ips=observed_ips)


def main():
    parser = argparse.ArgumentParser(description="Run the PAnGEA Evaluator on one sample.")
    parser.add_argument("--gold", required=True, help="Path to the hand-authored gold JSON file.")
    parser.add_argument("--system-output", required=True,
                         help="Path to 03c_evidence_matcher_output.json (or 05_final_pipeline_output.json).")
    parser.add_argument("--fingerprint-index", default=None,
                         help="Path to 01_preprocessing_output.json (optional, enables one compliance check).")
    parser.add_argument("--similarity", choices=["tfidf", "embedding"], default="tfidf",
                         help="Alignment similarity method. 'tfidf' (default) is lexical-overlap-based "
                              "and confirmed to fail on true paraphrases with no shared vocabulary -- "
                              "'embedding' uses real semantic similarity via OpenAI's API (needs "
                              "OPENAI_API_KEY) and likely needs a DIFFERENT --alignment-threshold, since "
                              "embedding cosine similarities are not on the same scale as TF-IDF's -- "
                              "not yet empirically tuned, verify against a known-correct pair first.")
    parser.add_argument("--alignment-threshold", type=float, default=0.15,
                         help="Minimum similarity score to count as a match (default: 0.15, tuned for TF-IDF only).")
    parser.add_argument("-o", "--output", default=None, help="Write the report as JSON to this path.")
    args = parser.parse_args()

    gold = load_gold(args.gold)
    system = load_system_output_from_pipeline_json(
        args.system_output, args.fingerprint_index, sample_id=gold.sample_id,
    )
    similarity_fn = embedding_similarity_matrix if args.similarity == "embedding" else tfidf_similarity_matrix
    report = evaluate_sample(gold, system, alignment_threshold=args.alignment_threshold, similarity_fn=similarity_fn)

    print(report.to_text())
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        print(f"\nWrote full report to: {args.output}")


if __name__ == "__main__":
    main()