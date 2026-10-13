"""
PAnGEA — Dataset Annotator.

Interactive CLI tool for creating ground truth annotations.

For each (step, cluster) pair the annotator is shown:
  - The step text
  - The cluster serialization
  - Key cluster stats (tier, Z-scores, fingerprint)

And applies the rubric:

  SUPPORTS (S)   — fingerprint consistent + scale consistent + no contradictions
  PARTIAL  (P)   — fingerprint matches but scale inconsistent OR only one
                   direction of described behavior present
  NEUTRAL  (N)   — plausible but too generic to discriminate
  CONTRADICTS (X)— hard contradiction (wrong protocol, direction, or scale)
  SKIP     (K)   — unsure, mark for later review

Usage:
  python annotator.py --dataset-dir ./dataset --number 001
  python annotator.py --dataset-dir ./dataset --number 001 --resume
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Rubric (printed at start and on request)
# ---------------------------------------------------------------------------

RUBRIC = """
╔══════════════════════════════════════════════════════════════════╗
║                     ANNOTATION RUBRIC                           ║
╠══════════════════════════════════════════════════════════════════╣
║  SUPPORTS (S)                                                    ║
║    ✓ Fingerprint consistent with step (protocol, port, flags)   ║
║    ✓ Scale consistent (flood → high rate; probe → low count)    ║
║    ✓ No field in cluster contradicts the step                   ║
╠══════════════════════════════════════════════════════════════════╣
║  PARTIAL (P)                                                     ║
║    ✓ Fingerprint matches                                         ║
║    ✗ Scale inconsistent, OR                                     ║
║    ✗ Only one direction of described behavior present, OR       ║
║    ✗ L7 matches but entropy bucket contradicts                  ║
╠══════════════════════════════════════════════════════════════════╣
║  NEUTRAL (N)                                                     ║
║    ~ Cluster is plausible but too generic to discriminate       ║
║    ~ Step could apply equally to many clusters                  ║
╠══════════════════════════════════════════════════════════════════╣
║  CONTRADICTS (X)                                                 ║
║    ✗ Wrong protocol, OR wrong direction, OR wrong scale         ║
╚══════════════════════════════════════════════════════════════════╝
"""

VALID_LABELS = {"S": "SUPPORTS", "P": "PARTIAL", "N": "NEUTRAL",
                "X": "CONTRADICTS", "K": "SKIP"}


# ---------------------------------------------------------------------------
# Main annotation loop
# ---------------------------------------------------------------------------

def annotate(dataset_dir: str, number: str, resume: bool = False) -> None:
    extracted_dir    = os.path.join(dataset_dir, "extracted")
    clusters_dir     = os.path.join(dataset_dir, "clusters")
    ground_truth_dir = os.path.join(dataset_dir, "ground_truth")
    os.makedirs(ground_truth_dir, exist_ok=True)

    steps    = _load_steps(extracted_dir, number)
    clusters = _load_clusters(clusters_dir, number)

    if not steps:
        print(f"No steps found for number {number}. Run dataset_builder first.")
        sys.exit(1)
    if not clusters:
        print(f"No clusters found for number {number}. Run dataset_builder first.")
        sys.exit(1)

    gt_path = _find_gt_path(ground_truth_dir, number)
    if gt_path and not resume:
        print(f"Ground truth already exists at {gt_path}. Use --resume to continue.")
        sys.exit(1)

    # Load existing annotations if resuming
    existing: dict = {}
    if gt_path and resume:
        with open(gt_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for ann in data.get("annotations", []):
            key = (ann["step_id"], ann["fingerprint_key"])
            existing[key] = ann

    print(RUBRIC)
    print(f"\nAnnotating entry {number}: {len(steps)} steps × {len(clusters)} clusters")
    print(f"Commands: S=SUPPORTS  P=PARTIAL  N=NEUTRAL  X=CONTRADICTS  K=SKIP  R=RUBRIC  Q=QUIT\n")

    annotations = list(existing.values())
    annotated_keys = set(existing.keys())

    try:
        for step in steps:
            print(f"\n{'═'*70}")
            print(f"STEP {step['step_id']}: {step['text']}")
            print(f"{'─'*70}")

            for cluster in clusters:
                fkey = cluster["fingerprint_key"]
                key  = (step["step_id"], fkey)

                if key in annotated_keys:
                    existing_label = existing[key]["label"]
                    print(f"  [already annotated: {existing_label}] {fkey}")
                    continue

                _print_cluster(cluster)

                label = _prompt_label()
                if label == "Q":
                    _save_annotations(annotations, gt_path or
                                      _default_gt_path(ground_truth_dir, number),
                                      number, steps, clusters)
                    print("Saved and quit.")
                    return
                if label == "R":
                    print(RUBRIC)
                    label = _prompt_label()

                if label == "K":
                    print("  → Skipped.")
                    continue

                annotation = {
                    "step_id":        step["step_id"],
                    "step_text":      step["text"],
                    "fingerprint_key":fkey,
                    "cluster_text":   cluster.get("cluster_text", ""),
                    "label":          VALID_LABELS[label],
                    "annotated_at":   datetime.utcnow().isoformat(),
                }
                annotations.append(annotation)
                annotated_keys.add(key)
                print(f"  → {VALID_LABELS[label]}")

    except KeyboardInterrupt:
        print("\n\nInterrupted — saving progress...")

    out_path = gt_path or _default_gt_path(ground_truth_dir, number)
    _save_annotations(annotations, out_path, number, steps, clusters)
    print(f"\nSaved {len(annotations)} annotations to {out_path}")


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _print_cluster(cluster: dict) -> None:
    fkey = cluster["fingerprint_key"]
    text = cluster.get("cluster_text", "(no serialization)")
    meta = cluster.get("metadata", {})
    agg  = cluster.get("aggregate", {})

    print(f"\n  Fingerprint: {fkey}")
    print(f"  Tier:        {meta.get('tier', 'N/A')}  |  "
          f"Context match: {meta.get('context_match', False)}")
    if agg:
        print(f"  Count: {agg.get('count','?')}  |  "
              f"Srcs: {len(agg.get('unique_sources',[]))}  |  "
              f"Dsts: {len(agg.get('unique_destinations',[]))}")
    zscores = meta.get("zscore_anomalies", {})
    if zscores:
        z_str = "  ".join(f"{k}={v:.1f}" for k, v in zscores.items() if v >= 2.0)
        if z_str:
            print(f"  Anomalies:   {z_str}")
    print(f"  Summary:     {text}")


def _prompt_label() -> str:
    while True:
        raw = input("  Label [S/P/N/X/K/R/Q]: ").strip().upper()
        if raw in VALID_LABELS or raw in ("R", "Q"):
            return raw
        print("  Invalid. Use S, P, N, X, K, R, or Q.")


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def _save_annotations(
    annotations: list[dict],
    path: str,
    number: str,
    steps: list[dict],
    clusters: list[dict],
) -> None:
    data = {
        "entry_number": number,
        "annotated_at": datetime.utcnow().isoformat(),
        "step_count":   len(steps),
        "cluster_count":len(clusters),
        "annotation_count": len(annotations),
        "label_distribution": _label_distribution(annotations),
        "annotations": annotations,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _label_distribution(annotations: list[dict]) -> dict:
    dist: dict[str, int] = {}
    for ann in annotations:
        label = ann.get("label", "UNKNOWN")
        dist[label] = dist.get(label, 0) + 1
    return dist


def _load_steps(extracted_dir: str, number: str) -> list[dict]:
    path = _find_file(extracted_dir, number, ".json")
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_clusters(clusters_dir: str, number: str) -> list[dict]:
    path = _find_file(clusters_dir, number, ".json")
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("clusters", [])


def _find_file(directory: str, number: str, extension: str) -> Optional[str]:
    if not os.path.isdir(directory):
        return None
    pattern = re.compile(rf"_0*{int(number):d}_.*\{extension}$")
    for f in os.listdir(directory):
        if pattern.search(f):
            return os.path.join(directory, f)
    return None


def _find_gt_path(directory: str, number: str) -> Optional[str]:
    return _find_file(directory, number, ".json")


def _default_gt_path(directory: str, number: str) -> str:
    return os.path.join(directory, f"gt_{number}_annotations.json")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PAnGEA Ground Truth Annotator")
    parser.add_argument("--dataset-dir", required=True, help="Path to dataset root directory")
    parser.add_argument("--number",      required=True, help="Entry number to annotate (e.g. 001)")
    parser.add_argument("--resume",      action="store_true", help="Resume existing annotation")
    args = parser.parse_args()
    annotate(args.dataset_dir, args.number, args.resume)


if __name__ == "__main__":
    main()
