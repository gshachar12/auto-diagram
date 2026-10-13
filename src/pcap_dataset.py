"""
PAnGEA — evaluation dataset kept next to the captures in src/pcaps.

Every capture <name>.pcap / .pcapng / .cap may have, side by side:

  <name>.txt              description (analyst-report style input text)
  <name>_steps.json       extracted steps — JSON array in Grounder.step_extractor format
  <name>_clusters.json    cached preprocessor output + the settings that produced it
  <name>_grounding.json   cached grounder output, keeping ALL top-k candidates
                          (neutral threshold 0) so thresholds can be re-applied
                          later without re-running the models
  <name>_gt.json          human ground truth (annotator.py format + reviewed_steps)

Fingerprint keys contain the time bucket, so ground truth is only valid for
clusters produced with the same preprocessor settings; those settings are
stored in every derived file and compared on load.

CLI (from src/):
    python -m pcap_dataset status
    python -m pcap_dataset build [--only NAME ...] [--no-ground] [--force]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Optional

from Grounder.grounder import (
    DEFAULT_AMBIGUITY_THRESHOLD,
    DEFAULT_PARTIAL_THRESHOLD,
    DEFAULT_SUPPORTS_THRESHOLD,
    DEFAULT_TOP_K_BIENCODER,
    GrounderModels,
    _assign_evidence_label,
    ground,
    grounder_output_to_dict,
)
from Grounder.schemas import (
    EvidenceLabel, GrounderOutput, GroundingResult, Step, StepGrounding,
)
from Grounder.step_extractor import load_steps
from Preprocessor.layer2_fingerprint import DEFAULT_DELTA_T

logger = logging.getLogger(__name__)

DATASET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")

# Settings that change fingerprint keys or cluster content. Ground truth is
# tied to these; max_packets caps captures too large for pyshark in practice.
DEFAULT_PREPROCESS_SETTINGS = {
    "token_budget":    10000,
    "filtering_limit": 3,
    "delta_t":         DEFAULT_DELTA_T,
    "max_packets":     None,
}

GT_LABELS = ("SUPPORTS", "PARTIAL", "NEUTRAL", "CONTRADICTS")


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Entry:
    name: str
    pcap: str

    def _sibling(self, suffix: str) -> str:
        return os.path.join(os.path.dirname(self.pcap), self.name + suffix)

    @property
    def text_path(self) -> str:      return self._sibling(".txt")
    @property
    def steps_path(self) -> str:     return self._sibling("_steps.json")
    @property
    def clusters_path(self) -> str:  return self._sibling("_clusters.json")
    @property
    def grounding_path(self) -> str: return self._sibling("_grounding.json")
    @property
    def gt_path(self) -> str:        return self._sibling("_gt.json")

    def has(self, path: str) -> bool:
        return os.path.isfile(path)

    def description(self) -> Optional[str]:
        if not self.has(self.text_path):
            return None
        with open(self.text_path, "r", encoding="utf-8") as f:
            return f.read()

    def steps(self) -> list[Step]:
        return load_steps(self.steps_path) if self.has(self.steps_path) else []


def list_entries(dataset_dir: str = DATASET_DIR) -> list[Entry]:
    entries = []
    for fname in sorted(os.listdir(dataset_dir), key=str.lower):
        stem, ext = os.path.splitext(fname)
        if ext.lower() in PCAP_EXTENSIONS:
            entries.append(Entry(name=stem, pcap=os.path.join(dataset_dir, fname)))
    return entries


# ---------------------------------------------------------------------------
# Preprocessing (cached on disk)
# ---------------------------------------------------------------------------

def preprocess(entry: Entry, settings: Optional[dict] = None) -> dict:
    """Run the preprocessor on the entry's capture and cache the result."""
    from Preprocessor.preprocessor import run_preprocessing

    settings = {**DEFAULT_PREPROCESS_SETTINGS, **(settings or {})}
    description = entry.description() or ""
    with open(entry.pcap, "rb") as f:
        pcap_bytes = f.read()

    output = asdict(run_preprocessing(
        pcap_bytes=pcap_bytes,
        attack_description=description,
        **settings,
    ))
    payload = {
        "pcap": os.path.basename(entry.pcap),
        "settings": settings,
        "generated_at": _now(),
        "output": output,
    }
    _write_json(entry.clusters_path, payload)
    return payload


def load_clusters(entry: Entry) -> Optional[dict]:
    """Cached preprocessor payload {pcap, settings, generated_at, output}, or None."""
    return _read_json(entry.clusters_path)


# ---------------------------------------------------------------------------
# Grounding (cached on disk, all top-k candidates kept)
# ---------------------------------------------------------------------------

def run_grounding(
    entry: Entry,
    models: GrounderModels,
    top_k: int = DEFAULT_TOP_K_BIENCODER,
) -> dict:
    """
    Ground the entry's steps against its cached clusters and save the result.

    The grounder runs with neutral_threshold=0 so every top-k candidate is
    kept with its score; rethreshold() applies the real thresholds later.
    """
    clusters_payload = load_clusters(entry)
    if clusters_payload is None:
        raise FileNotFoundError(f"No cached clusters for {entry.name}; run preprocess first.")
    steps = entry.steps()
    if not steps:
        raise FileNotFoundError(f"No steps for {entry.name} ({entry.steps_path}).")

    output = ground(
        steps=steps,
        clusters=clusters_payload["output"]["clusters"],
        models=models,
        top_k=top_k,
        supports_threshold=DEFAULT_SUPPORTS_THRESHOLD,
        partial_threshold=DEFAULT_PARTIAL_THRESHOLD,
        neutral_threshold=0.0,
        ambiguity_threshold=DEFAULT_AMBIGUITY_THRESHOLD,
    )
    payload = {
        "pcap": os.path.basename(entry.pcap),
        "preprocess_settings": clusters_payload["settings"],
        "generated_at": _now(),
        "grounding": grounder_output_to_dict(output),
    }
    _write_json(entry.grounding_path, payload)
    return payload


def load_grounding(entry: Entry) -> Optional[dict]:
    """Cached grounding payload {pcap, preprocess_settings, generated_at, grounding}, or None."""
    return _read_json(entry.grounding_path)


def grounder_output_from_dict(data: dict) -> GrounderOutput:
    """Inverse of Grounder.grounder.grounder_output_to_dict."""
    groundings = []
    for sg in data["step_groundings"]:
        step = Step(**sg["step"])
        matched = [
            GroundingResult(**{**gr, "evidence_label": EvidenceLabel(gr["evidence_label"])})
            for gr in sg["matched_clusters"]
        ]
        groundings.append(StepGrounding(
            step=step,
            matched_clusters=matched,
            is_ambiguous=sg.get("is_ambiguous", False),
            is_ungrounded=sg.get("is_ungrounded", not matched),
            top_candidate_score=sg.get("top_candidate_score"),
        ))
    return GrounderOutput(
        step_groundings=groundings,
        threshold_used=data["threshold_used"],
        model_bi_encoder=data["model_bi_encoder"],
        model_cross_encoder=data["model_cross_encoder"],
        parameters=data.get("parameters", {}),
        clusters_scored=data.get("clusters_scored", 0),
        clusters_skipped_no_text=data.get("clusters_skipped_no_text", 0),
    )


def rethreshold(
    raw: GrounderOutput,
    supports_threshold: float = DEFAULT_SUPPORTS_THRESHOLD,
    partial_threshold: float = DEFAULT_PARTIAL_THRESHOLD,
    neutral_threshold: float = 0.40,
    ambiguity_threshold: float = DEFAULT_AMBIGUITY_THRESHOLD,
) -> GrounderOutput:
    """
    Apply thresholds to a grounding run that kept all top-k candidates.
    Mirrors the label / ungrounded / ambiguity rules in Grounder.grounder.
    """
    if not (neutral_threshold <= partial_threshold <= supports_threshold):
        raise ValueError("Thresholds must satisfy neutral <= partial <= supports")
    if raw.threshold_used > neutral_threshold:
        raise ValueError(
            f"Grounding was saved with neutral threshold {raw.threshold_used}; "
            f"cannot re-apply a lower one ({neutral_threshold})."
        )

    groundings = []
    for sg in raw.step_groundings:
        candidates = sg.matched_clusters        # rank order, all top-k
        kept = [
            replace(gr, evidence_label=_assign_evidence_label(gr.score, supports_threshold, partial_threshold))
            for gr in candidates if gr.score >= neutral_threshold
        ]
        is_ambiguous = (
            bool(kept) and len(candidates) >= 2
            and (candidates[0].score - candidates[1].score) < ambiguity_threshold
        )
        groundings.append(StepGrounding(
            step=sg.step,
            matched_clusters=kept,
            is_ambiguous=is_ambiguous,
            is_ungrounded=not kept,
            top_candidate_score=candidates[0].score if candidates else None,
        ))

    return replace(
        raw,
        step_groundings=groundings,
        threshold_used=neutral_threshold,
        parameters={
            **raw.parameters,
            "supports_threshold": supports_threshold,
            "partial_threshold": partial_threshold,
            "neutral_threshold": neutral_threshold,
            "ambiguity_threshold": ambiguity_threshold,
        },
    )


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def load_gt(entry: Entry) -> dict:
    """Ground-truth file contents, or an empty skeleton if none exists yet."""
    return _read_json(entry.gt_path) or {"annotations": [], "reviewed_steps": []}


def save_gt(
    entry: Entry,
    steps: list[Step],
    labels: dict[tuple[int, str], str],
    reviewed_steps: set[int],
    clusters_by_key: dict[str, dict],
    preprocess_settings: dict,
    annotator: Optional[str] = None,
) -> dict:
    """
    Write ground truth in annotator.py's format, plus reviewed_steps (steps
    the annotator finished, including explicit no-match steps) and the
    preprocessor settings the fingerprint keys belong to.

    labels: {(step_id, fingerprint_key): label} with label in GT_LABELS.
    """
    step_text = {s.step_id: s.text for s in steps}
    previous = {
        (a["step_id"], a["fingerprint_key"]): a
        for a in load_gt(entry).get("annotations", [])
    }
    now = _now()
    annotations = []
    for (step_id, fkey), label in sorted(labels.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        if label not in GT_LABELS:
            continue
        prev = previous.get((step_id, fkey))
        unchanged = prev is not None and prev.get("label") == label
        cluster = clusters_by_key.get(fkey, {})
        annotations.append({
            "step_id":         step_id,
            "step_text":       step_text.get(step_id, ""),
            "fingerprint_key": fkey,
            "cluster_text":    (cluster.get("metadata") or {}).get("cluster_text", ""),
            "label":           label,
            "annotated_at":    prev["annotated_at"] if unchanged else now,
            **({"annotator": annotator} if annotator else {}),
        })

    distribution: dict[str, int] = {}
    for a in annotations:
        distribution[a["label"]] = distribution.get(a["label"], 0) + 1

    data = {
        "entry":               entry.name,
        "pcap":                os.path.basename(entry.pcap),
        "annotated_at":        now,
        "preprocess_settings": preprocess_settings,
        "step_count":          len(steps),
        "cluster_count":       len(clusters_by_key),
        "reviewed_steps":      sorted(reviewed_steps),
        "annotation_count":    len(annotations),
        "label_distribution":  distribution,
        "annotations":         annotations,
    }
    _write_json(entry.gt_path, data)
    return data


# ---------------------------------------------------------------------------
# Display helper
# ---------------------------------------------------------------------------

def cluster_label(fingerprint_key: str) -> str:
    """Short human name for a fingerprint, e.g. 'DNS :53 · medium entropy'."""
    try:
        l4, state, l7, port, entropy, _bucket = json.loads(fingerprint_key)
    except (ValueError, TypeError):
        return fingerprint_key
    if l4 == "ARP" and state:
        _, op, mac = (state.split(":", 2) + ["", ""])[:3]
        name = {"1": "ARP request", "2": "ARP reply"}.get(op, f"ARP op {op}")
        return f"{name} · {mac}"
    if l4 == "ICMP" and state:
        _, t, c = (state.split(":") + ["", ""])[:3]
        name = {"8": "echo request", "0": "echo reply", "3": "unreachable",
                "5": "redirect", "11": "time exceeded"}.get(t, f"type {t}")
        return f"ICMP {name} ({t}/{c})"
    parts = [f"{l7 or l4}" + (f" :{port}" if port is not None else "")]
    if l4 == "TCP" and state:
        parts.append(state)
    if entropy:
        parts.append(f"{entropy.replace('_', ' ')} entropy")
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: str, data) -> None:
    # Write-then-rename so an interrupted run never leaves a truncated file.
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _status(entries: list[Entry]) -> None:
    def mark(e: Entry, p: str) -> str:
        return "yes" if e.has(p) else "-"
    print(f"{'capture':34} {'text':5} {'steps':6} {'clusters':9} {'grounding':10} {'gt':4}")
    for e in entries:
        print(f"{os.path.basename(e.pcap):34} {mark(e, e.text_path):5} {mark(e, e.steps_path):6} "
              f"{mark(e, e.clusters_path):9} {mark(e, e.grounding_path):10} {mark(e, e.gt_path):4}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the PAnGEA evaluation dataset in src/pcaps.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="show which files exist for each capture")
    b = sub.add_parser("build", help="preprocess and ground every capture")
    b.add_argument("--only", nargs="*", help="capture names (without extension)")
    b.add_argument("--no-ground", action="store_true", help="preprocess only")
    b.add_argument("--force", action="store_true", help="recompute even if cached")
    b.add_argument("--max-packets", type=int, default=None,
                   help="cap packets per capture (recorded in the settings)")
    b.add_argument("--top-k", type=int, default=DEFAULT_TOP_K_BIENCODER)
    parser.add_argument("--dataset-dir", default=DATASET_DIR)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    entries = list_entries(args.dataset_dir)
    if args.cmd == "status":
        _status(entries)
        return

    if args.only:
        entries = [e for e in entries if e.name in set(args.only)]
    settings = {**DEFAULT_PREPROCESS_SETTINGS, "max_packets": args.max_packets}

    models = None
    for e in entries:
        cached = load_clusters(e)
        if args.force or cached is None or cached["settings"] != settings:
            logger.info("Preprocessing %s ...", e.name)
            cached = preprocess(e, settings)
        stats = cached["output"]["compression_stats"]
        logger.info("%s: %d packets -> %d clusters", e.name,
                    stats["raw_packet_count_in"], stats["cluster_count"])

        if args.no_ground or not e.has(e.steps_path):
            continue
        g = load_grounding(e)
        if args.force or g is None or g["preprocess_settings"] != cached["settings"]:
            if models is None:
                logger.info("Loading grounder models ...")
                models = GrounderModels.default()
            logger.info("Grounding %s ...", e.name)
            run_grounding(e, models, top_k=args.top_k)

    _status(list_entries(args.dataset_dir))


if __name__ == "__main__":
    main()
