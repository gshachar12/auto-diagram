"""
PAnGEA — Dataset Builder.

Responsibility: given a dataset directory, run the full preprocessor on
each PCAP and save clusters + serializations to disk. Also runs the step
extractor on each text description and saves extracted steps.

Directory convention:
  dataset/
  ├── pcaps/      pcap_[N]_[desc].pcap
  ├── texts/      text_[N]_[desc].txt
  ├── extracted/  extracted_[N]_[desc].json   ← step extractor output
  ├── clusters/   clusters_[N]_[desc].json    ← preprocessor output
  └── ground_truth/ gt_[N]_[desc].json        ← annotation (written by annotator.py)

The number N in the filename is the pairing key — pcap_001 pairs with
text_001, extracted_001, clusters_001, and gt_001.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Callable, Optional

from Preprocessor.preprocessor import run_preprocessing
from Preprocessor.layer4_serialization import serialize_cluster
from Grounder.step_extractor import extract_steps, load_steps
from Grounder.schemas import Step

logger = logging.getLogger(__name__)

LLMClient = Callable[[str], str]


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def build_clusters(
    dataset_dir: str,
    token_budget: int = 25000,
    filtering_limit: int = 3,
    attack_context_llm_client: Optional[LLMClient] = None,
    overwrite: bool = False,
) -> None:
    """
    For each pcap_N_*.pcap in dataset/pcaps/, run the preprocessor and
    save clusters_N_*.json to dataset/clusters/.

    Pairs each PCAP with text_N_*.txt for the attack description.
    If no matching text file exists, uses an empty description.
    """
    pcaps_dir    = os.path.join(dataset_dir, "pcaps")
    texts_dir    = os.path.join(dataset_dir, "texts")
    clusters_dir = os.path.join(dataset_dir, "clusters")
    os.makedirs(clusters_dir, exist_ok=True)

    pcap_files = _list_files(pcaps_dir, ".pcap")
    if not pcap_files:
        logger.warning("No PCAP files found in %s", pcaps_dir)
        return

    for pcap_path in pcap_files:
        pcap_name = os.path.basename(pcap_path)
        number    = _extract_number(pcap_name)
        desc      = _extract_desc(pcap_name, ".pcap")

        out_name = f"clusters_{number}_{desc}.json"
        out_path = os.path.join(clusters_dir, out_name)

        if os.path.exists(out_path) and not overwrite:
            logger.info("Skipping %s (already exists)", out_name)
            continue

        # Find matching text file
        text_path = _find_paired_file(texts_dir, number, ".txt")
        description = ""
        if text_path:
            with open(text_path, "r", encoding="utf-8") as f:
                description = f.read().strip()
        else:
            logger.warning("No text file found for number %s", number)

        logger.info("Processing %s ...", pcap_name)
        with open(pcap_path, "rb") as f:
            pcap_bytes = f.read()

        try:
            output = run_preprocessing(
                pcap_bytes=pcap_bytes,
                attack_description=description,
                token_budget=token_budget,
                filtering_limit=filtering_limit,
                attack_context_llm_client=attack_context_llm_client,
            )
        except Exception as exc:
            logger.error("Preprocessor failed on %s: %s", pcap_name, exc)
            continue

        # Serialize clusters (must happen after full analysis)
        for cluster in output.clusters:
            cluster.metadata.cluster_text = serialize_cluster(cluster)

        _save_clusters(output, out_path)
        logger.info("Saved %d clusters to %s", len(output.clusters), out_path)


def build_extracted_steps(
    dataset_dir: str,
    llm_client: LLMClient,
    overwrite: bool = False,
) -> None:
    """
    For each text_N_*.txt in dataset/texts/, extract steps and save
    extracted_N_*.json to dataset/extracted/.
    """
    texts_dir     = os.path.join(dataset_dir, "texts")
    extracted_dir = os.path.join(dataset_dir, "extracted")
    os.makedirs(extracted_dir, exist_ok=True)

    text_files = _list_files(texts_dir, ".txt")
    if not text_files:
        logger.warning("No text files found in %s", texts_dir)
        return

    for text_path in text_files:
        text_name = os.path.basename(text_path)
        number    = _extract_number(text_name)
        desc      = _extract_desc(text_name, ".txt")

        out_name = f"extracted_{number}_{desc}.json"
        out_path = os.path.join(extracted_dir, out_name)

        if os.path.exists(out_path) and not overwrite:
            logger.info("Skipping %s (already exists)", out_name)
            continue

        with open(text_path, "r", encoding="utf-8") as f:
            description = f.read().strip()

        logger.info("Extracting steps from %s ...", text_name)
        steps = extract_steps(
            description=description,
            llm_client=llm_client,
            save_path=out_path,
        )
        logger.info("Saved %d steps to %s", len(steps), out_path)


def load_dataset_entry(
    dataset_dir: str,
    number: str,
) -> dict:
    """
    Load all artifacts for a given entry number.
    Returns a dict with keys: steps, clusters, ground_truth (if exists).
    """
    extracted_dir    = os.path.join(dataset_dir, "extracted")
    clusters_dir     = os.path.join(dataset_dir, "clusters")
    ground_truth_dir = os.path.join(dataset_dir, "ground_truth")

    extracted_path = _find_paired_file(extracted_dir, number, ".json")
    clusters_path  = _find_paired_file(clusters_dir,  number, ".json")
    gt_path        = _find_paired_file(ground_truth_dir, number, ".json")

    result = {}

    if extracted_path:
        result["steps"] = load_steps(extracted_path)
    else:
        logger.warning("No extracted steps found for number %s", number)
        result["steps"] = []

    if clusters_path:
        result["clusters"] = _load_clusters(clusters_path)
    else:
        logger.warning("No clusters found for number %s", number)
        result["clusters"] = []

    if gt_path:
        with open(gt_path, "r", encoding="utf-8") as f:
            result["ground_truth"] = json.load(f)
    else:
        result["ground_truth"] = None

    return result


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _save_clusters(output, path: str) -> None:
    """Save ReducerOutput clusters to JSON."""
    data = {
        "budget_status": output.budget_status.value,
        "compression_stats": {
            "raw_packet_count_in":    output.compression_stats.raw_packet_count_in,
            "packet_count_out":       output.compression_stats.packet_count_out,
            "cluster_count":          output.compression_stats.cluster_count,
            "compression_ratio":      output.compression_stats.compression_ratio,
            "dropped_parse_failures": output.compression_stats.dropped_parse_failures,
        },
        "attack_context": {
            "suspected_protocols": [p.value for p in output.attack_context.suspected_protocols]
                                    if output.attack_context else [],
            "suspected_behaviors": [b.value for b in output.attack_context.suspected_behaviors]
                                    if output.attack_context else [],
            "target_indicators":   [i.value for i in output.attack_context.target_indicators]
                                    if output.attack_context else [],
        } if output.attack_context else {},
        "clusters": [_serialize_cluster_to_dict(c) for c in output.clusters],
        "ip_summary": output.ip_summary,
        "anomalies":  output.anomalies,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _serialize_cluster_to_dict(cluster) -> dict:
    agg  = cluster.aggregate
    meta = cluster.metadata
    return {
        "fingerprint_key": cluster.fingerprint_key,
        "cluster_text":    meta.cluster_text if meta else None,
        "is_singleton":    cluster.is_singleton,
        "representative_items": [
            {
                "packet_id": item.packet_id,
                "timestamp": item.timestamp,
                "protocol":  item.protocol,
                "src":       item.src,
                "dst":       item.dst,
                "length":    item.length,
                "info":      item.info,
            }
            for item in cluster.representative_items
        ],
        "aggregate": {
            "count":               agg.count,
            "total_bytes":         agg.total_bytes,
            "unique_sources":      agg.unique_sources,
            "unique_destinations": agg.unique_destinations,
            "first_seen":          agg.first_seen,
            "last_seen":           agg.last_seen,
            "iat_mean":            agg.iat_mean,
            "iat_std":             agg.iat_std,
            "iat_min":             agg.iat_min,
            "iat_max":             agg.iat_max,
        } if agg else None,
        "metadata": {
            "tier":             meta.tier.value if meta and meta.tier else None,
            "traffic_share":    meta.traffic_share if meta else None,
            "tfidf_weight":     meta.tfidf_weight  if meta else None,
            "context_match":    meta.context_match  if meta else False,
            "dst_port_class":   meta.dst_port_class.value
                                if meta and meta.dst_port_class else None,
            "dst_port_service": meta.dst_port_service if meta else None,
            "zscore_anomalies": meta.zscore_anomalies if meta else {},
        } if meta else {},
    }


def _load_clusters(path: str) -> list[dict]:
    """Load clusters from saved JSON. Returns raw dicts for annotation."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("clusters", [])


# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------

def _list_files(directory: str, extension: str) -> list[str]:
    if not os.path.isdir(directory):
        return []
    return sorted([
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.endswith(extension)
    ])


def _extract_number(filename: str) -> str:
    """Extract the numeric part from pcap_001_desc.pcap → '001'."""
    match = re.match(r"[a-z_]+_(\d+)_", filename)
    return match.group(1) if match else "000"


def _extract_desc(filename: str, extension: str) -> str:
    """Extract description part from pcap_001_syn_flood.pcap → 'syn_flood'."""
    base = filename.replace(extension, "")
    match = re.match(r"[a-z_]+_\d+_(.*)", base)
    return match.group(1) if match else "unknown"


def _find_paired_file(directory: str, number: str, extension: str) -> Optional[str]:
    """Find a file in directory whose name contains the given number."""
    if not os.path.isdir(directory):
        return None
    pattern = re.compile(rf"_0*{int(number):d}_.*\{extension}$")
    for f in os.listdir(directory):
        if pattern.search(f):
            return os.path.join(directory, f)
    return None
