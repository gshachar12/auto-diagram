"""
PAnGEA — Preprocessor orchestrator.

Exposes a single public function:

    run_preprocessing(pcap_bytes, attack_description, token_budget, ...) -> ReducerOutput

This is the entry point called by pipeline_runner.py. It owns:
  - the pcap loading and iteration loop (the only place pyshark is touched
    outside of layer1_dissection.py, which only receives individual packets)
  - the budget tracking loop
  - wiring all four layers together in order
  - constructing the final ReducerOutput

Layer responsibilities (this file only orchestrates; logic lives in layers):
  layer0  extract_attack_context   — description → AttackContext
  layer1  dissect_packet           — pyshark pkt → PacketFeatures
  layer2  build_fingerprint_key    — PacketFeatures → fingerprint key string
  layer3  process_packet           — packet + key → update Cluster dict
          finalise_clusters        — Cluster dict → list[Cluster] with IAT stats
  layer4  analyse_clusters         — list[Cluster] → enriched with metadata + tiers

Design constraints honoured here:
  R1  Every ReducedItem carries packet_id + timestamp.
  R2  attack_description is passed only to layer0; never to layers 1–4.
  R3  Aggregate updated even under budget pressure (layer3 responsibility).
  R4  Chronological order preserved (dict insertion order, Python 3.7+).
  R5  Budget exceeded → processing stops, partial result returned with
      EXCEEDED status and detail string.
  R6  No attack-type branching here or in any layer.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import tempfile
from typing import Callable, Optional

import pyshark

from Preprocessor.layer0_attack_context import extract_attack_context
from Preprocessor.layer1_dissection import dissect_packet
from Preprocessor.layer2_fingerprint import build_fingerprint_key, DEFAULT_DELTA_T
from Preprocessor.layer3_clustering import process_packet, finalise_clusters
from Preprocessor.layer4_analysis import analyse_clusters
from Preprocessor.schemas import (
    BudgetStatus,
    Cluster,
    CompressionStats,
    ReducerOutput,
)
from Preprocessor.token_budget import estimate_item_tokens

logger = logging.getLogger(__name__)

LLMClient = Callable[[str], str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_preprocessing(
    pcap_bytes: bytes,
    attack_description: str,
    token_budget: int,
    filtering_limit: int = 3,
    delta_t: float = DEFAULT_DELTA_T,
    max_packets: Optional[int] = None,
    attack_context_llm_client: Optional[LLMClient] = None,
) -> ReducerOutput:
    """
    Full preprocessing pipeline.

    Args:
        pcap_bytes:                   raw PCAP file contents.
        attack_description:           free-text description. Passed ONLY to
                                      layer0; never reaches layers 1–4 (R2).
        token_budget:                 max tokens for ReducedItems output.
                                      Computed upstream (pipeline_runner.py).
        filtering_limit:              max representative ReducedItems per cluster.
        delta_t:                      temporal bucket size in seconds. Packets
                                      more than delta_t apart with the same
                                      fingerprint go into separate clusters.
        max_packets:                  optional hard cap on packets processed.
        attack_context_llm_client:    optional LLM backend for layer0.
                                      If None, keyword fallback is used.

    Returns:
        ReducerOutput — see schemas.py. Always returns a result; budget
        exhaustion is reported in budget_status, not as an exception.
    """

    # ------------------------------------------------------------------
    # Layer 0 — extract attack context from description (R2 boundary)
    # ------------------------------------------------------------------
    attack_context = extract_attack_context(
        description=attack_description,
        llm_client=attack_context_llm_client,
    )
    logger.info(
        "AttackContext: protocols=%s behaviors=%s indicators=%s",
        [p.value for p in attack_context.suspected_protocols],
        [b.value for b in attack_context.suspected_behaviors],
        [i.value for i in attack_context.target_indicators],
    )

    # ------------------------------------------------------------------
    # PCAP loading
    # ------------------------------------------------------------------
    loop = asyncio.new_event_loop()
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    pcap_path = tmp.name

    clusters: dict[str, Cluster] = {}
    _iat_scratch: dict[str, list[float]] = {}
    _last_ts: dict[str, float] = {}
    handshakes_completed: set[str] = set()

    total_raw_packets    = 0
    dropped_parse_failures = 0
    running_tokens       = 0
    total_bytes          = 0
    budget_status        = BudgetStatus.WITHIN_BUDGET
    budget_status_detail: Optional[str] = None

    try:
        tmp.write(pcap_bytes)
        tmp.close()

        cap = pyshark.FileCapture(
            pcap_path,
            eventloop=loop,
            keep_packets=False,
        )

        try:
            for pkt in cap:
                total_raw_packets += 1

                if max_packets is not None and total_raw_packets > max_packets:
                    break

                # ----------------------------------------------------------
                # Layer 1 — dissect
                # ----------------------------------------------------------
                features = dissect_packet(pkt)
                if features is None:
                    dropped_parse_failures += 1
                    continue

                total_bytes += features.total_length

                # ----------------------------------------------------------
                # Layer 2 — fingerprint
                # ----------------------------------------------------------
                fkey = build_fingerprint_key(
                    features=features,
                    handshakes_completed=handshakes_completed,
                    delta_t=delta_t,
                )
                if fkey is None:
                    dropped_parse_failures += 1
                    continue

                # ----------------------------------------------------------
                # Layer 3 — cluster
                # ----------------------------------------------------------
                running_tokens, status, detail = process_packet(
                    features=features,
                    fingerprint_key=fkey,
                    clusters=clusters,
                    _iat_scratch=_iat_scratch,
                    _last_ts=_last_ts,
                    filtering_limit=filtering_limit,
                    token_budget=token_budget,
                    running_tokens=running_tokens,
                )

                if status == BudgetStatus.EXCEEDED:
                    budget_status = BudgetStatus.EXCEEDED
                    budget_status_detail = detail
                    # Do NOT break — we continue iterating to update aggregates.
                    # layer3.process_packet skips ReducedItem creation when
                    # budget is exceeded but still updates aggregate (R3).

        finally:
            cap.close()

    finally:
        try:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
        except OSError:
            pass
        loop.close()

    # ------------------------------------------------------------------
    # Layer 3 finalisation — IAT stats
    # ------------------------------------------------------------------
    cluster_list = finalise_clusters(clusters, _iat_scratch)

    # ------------------------------------------------------------------
    # Layer 4 — analysis, metadata, tier assignment
    # ------------------------------------------------------------------
    cluster_list = analyse_clusters(
        clusters=cluster_list,
        attack_context=attack_context,
        total_bytes=total_bytes,
    )

    # ------------------------------------------------------------------
    # Assemble output
    # ------------------------------------------------------------------
    total_items = sum(len(c.representative_items) for c in cluster_list)
    compression_ratio = (
        1.0 - (total_items / total_raw_packets)
        if total_raw_packets > 0 else 0.0
    )

    stats = CompressionStats(
        raw_packet_count_in=total_raw_packets,
        packet_count_out=total_items,
        cluster_count=len(cluster_list),
        estimated_tokens_out=running_tokens,
        dropped_parse_failures=dropped_parse_failures,
        compression_ratio=round(compression_ratio, 4),
    )

    return ReducerOutput(
        clusters=cluster_list,
        compression_stats=stats,
        budget_status=budget_status,
        attack_context=attack_context,
        budget_status_detail=budget_status_detail,
        filter_string_used=None,   # filter_generator removed; kept for pipeline compat
    )
