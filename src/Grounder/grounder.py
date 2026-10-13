"""
PAnGEA — Grounder.

Responsibility: match each extracted Step to the cluster(s) that provide
evidence for it, producing a scored, ranked, reproducible grounding.

Two-stage architecture:
  Stage 1 — Bi-encoder (BAAI/bge-large-en-v1.5)
    Embeds all cluster serializations once per call (reusable across steps).
    Embeds every step query in one batch, prefixed with the BGE retrieval
    instruction (asymmetric query → passage search).
    Cosine similarity → top-k candidates.

  Stage 2 — Cross-encoder (BAAI/bge-reranker-large)
    Scores each (step_text, cluster_text) pair jointly.
    Raw logits are requested explicitly and sigmoid-normalised once here,
    so the score scale does not depend on the sentence-transformers version
    (newer versions apply a sigmoid inside predict() by default; applying a
    second one would squash every score into [0.5, 0.73]).

Evidence label assignment:
  score >= supports_threshold  → SUPPORTS
  score >= partial_threshold   → PARTIAL
  score >= neutral_threshold   → NEUTRAL
  score <  neutral_threshold   → cluster not returned (below threshold)

No-match detection:
  No cluster scores above neutral_threshold → StepGrounding.is_ungrounded = True
  Gap between rank-1 and rank-2 cross-encoder scores < ambiguity_threshold
  → is_ambiguous = True

Design constraints:
  - Fully deterministic given fixed model weights and fixed cluster
    serializations (stable sort, ties broken by original cluster order).
  - No LLM dependency in this module.
  - All thresholds are parameters with documented defaults.
  - Model names are exact Hugging Face ids, never aliases.
"""
from __future__ import annotations

import inspect
import json
import logging
import math
import os
from dataclasses import asdict, dataclass
from typing import Any, Optional, Sequence, Union

from Preprocessor.schemas import Cluster
from Grounder.schemas import (
    EvidenceLabel, GrounderOutput, GroundingResult, Step, StepGrounding,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default thresholds — calibrate on labeled data once available
# ---------------------------------------------------------------------------
DEFAULT_SUPPORTS_THRESHOLD  = 0.75
DEFAULT_PARTIAL_THRESHOLD   = 0.55
DEFAULT_NEUTRAL_THRESHOLD   = 0.40   # below this → not returned
DEFAULT_AMBIGUITY_THRESHOLD = 0.10   # gap between rank-1 and rank-2
DEFAULT_TOP_K_BIENCODER     = 10     # candidates passed to cross-encoder
DEFAULT_BI_ENCODER_MODEL    = "BAAI/bge-large-en-v1.5"
DEFAULT_CROSS_ENCODER_MODEL = "BAAI/bge-reranker-large"
# Query-side instruction recommended by BAAI for bge-*-v1.5 retrieval.
# Applied to step texts only (queries), never to cluster texts (passages).
DEFAULT_QUERY_INSTRUCTION   = "Represent this sentence for searching relevant passages: "

# A cluster is either a Preprocessor Cluster or its dict form
# (dataclasses.asdict output, or dataset_builder's clusters_*.json entries).
ClusterLike = Union[Cluster, dict]


# ---------------------------------------------------------------------------
# Model container — loaded once, reused across calls
# ---------------------------------------------------------------------------

@dataclass
class GrounderModels:
    """
    Holds loaded bi-encoder and cross-encoder models.
    Create once and pass to ground() to avoid reloading on every call.
    """
    bi_encoder_model:    str
    cross_encoder_model: str
    device:              Optional[str] = None   # None → sentence-transformers picks
    _bi_encoder:    object = None   # SentenceTransformer instance
    _cross_encoder: object = None   # CrossEncoder instance

    def load(self) -> "GrounderModels":
        """Load both models. Call once before first use."""
        # The grounder is PyTorch-only. Without this, transformers 4.x imports
        # any installed TensorFlow and fails on Keras 3.
        os.environ.setdefault("USE_TF", "0")
        try:
            from sentence_transformers import SentenceTransformer, CrossEncoder
        except ImportError:
            raise ImportError(
                "sentence-transformers is required for the grounder. "
                "Install with: pip install sentence-transformers"
            )
        logger.info("Loading bi-encoder: %s", self.bi_encoder_model)
        self._bi_encoder = SentenceTransformer(self.bi_encoder_model, device=self.device)

        logger.info("Loading cross-encoder: %s", self.cross_encoder_model)
        self._cross_encoder = CrossEncoder(self.cross_encoder_model, device=self.device)

        return self

    @classmethod
    def default(cls, device: Optional[str] = None) -> "GrounderModels":
        return cls(
            bi_encoder_model=DEFAULT_BI_ENCODER_MODEL,
            cross_encoder_model=DEFAULT_CROSS_ENCODER_MODEL,
            device=device,
        ).load()

    def cross_encoder_logits(self, pairs: list[list[str]]) -> list[float]:
        """
        Raw (pre-activation) cross-encoder scores for each pair.

        The keyword for overriding the activation was renamed between
        sentence-transformers releases (activation_fct → activation_fn),
        so it is resolved from the installed predict() signature.
        """
        import torch

        params = inspect.signature(self._cross_encoder.predict).parameters
        kwargs: dict[str, Any] = {"show_progress_bar": False}
        for name in ("activation_fn", "activation_fct"):
            if name in params:
                kwargs[name] = torch.nn.Identity()
                break
        else:
            raise RuntimeError(
                "Installed sentence-transformers CrossEncoder.predict() exposes "
                "no activation override; cannot obtain raw logits reproducibly."
            )
        raw = self._cross_encoder.predict(pairs, **kwargs)
        return [float(s) for s in raw]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def ground(
    steps: list[Step],
    clusters: Sequence[ClusterLike],
    models: Optional[GrounderModels] = None,
    top_k: int = DEFAULT_TOP_K_BIENCODER,
    supports_threshold:  float = DEFAULT_SUPPORTS_THRESHOLD,
    partial_threshold:   float = DEFAULT_PARTIAL_THRESHOLD,
    neutral_threshold:   float = DEFAULT_NEUTRAL_THRESHOLD,
    ambiguity_threshold: float = DEFAULT_AMBIGUITY_THRESHOLD,
    query_instruction:   str   = DEFAULT_QUERY_INSTRUCTION,
) -> GrounderOutput:
    """
    Match each Step to the clusters that provide evidence for it.

    Args:
        steps:     extracted steps from the input text.
        clusters:  preprocessor clusters (Cluster objects or their dict form);
                   only those with a populated cluster_text are scorable.
        models:    loaded GrounderModels. Loaded with defaults if None.
        top_k:     number of bi-encoder candidates passed to cross-encoder.
        supports_threshold:  minimum score for SUPPORTS label.
        partial_threshold:   minimum score for PARTIAL label.
        neutral_threshold:   minimum score to be returned at all.
        ambiguity_threshold: max rank-1/rank-2 score gap that flags ambiguity.
        query_instruction:   prefix added to step text for the bi-encoder only.

    Returns:
        GrounderOutput with full grounding results and convenience properties.
    """
    if not (neutral_threshold <= partial_threshold <= supports_threshold):
        raise ValueError(
            "Thresholds must satisfy neutral <= partial <= supports, got "
            f"{neutral_threshold} / {partial_threshold} / {supports_threshold}"
        )
    if top_k < 1:
        raise ValueError(f"top_k must be >= 1, got {top_k}")

    if models is None:
        models = GrounderModels.default()

    def _output(groundings: list[StepGrounding], n_scorable: int, n_total: int) -> GrounderOutput:
        return GrounderOutput(
            step_groundings=groundings,
            threshold_used=neutral_threshold,
            model_bi_encoder=models.bi_encoder_model,
            model_cross_encoder=models.cross_encoder_model,
            parameters={
                "top_k": top_k,
                "supports_threshold": supports_threshold,
                "partial_threshold": partial_threshold,
                "neutral_threshold": neutral_threshold,
                "ambiguity_threshold": ambiguity_threshold,
                "query_instruction": query_instruction,
            },
            clusters_scored=n_scorable,
            clusters_skipped_no_text=n_total - n_scorable,
        )

    # Only clusters that have been serialized can be scored. Skipped clusters
    # are counted in the output (no silent drops).
    scorable = [
        (key, text) for key, text in (_cluster_key_and_text(c) for c in clusters)
        if text
    ]
    if len(scorable) < len(clusters):
        logger.warning("%d of %d clusters have no cluster_text and were not scored.",
                       len(clusters) - len(scorable), len(clusters))
    if not steps:
        return _output([], len(scorable), len(clusters))
    if not scorable:
        logger.warning("No clusters have cluster_text. Run layer4_serialization first.")
        return _output(
            [StepGrounding(step=s, matched_clusters=[], is_ungrounded=True) for s in steps],
            0, len(clusters),
        )

    import numpy as np

    keys  = [k for k, _ in scorable]
    texts = [t for _, t in scorable]

    # Stage 1 — encode all cluster texts once, all step queries in one batch
    logger.info("Encoding %d cluster texts and %d steps with bi-encoder...",
                len(texts), len(steps))
    cluster_emb = models._bi_encoder.encode(
        texts, normalize_embeddings=True, show_progress_bar=False,
    )
    step_emb = models._bi_encoder.encode(
        [query_instruction + s.text for s in steps],
        normalize_embeddings=True, show_progress_bar=False,
    )
    similarities = np.asarray(step_emb) @ np.asarray(cluster_emb).T   # (steps, clusters)

    groundings = [
        _ground_one_step(
            step=step,
            similarities=similarities[i],
            keys=keys,
            texts=texts,
            models=models,
            top_k=top_k,
            supports_threshold=supports_threshold,
            partial_threshold=partial_threshold,
            neutral_threshold=neutral_threshold,
            ambiguity_threshold=ambiguity_threshold,
        )
        for i, step in enumerate(steps)
    ]
    return _output(groundings, len(scorable), len(clusters))


# ---------------------------------------------------------------------------
# Per-step grounding
# ---------------------------------------------------------------------------

def _ground_one_step(
    step: Step,
    similarities,
    keys: list[str],
    texts: list[str],
    models: GrounderModels,
    top_k: int,
    supports_threshold: float,
    partial_threshold: float,
    neutral_threshold: float,
    ambiguity_threshold: float,
) -> StepGrounding:
    import numpy as np

    # Stage 1 — top-k by cosine similarity. Stable sort on the negated scores
    # keeps ties in original cluster order (R4, reproducibility).
    top_idx = np.argsort(-similarities, kind="stable")[:top_k]

    # Stage 2 — cross-encoder on (step, candidate) pairs
    logits = models.cross_encoder_logits([[step.text, texts[i]] for i in top_idx])
    scored = [
        (_sigmoid(logit), int(i), float(similarities[i]))
        for logit, i in zip(logits, top_idx)
    ]
    # Sort by score descending; Python's sort is stable, so ties keep
    # bi-encoder order.
    scored.sort(key=lambda x: -x[0])

    results: list[GroundingResult] = []
    for rank, (score, idx, bi_score) in enumerate(scored, start=1):
        if score < neutral_threshold:
            break
        next_score = scored[rank][0] if rank < len(scored) else 0.0
        results.append(GroundingResult(
            cluster_fingerprint_key=keys[idx],
            cluster_text=texts[idx],
            score=round(score, 4),
            rank=rank,
            evidence_label=_assign_evidence_label(score, supports_threshold, partial_threshold),
            score_gap=round(score - next_score, 4),
            bi_encoder_score=round(bi_score, 4),
        ))

    # Ambiguity compares rank-1 against the rank-2 candidate, whether or not
    # rank-2 cleared the neutral threshold.
    is_ambiguous = (
        bool(results)
        and len(scored) >= 2
        and (scored[0][0] - scored[1][0]) < ambiguity_threshold
    )

    return StepGrounding(
        step=step,
        matched_clusters=results,
        is_ungrounded=not results,
        is_ambiguous=is_ambiguous,
        top_candidate_score=round(scored[0][0], 4) if scored else None,
    )


def _assign_evidence_label(
    score: float,
    supports_threshold: float,
    partial_threshold: float,
) -> EvidenceLabel:
    if score >= supports_threshold:
        return EvidenceLabel.SUPPORTS
    if score >= partial_threshold:
        return EvidenceLabel.PARTIAL
    return EvidenceLabel.NEUTRAL


def _sigmoid(x: float) -> float:
    # Numerically stable for large |x|.
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def _cluster_key_and_text(cluster: ClusterLike) -> tuple[str, Optional[str]]:
    if isinstance(cluster, dict):
        meta = cluster.get("metadata") or {}
        # dataset_builder stores cluster_text at top level; asdict() nests it.
        text = cluster.get("cluster_text") or meta.get("cluster_text")
        return cluster["fingerprint_key"], text
    meta = cluster.metadata
    return cluster.fingerprint_key, (meta.cluster_text if meta else None)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def grounder_output_to_dict(output: GrounderOutput) -> dict:
    """JSON-ready dict: full results plus the {step_id: [...]} mapping."""
    data = asdict(output)
    data["grounding_dict"] = {str(k): v for k, v in output.grounding_dict.items()}
    data["ungrounded_step_ids"] = [s.step_id for s in output.ungrounded_steps]
    data["ambiguous_step_ids"]  = [s.step_id for s in output.ambiguous_steps]
    return data


def save_grounding(output: GrounderOutput, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(grounder_output_to_dict(output), f, indent=2, ensure_ascii=False)
    logger.info("Saved grounding for %d steps to %s", len(output.step_groundings), path)
