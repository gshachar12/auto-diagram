"""
PAnGEA Evaluator -- coreference metrics (MUC, B-cubed, CEAF).

Measures how well the system's actor clustering matches gold, given
clusters already determined by content-based alignment (see alignment.py)
-- NOT by actor_id or resolved IP.

Input shape: both gold and system clusters are represented the same way --
a list of clusters, each cluster being a set of "mention ids". A mention
here is simply an index into a shared list of all system-actor items (the
mentions are the SYSTEM's extracted actors; gold clusters group them
according to which real-world entity each was aligned to). A system actor
with no gold alignment at all is its own singleton cluster in the "key"
side only implicitly -- see `build_clusters_from_alignment` for exactly
how this is constructed.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import linear_sum_assignment

from .alignment import AlignmentResult


@dataclass
class CorefScore:
    precision: float
    recall: float
    f1: float


def build_clusters_from_alignment(
    n_system: int, n_gold: int, alignment: AlignmentResult,
) -> tuple[list[set[int]], list[set[int]]]:
    """
    Builds (system_clusters, gold_clusters) over a SHARED mention space --
    the mentions are the system's extracted actors (indices 0..n_system-1).

    gold_clusters[g] = the set of system-actor indices aligned to gold
    entity g (can be empty -- a gold entity the system never extracted at
    all; can have >1 member -- fragmentation).

    system_clusters: each system actor that WAS aligned to some gold
    entity is grouped with every other system actor aligned to that SAME
    entity (i.e. system_clusters mirror gold_clusters for aligned actors).
    A system actor that was NOT aligned to anything (a spurious/extra
    actor) forms its own singleton cluster -- it still needs to exist in
    the mention space for precision to correctly penalize it.
    """
    system_to_gold = alignment.system_to_gold
    gold_clusters: list[set[int]] = [set() for _ in range(n_gold)]
    for sys_idx, gold_idx in system_to_gold.items():
        if gold_idx is not None:
            gold_clusters[gold_idx].add(sys_idx)

    # System clusters: group by aligned gold entity; singleton for unaligned.
    cluster_by_gold: dict[int, set[int]] = {}
    system_clusters: list[set[int]] = []
    seen = set()
    for sys_idx, gold_idx in system_to_gold.items():
        if gold_idx is None:
            system_clusters.append({sys_idx})
            seen.add(sys_idx)
        else:
            cluster_by_gold.setdefault(gold_idx, set()).add(sys_idx)
    for cluster in cluster_by_gold.values():
        system_clusters.append(cluster)
        seen.update(cluster)
    for i in range(n_system):
        if i not in seen:
            system_clusters.append({i})

    return system_clusters, gold_clusters


def muc_score(system_clusters: list[set[int]], gold_clusters: list[set[int]]) -> CorefScore:
    """
    MUC (Vilain et al., 1995) -- link-based. Ignores singleton clusters
    entirely (both for precision and recall), since a singleton has no
    links to count. Known bias: favors systems producing fewer/larger
    clusters.
    """
    def _score(clusters_a: list[set[int]], clusters_b: list[set[int]]) -> float:
        numerator = 0.0
        denominator = 0.0
        for a in clusters_a:
            if len(a) < 2:
                continue
            # partition a's members according to clusters_b
            partitions = 0
            covered = set()
            for m in a:
                if m in covered:
                    continue
                for b in clusters_b:
                    if m in b:
                        covered.update(a & b)
                        partitions += 1
                        break
                else:
                    partitions += 1
                    covered.add(m)
            numerator += len(a) - partitions
            denominator += len(a) - 1
        return numerator / denominator if denominator > 0 else 0.0

    recall = _score(gold_clusters, system_clusters)
    precision = _score(system_clusters, gold_clusters)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return CorefScore(precision, recall, f1)


def b_cubed_score(system_clusters: list[set[int]], gold_clusters: list[set[int]]) -> CorefScore:
    """B-cubed (Bagga & Baldwin, 1998) -- per-mention precision/recall,
    averaged over all mentions. Unlike MUC, singletons count fully."""
    all_mentions = set()
    for c in system_clusters:
        all_mentions |= c
    for c in gold_clusters:
        all_mentions |= c

    def _cluster_containing(m: int, clusters: list[set[int]]) -> set[int]:
        for c in clusters:
            if m in c:
                return c
        return {m}  # mention with no cluster at all -> treat as its own singleton

    precisions, recalls = [], []
    for m in all_mentions:
        sys_c = _cluster_containing(m, system_clusters)
        gold_c = _cluster_containing(m, gold_clusters)
        overlap = len(sys_c & gold_c)
        precisions.append(overlap / len(sys_c) if sys_c else 0.0)
        recalls.append(overlap / len(gold_c) if gold_c else 0.0)

    precision = float(np.mean(precisions)) if precisions else 0.0
    recall = float(np.mean(recalls)) if recalls else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return CorefScore(precision, recall, f1)


def ceaf_score(system_clusters: list[set[int]], gold_clusters: list[set[int]]) -> CorefScore:
    """
    CEAF-mention (Luo, 2005) -- finds the OPTIMAL one-to-one alignment
    between system and gold clusters (via the Hungarian algorithm,
    maximizing total overlap), then scores based on that alignment alone.
    Known bias: a system cluster that "loses" the optimal-alignment
    competition for its best-matching gold cluster contributes NOTHING to
    the score, even if it was a mostly-correct near-miss.
    """
    if not system_clusters or not gold_clusters:
        return CorefScore(0.0, 0.0, 0.0)

    n, m = len(system_clusters), len(gold_clusters)
    overlap = np.zeros((n, m))
    for i, sc in enumerate(system_clusters):
        for j, gc in enumerate(gold_clusters):
            overlap[i, j] = len(sc & gc)  # phi4 (mention-based) similarity

    row_ind, col_ind = linear_sum_assignment(-overlap)  # maximize overlap
    total_overlap = overlap[row_ind, col_ind].sum()

    total_system = sum(len(c) for c in system_clusters)
    total_gold = sum(len(c) for c in gold_clusters)

    precision = total_overlap / total_system if total_system > 0 else 0.0
    recall = total_overlap / total_gold if total_gold > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return CorefScore(precision, recall, f1)