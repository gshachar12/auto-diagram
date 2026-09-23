"""
PAnGEA Evaluator -- extraction, grounding, and evidence-matching accuracy
metrics. All operate on an already-computed claim alignment (see
alignment.py) -- none of these re-derive alignment themselves.
"""
from __future__ import annotations

from dataclasses import dataclass

from .alignment import AlignmentResult, find_covered_gold_indices, tfidf_similarity_matrix
from .schemas import GoldClaim, SystemClaim


@dataclass
class PRF1:
    precision: float
    recall: float
    f1: float


def _prf1(true_positives: int, predicted: int, actual: int) -> PRF1:
    precision = true_positives / predicted if predicted > 0 else 0.0
    recall = true_positives / actual if actual > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return PRF1(precision, recall, f1)


def extraction_prf1(
    alignment: AlignmentResult, n_system: int, n_gold: int,
    system_texts: list[str] = None, gold_texts: list[str] = None,
    threshold: float = None, similarity_fn=None,
) -> PRF1:
    """
    Of system claims, how many correspond to a real gold claim
    (precision)? Of gold claims, how many did the system catch (recall)?

    Precision numerator: count of system items with system_to_gold[i] is
    not None -- i.e. how many system items individually found SOME
    qualifying match, NOT deduplicated by which gold index they matched.
    Deduplicating (the earlier version) meant two system items that
    legitimately both correspond to the same one gold fact (fragmentation
    -- e.g. gold "I went home and took off my shoes" split by the system
    into two separate claims) would count as only 1 true positive against
    2 predicted, artificially halving precision for a case where BOTH
    system claims are individually true -- not a real fabrication.

    Recall numerator: if system_texts/gold_texts are provided, uses
    find_covered_gold_indices (does ANY system item's similarity to THIS
    gold item clear the threshold), NOT just "was this gold item someone's
    single best match". This specifically fixes the opposite case
    (consolidation): gold ["I went home", "I took off my shoes"] vs a
    single system claim "I went home and took off my shoes" -- the
    system's one sentence genuinely covers both gold facts, but argmax-only
    matching can only assign it to ONE of them, wrongly scoring the other
    as a miss (confirmed directly: recall came out 0.5, not 1.0).
    Falls back to the old argmax-based count if texts aren't passed in
    (keeps this function usable without recomputing similarity when the
    caller already has the alignment and doesn't need the fix).
    """
    precision_tp = sum(1 for g in alignment.system_to_gold.values() if g is not None)

    if system_texts is not None and gold_texts is not None:
        sim_fn = similarity_fn or tfidf_similarity_matrix
        thresh = threshold if threshold is not None else alignment.threshold
        covered = find_covered_gold_indices(system_texts, gold_texts, thresh, sim_fn)
        recall_tp = len(covered)
    else:
        matched_gold = {g for g in alignment.system_to_gold.values() if g is not None}
        recall_tp = len(matched_gold)

    precision = precision_tp / n_system if n_system > 0 else 0.0
    recall = recall_tp / n_gold if n_gold > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return PRF1(precision, recall, f1)




def grounding_status_accuracy(
    system_claims: list[SystemClaim], gold_claims: list[GoldClaim], alignment: AlignmentResult,
) -> dict[str, PRF1]:
    """
    Per-status precision/recall, computed ONLY over claim pairs that were
    successfully aligned (an unaligned system claim has no gold status to
    compare against at all -- it's already penalized by extraction
    precision instead).
    """
    statuses = ["grounded", "unsupported", "uncertain_needs_drilldown"]
    result = {}
    for status in statuses:
        tp = predicted = actual = 0
        for sys_idx, gold_idx in alignment.system_to_gold.items():
            if gold_idx is None:
                continue
            sys_status = system_claims[sys_idx].grounding_status
            gold_status = gold_claims[gold_idx].gold_grounding_status
            if sys_status == status:
                predicted += 1
            if gold_status == status:
                actual += 1
            if sys_status == status and gold_status == status:
                tp += 1
        result[status] = _prf1(tp, predicted, actual)
    return result


def evidence_matching_accuracy(
    system_claims: list[SystemClaim], gold_claims: list[GoldClaim], alignment: AlignmentResult,
) -> PRF1:
    """
    For ALIGNED claim pairs, does the system's linked-evidence set overlap
    with gold's annotated evidence set?

    Respects flow-level disambiguation (GoldEvidenceRef.flow_dst_ip) --
    fingerprint_key alone is NOT sufficient: confirmed on real data
    (a ransomware capture) that entirely different conversations to
    entirely different hosts can share the identical fingerprint_key,
    since fingerprint_key is deliberately IP-agnostic (needed elsewhere,
    for scan/anomaly detection). A gold ref with a flow_dst_ip only counts
    as matched if the system's linked aggregate for that SAME
    fingerprint_key also lists that destination among its
    unique_destinations -- matching on the key alone would silently credit
    the system for grounding evidence for a completely different
    real-world event that happens to look structurally identical.

    A gold ref with flow_dst_ip=None (genuinely unambiguous -- only one
    destination exists for that fingerprint in the capture, as with DNS
    tunneling) falls back to key-only matching, unchanged from before.
    """
    tp = predicted = actual = 0
    for sys_idx, gold_idx in alignment.system_to_gold.items():
        if gold_idx is None:
            continue
        sys_claim = system_claims[sys_idx]
        gold_refs = gold_claims[gold_idx].gold_linked_evidence

        predicted += len(sys_claim.linked_fingerprint_keys)
        actual += len(gold_refs)

        for ref in gold_refs:
            if ref.fingerprint_key not in sys_claim.linked_fingerprint_keys:
                continue
            if ref.flow_dst_ip is None:
                tp += 1  # unambiguous case -- key match is sufficient
            elif ref.flow_dst_ip in sys_claim.linked_fingerprint_destinations.get(ref.fingerprint_key, []):
                tp += 1  # disambiguated case -- destination confirmed too
            # else: same key, but the system's aggregate for it doesn't
            # actually include this specific destination -- NOT a match,
            # even though the fingerprint_key alone would have looked
            # identical.

    return _prf1(tp, predicted, actual)


def actor_ip_resolution_accuracy(
    system_actor_endpoints: list[list[str]],
    gold_actor_ip_lists: list[list[str]],
    alignment: AlignmentResult,
) -> dict[str, int]:
    """
    For aligned actor pairs: correctly resolved / incorrectly resolved /
    failed to resolve. Also reports gold entities never extracted at all
    (distinct from "extracted but unresolved" -- these are different
    failure modes worth telling apart, per the earlier discussion).

    "Correctly resolved" now means ANY overlap between the system's
    resolved_endpoints and the gold entity's list of valid IPs -- not
    exact equality against one expected value. See GoldActor.ground_truth_ips
    for why: a CDN/load-balanced service can legitimately have many valid
    IPs, and a single-value comparison would mark a correct answer wrong
    just for picking a different (also legitimate) one.
    """
    correct = incorrect = unresolved = 0
    aligned_gold = set()
    for sys_idx, gold_idx in alignment.system_to_gold.items():
        if gold_idx is None:
            continue
        aligned_gold.add(gold_idx)
        endpoints = set(system_actor_endpoints[sys_idx])
        gold_ips = set(gold_actor_ip_lists[gold_idx])
        if not endpoints:
            unresolved += 1
        elif gold_ips and (endpoints & gold_ips):
            correct += 1
        else:
            incorrect += 1
    never_extracted = len(gold_actor_ip_lists) - len(aligned_gold)
    return {
        "correctly_resolved": correct,
        "incorrectly_resolved": incorrect,
        "extracted_but_unresolved": unresolved,
        "never_extracted": never_extracted,
    }