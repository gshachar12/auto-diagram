"""
The statistics the analysis is allowed to use.

  Responsibility: small, dependency-free estimators, each written once and
  tested on hand-worked examples. Nothing here reads the database; every
  function takes plain numbers and returns plain numbers, which is what
  makes the replay property checkable at this level rather than only at the
  end of the pipeline.

  Three choices worth stating:

    Wilson, not the normal approximation.  Counts here are small and often
      near 0 or 1, where the normal interval runs off the end of the scale.
    Fleiss' kappa AND Gwet's AC1.  Kappa collapses when one category
      dominates -- which is the expected shape of this experiment, where
      most items are SUPPORTED -- and reporting it alone would turn high
      agreement into a number near zero. AC1 is reported beside it, never
      instead of it.
    The bootstrap resamples clusters, not items.  Claims about the same
      capture are not independent, so an interval that resamples items
      would be too narrow. The cluster is the PCAP, the draw is seeded, and
      the seed is a stored analysis parameter.

  Determinism is a requirement, not a nicety: analysing the same stored
  responses twice must produce identical numbers, so every iteration order
  here is over a sorted sequence and every random draw comes from a
  `random.Random` seeded from the analysis parameters.
"""
from __future__ import annotations

import math
import random
from collections import Counter
from typing import Any, Callable, Hashable, Iterable, Sequence


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% (by default) interval for a proportion, Wilson's score interval."""
    if total <= 0:
        return (0.0, 1.0)
    phat = successes / total
    denominator = 1 + z * z / total
    centre = phat + z * z / (2 * total)
    spread = z * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total))
    return (max(0.0, (centre - spread) / denominator), min(1.0, (centre + spread) / denominator))


def proportion(successes: int, total: int, z: float = 1.96) -> dict[str, Any]:
    """A rate that always carries its n and its interval. There is no other kind here."""
    low, high = wilson_interval(successes, total, z)
    return {
        "value": (successes / total) if total else None,
        "n": total,
        "ci_low": low if total else None,
        "ci_high": high if total else None,
        "successes": successes,
    }


def newcombe_difference(
    successes_a: int, total_a: int, successes_b: int, total_b: int, z: float = 1.96
) -> dict[str, Any]:
    """
    Interval for the difference of two independent proportions.

    Newcombe's hybrid-score method: it is built from the two Wilson
    intervals, so it inherits their behaviour at the ends of the scale,
    where a normal-approximation difference interval is worst and where a
    position-bias gap measured over a few dozen items actually lands.
    """
    if total_a <= 0 or total_b <= 0:
        return {"value": None, "n": min(total_a, total_b), "ci_low": None, "ci_high": None}
    p1, p2 = successes_a / total_a, successes_b / total_b
    l1, u1 = wilson_interval(successes_a, total_a, z)
    l2, u2 = wilson_interval(successes_b, total_b, z)
    delta = p1 - p2
    low = delta - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    high = delta + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return {"value": delta, "n": total_a + total_b, "ci_low": max(-1.0, low), "ci_high": min(1.0, high)}


def entropy_bits(counts: Iterable[int]) -> float:
    """Shannon entropy of a vote distribution, in bits. 0 for unanimity."""
    values = [c for c in counts if c > 0]
    total = sum(values)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in values)


def jaccard(left: Iterable[int], right: Iterable[int]) -> float | None:
    """
    |A ∩ B| / |A ∪ B|, or None when both sets are empty.

    Two models that each found nothing have not agreed on evidence; they
    have produced no evidence, and 1.0 would read as perfect agreement.
    """
    a, b = set(left), set(right)
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


# -- agreement among raters ------------------------------------------------

def _item_tables(items: Sequence[Sequence[str]], categories: Sequence[str]) -> list[list[int]]:
    """Each item as a count per category, keeping only items with ≥2 votes."""
    index = {name: i for i, name in enumerate(categories)}
    tables = []
    for votes in items:
        row = [0] * len(categories)
        for vote in votes:
            if vote in index:
                row[index[vote]] += 1
        if sum(row) >= 2:
            tables.append(row)
    return tables


def raw_agreement(items: Sequence[Sequence[str]], categories: Sequence[str]) -> dict[str, Any]:
    """
    Mean proportion of agreeing rater pairs, over items rated at least twice.

    Reported beside kappa because it is the number people actually want
    when kappa is low for paradoxical reasons.
    """
    tables = _item_tables(items, categories)
    if not tables:
        return {"value": None, "n": 0}
    shares = []
    for row in tables:
        n = sum(row)
        shares.append((sum(c * c for c in row) - n) / (n * (n - 1)))
    return {"value": sum(shares) / len(shares), "n": len(tables)}


def fleiss_kappa(items: Sequence[Sequence[str]], categories: Sequence[str]) -> dict[str, Any]:
    """
    Fleiss' kappa, allowing a different number of raters per item.

    The per-item agreement P_i is the textbook one; the chance term uses the
    pooled category shares. With an unequal number of raters per item this
    is the usual generalisation, and the item count is reported so a reader
    can see how little it may rest on.
    """
    tables = _item_tables(items, categories)
    if not tables:
        return {"value": None, "n": 0, "detail": {"reason": "no item has two or more votes"}}
    agreements = []
    totals = [0] * len(categories)
    grand = 0
    for row in tables:
        n = sum(row)
        agreements.append((sum(c * c for c in row) - n) / (n * (n - 1)))
        grand += n
        for i, c in enumerate(row):
            totals[i] += c
    p_bar = sum(agreements) / len(agreements)
    shares = [t / grand for t in totals]
    p_e = sum(s * s for s in shares)
    if p_e >= 1.0:
        # Every rater used one category: agreement is perfect and chance
        # agreement is also perfect, so kappa is undefined, not 1.0.
        return {
            "value": None, "n": len(tables),
            "detail": {"reason": "all votes fall in one category; kappa is undefined there",
                       "observed_agreement": p_bar, "category_shares": shares},
        }
    return {
        "value": (p_bar - p_e) / (1 - p_e),
        "n": len(tables),
        "detail": {"observed_agreement": p_bar, "chance_agreement": p_e, "category_shares": shares},
    }


def gwet_ac1(items: Sequence[Sequence[str]], categories: Sequence[str]) -> dict[str, Any]:
    """
    Gwet's AC1: the same observed agreement, a chance term that does not
    collapse when one category dominates.
    """
    tables = _item_tables(items, categories)
    if not tables:
        return {"value": None, "n": 0, "detail": {"reason": "no item has two or more votes"}}
    k = len(categories)
    if k < 2:
        return {"value": None, "n": len(tables), "detail": {"reason": "AC1 needs at least two categories"}}
    agreements = []
    totals = [0] * k
    grand = 0
    for row in tables:
        n = sum(row)
        agreements.append((sum(c * c for c in row) - n) / (n * (n - 1)))
        grand += n
        for i, c in enumerate(row):
            totals[i] += c
    p_bar = sum(agreements) / len(agreements)
    shares = [t / grand for t in totals]
    p_e = sum(s * (1 - s) for s in shares) / (k - 1)
    if p_e >= 1.0:
        return {"value": None, "n": len(tables), "detail": {"reason": "chance agreement is 1; AC1 is undefined"}}
    return {
        "value": (p_bar - p_e) / (1 - p_e),
        "n": len(tables),
        "detail": {"observed_agreement": p_bar, "chance_agreement": p_e},
    }


# -- association between two raters' errors --------------------------------

def phi_coefficient(pairs: Sequence[tuple[bool, bool]]) -> dict[str, Any]:
    """
    Phi for two binary error vectors, with the 2x2 table it came from.

    Phi is undefined when either rater never errs (or always does): a
    margin of the table is zero, so the denominator is zero. That is
    reported as undefined with the reason, never as 0.0 -- "no correlation"
    and "not computable" are different findings.
    """
    a = b = c = d = 0  # both wrong, left only, right only, both right
    for left, right in pairs:
        if left and right:
            a += 1
        elif left:
            b += 1
        elif right:
            c += 1
        else:
            d += 1
    n = a + b + c + d
    denominator = math.sqrt((a + b) * (c + d) * (a + c) * (b + d))
    table = {"both_wrong": a, "left_only": b, "right_only": c, "both_right": d}
    if n == 0 or denominator == 0:
        return {
            "value": None, "n": n,
            "detail": {**table, "reason": "a margin of the 2x2 table is zero, so phi is undefined"},
        }
    return {"value": (a * d - b * c) / denominator, "n": n, "detail": table}


def double_fault(pairs: Sequence[tuple[bool, bool]]) -> dict[str, Any]:
    """Share of scored items on which both raters were wrong together."""
    both = sum(1 for left, right in pairs if left and right)
    return {**proportion(both, len(pairs)), "detail": {"definition": "both differ from the expected verdict"}}


def effective_votes(n_raters: int, mean_correlation: float | None) -> dict[str, Any]:
    """
    N / (1 + (N-1)·rho): how many independent votes a correlated panel is worth.

    With rho ≤ 0 the formula can exceed N, which would claim the panel is
    worth more than its members; it is capped at N and the cap is recorded.
    """
    if n_raters <= 0 or mean_correlation is None:
        return {"value": None, "n": n_raters, "detail": {"reason": "no usable error correlation between members"}}
    denominator = 1 + (n_raters - 1) * mean_correlation
    if denominator <= 0:
        return {"value": None, "n": n_raters, "detail": {"reason": "the correlation implies a non-positive divisor"}}
    value = n_raters / denominator
    return {
        "value": min(value, float(n_raters)),
        "n": n_raters,
        "detail": {"rho": mean_correlation, "capped_at_n": value > n_raters},
    }


# -- the bootstrap ---------------------------------------------------------

def cluster_bootstrap(
    clusters: dict[Hashable, list[Any]],
    statistic: Callable[[list[Any]], float | None],
    *,
    resamples: int,
    seed: int,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """
    Percentile interval from resampling whole clusters with replacement.

    The cluster here is the PCAP: claims about one capture share its
    quirks, its vantage point and its gaps, so treating them as independent
    items would understate the interval. Clusters are iterated in sorted
    order and the draws come from one seeded generator, so the interval is
    reproducible to the last digit.
    """
    keys = sorted(clusters, key=str)
    observed = statistic([row for key in keys for row in clusters[key]])
    if observed is None or not keys:
        return {"value": observed, "n": sum(len(v) for v in clusters.values()), "ci_low": None, "ci_high": None,
                "detail": {"reason": "nothing to resample"}}
    rng = random.Random(seed)
    draws: list[float] = []
    for _ in range(resamples):
        sample: list[Any] = []
        for _ in range(len(keys)):
            sample.extend(clusters[keys[rng.randrange(len(keys))]])
        value = statistic(sample)
        if value is not None:
            draws.append(value)
    if not draws:
        return {"value": observed, "n": sum(len(v) for v in clusters.values()), "ci_low": None, "ci_high": None,
                "detail": {"reason": "no resample produced a value"}}
    draws.sort()
    low = draws[max(0, int(math.floor((alpha / 2) * len(draws))))]
    high = draws[min(len(draws) - 1, int(math.ceil((1 - alpha / 2) * len(draws))) - 1)]
    return {
        "value": observed,
        "n": sum(len(v) for v in clusters.values()),
        "ci_low": low,
        "ci_high": high,
        "detail": {"clusters": len(keys), "resamples": resamples, "seed": seed, "method": "cluster bootstrap by PCAP"},
    }


def mean_rate(rows: Sequence[bool]) -> float | None:
    return (sum(1 for row in rows if row) / len(rows)) if rows else None


# -- variance explained ----------------------------------------------------

def eta_squared(values: Sequence[float], groups: Sequence[Hashable]) -> dict[str, Any]:
    """
    Share of the total variance that lies between a factor's groups.

    Deliberately not called a variance component: this is eta-squared from
    a one-way split, not a fit of a mixed-effects model. For crossed
    factors the shares do not add to one and a factor nested inside another
    (an item inside its PCAP) carries the outer factor's effect too. Those
    caveats travel with the number in `detail` rather than in a footnote
    somewhere else.
    """
    if len(values) != len(groups) or len(values) < 2:
        return {"value": None, "n": len(values), "detail": {"reason": "not enough observations"}}
    grand = sum(values) / len(values)
    total_ss = sum((v - grand) ** 2 for v in values)
    if total_ss == 0:
        return {"value": None, "n": len(values),
                "detail": {"reason": "the outcome is constant, so no variance can be attributed"}}
    sums: dict[Hashable, list[float]] = {}
    for value, group in zip(values, groups):
        sums.setdefault(group, []).append(value)
    between = sum(len(v) * ((sum(v) / len(v)) - grand) ** 2 for v in sums.values())
    return {
        "value": between / total_ss,
        "n": len(values),
        "detail": {"groups": len(sums), "statistic": "eta_squared", "note":
                   "share of total variance between this factor's groups; not a mixed-effects variance component"},
    }


def majority(votes: Sequence[str], threshold: float = 0.5) -> tuple[str | None, float]:
    """
    The strictly-above-threshold category and its share, or (None, share).

    Ties are broken by name only to keep the *share* deterministic; a tie
    can never win, since no tie exceeds half the votes.
    """
    if not votes:
        return None, 0.0
    counts = Counter(votes)
    verdict, count = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    share = count / len(votes)
    return (verdict if share > threshold else None), share
