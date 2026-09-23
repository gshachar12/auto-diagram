"""
PAnGEA Evaluator -- similarity and alignment.

This is the step everything else in the Evaluator depends on: deciding
which system actor/claim corresponds to which gold entity/claim. Matching
must be based on TEXT CONTENT (description_ref / claim text), never on
actor_id/claim_id/resolved IP -- see the design discussion this module
implements:
  - actor_id is a free label the system invents (e.g. "unicorn_attacker")
    and carries no guaranteed relationship to gold at all.
  - Matching on resolved IP would let a RESOLUTION bug (e.g. two different
    real entities incorrectly resolved to the same IP) masquerade as an
    EXTRACTION coreference success, corrupting exactly the metric meant to
    catch extraction problems independently of resolution problems.

Default similarity is TF-IDF cosine similarity -- lexical-overlap based,
deterministic, no network/API call needed. This is a real, named
limitation: it will correctly handle cases with shared distinctive tokens
(e.g. "kali is a very evil attacker" vs "an offensive framework host
named 'kali'" -- both contain "kali") but will under-perform true
semantic embeddings on paraphrases with NO shared vocabulary at all. The
`similarity_fn` parameter is pluggable specifically so a real embedding
model can be substituted later without changing any downstream code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from scipy.optimize import linear_sum_assignment

SimilarityFn = Callable[[list[str], list[str]], np.ndarray]


def tfidf_similarity_matrix(texts_a: list[str], texts_b: list[str]) -> np.ndarray:
    """
    Returns an (len(texts_a) x len(texts_b)) matrix of cosine similarities.
    Fit jointly on both sides so the vocabulary is shared -- fitting only
    on one side would leave terms unique to the other side out of the
    vector space entirely.
    """
    if not texts_a or not texts_b:
        return np.zeros((len(texts_a), len(texts_b)))
    vectorizer = TfidfVectorizer(lowercase=True, stop_words="english")
    try:
        all_vecs = vectorizer.fit_transform(texts_a + texts_b)
    except ValueError:
        # Empty vocabulary after stopword removal (e.g. all-stopword inputs)
        return np.zeros((len(texts_a), len(texts_b)))
    vecs_a = all_vecs[: len(texts_a)]
    vecs_b = all_vecs[len(texts_a) :]
    return cosine_similarity(vecs_a, vecs_b)


def local_embedding_similarity_matrix(
    texts_a: list[str], texts_b: list[str], model_name: str = "all-MiniLM-L6-v2",
) -> np.ndarray:
    """
    Real semantic-embedding similarity computed FULLY LOCALLY -- no API
    call, no external service dependency. Uses sentence-transformers
    (built on PyTorch), which downloads a small pretrained model once
    (all-MiniLM-L6-v2 is ~80MB) and runs entirely on CPU from then on.

    Added after a direct, fair challenge to embedding_similarity_matrix's
    design: an OpenAI API call is not actually necessary for this --
    open-source sentence embedding models run locally and avoid the API
    key dependency, per-call cost, and (for some deployments) the
    data-leaves-the-environment concern entirely.

    STATUS, confirmed directly (not guessed): the sentence-transformers
    PACKAGE installs correctly and this function's code runs correctly up
    to the model-loading step. What could NOT be verified in this
    project's own sandbox: actually downloading the pretrained model
    weights from huggingface.co, which returns a 403 -- confirmed to be a
    network-egress restriction specific to this sandbox (huggingface.co
    is not in its allowed domain list), NOT a code or dependency problem.
    A normal environment with regular internet access should not hit this
    same wall. Still: this function's actual similarity OUTPUT (e.g.
    against this project's own confirmed TF-IDF weak spots -- the
    "kali is a very evil attacker" borderline case (0.151, just above a
    typical 0.15 threshold -- not a clean failure, but notably low margin
    for a genuine same-fact paraphrase) and the "phishing email" false
    positive (0.381, confirmed) -- has not been empirically confirmed anywhere yet.
    Test it directly in an environment where the model can actually
    download before trusting it in place of TF-IDF.

    Requires: pip install sentence-transformers
    """
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        raise ImportError(
            "local_embedding_similarity_matrix requires sentence-transformers "
            "(pip install sentence-transformers). Not installed."
        ) from e

    if not texts_a or not texts_b:
        return np.zeros((len(texts_a), len(texts_b)))

    model = SentenceTransformer(model_name)
    vecs_a = model.encode(texts_a, convert_to_numpy=True)
    vecs_b = model.encode(texts_b, convert_to_numpy=True)
    return cosine_similarity(vecs_a, vecs_b)


def alignscore_similarity_matrix(
    texts_a: list[str], texts_b: list[str],
    model: str = "roberta-base", ckpt_path: str = None, device: str = "cpu",
) -> np.ndarray:
    """
    Uses AlignScore (Zha et al., ACL 2023) -- a RoBERTa-based model
    trained on 4.7M examples across 7 tasks (NLI, QA, paraphrasing, fact
    verification, semantic similarity, summarization) specifically to
    judge factual alignment between two text pieces. Chosen over a
    general-purpose sentence-embedding model because its TRAINING
    OBJECTIVE is a closer match to what alignment needs here: embedding
    models trained for broad topical similarity are exactly the kind of
    signal that produced this project's confirmed false-positive case
    ("kali sends a phishing email" scored 0.38 similar to "kali sends
    spoofed ARP replies" under TF-IDF, purely from shared actor/verb
    vocabulary) -- AlignScore's NLI/fact-verification training is aimed
    directly at distinguishing genuine entailment from superficial
    similarity, which is precisely this failure mode.

    IMPORTANT ASYMMETRY, handled explicitly here: AlignScore answers a
    DIRECTIONAL question -- "is everything in the claim contained in/
    consistent with the context" -- not a symmetric similarity. Our
    alignment needs symmetric equivalence (does system text X describe
    the SAME fact as gold text Y, not just "is X entailed by Y" or vice
    versa alone). This function scores BOTH directions
    (score(context=a, claim=b) and score(context=b, claim=a)) and takes
    the MINIMUM -- a conservative combination requiring genuine mutual
    entailment in both directions, rather than one-directional
    containment (e.g. a vague claim could be "entailed by" almost
    anything specific, but shouldn't count as a true match unless the
    reverse also holds).

    NOT TESTED in this project's own environment -- installing AlignScore
    needs the same infrastructure (PyTorch + a checkpoint hosted on
    huggingface.co) that hit a confirmed network-egress block in this
    sandbox specifically (see local_embedding_similarity_matrix's
    docstring). Untested here for the identical reason, not a separate
    problem. ckpt_path must point to a downloaded AlignScore checkpoint
    (AlignScore-base ~500MB or AlignScore-large ~1.4GB, both hosted at
    huggingface.co/yzha/AlignScore) -- there is no default; this function
    raises clearly if ckpt_path is not supplied, rather than failing
    obscurely deeper in the library.

    Requires: pip install alignscore (see github.com/yuh-zha/AlignScore
    for the PyTorch version note and the required
    `python -m spacy download en_core_web_sm` step).
    """
    if ckpt_path is None:
        raise ValueError(
            "alignscore_similarity_matrix requires ckpt_path -- download "
            "AlignScore-base or AlignScore-large from "
            "https://huggingface.co/yzha/AlignScore and pass its local path."
        )
    try:
        from alignscore import AlignScore
    except ImportError as e:
        raise ImportError(
            "alignscore_similarity_matrix requires the alignscore package "
            "(pip install alignscore -- see github.com/yuh-zha/AlignScore "
            "for full setup, including a required spaCy model download)."
        ) from e

    if not texts_a or not texts_b:
        return np.zeros((len(texts_a), len(texts_b)))

    scorer = AlignScore(model=model, batch_size=32, device=device, ckpt_path=ckpt_path, evaluation_mode="nli_sp")

    n_a, n_b = len(texts_a), len(texts_b)
    # Flatten into one batch call per direction, rather than n_a*n_b
    # individual calls -- AlignScore's batch_size parameter exists
    # specifically to make this efficient.
    contexts_ab, claims_ab = [], []
    for a in texts_a:
        for b in texts_b:
            contexts_ab.append(a)
            claims_ab.append(b)
    scores_a_to_b = np.array(scorer.score(contexts=contexts_ab, claims=claims_ab)).reshape(n_a, n_b)

    contexts_ba, claims_ba = [], []
    for a in texts_a:
        for b in texts_b:
            contexts_ba.append(b)
            claims_ba.append(a)
    scores_b_to_a = np.array(scorer.score(contexts=contexts_ba, claims=claims_ba)).reshape(n_a, n_b)

    return np.minimum(scores_a_to_b, scores_b_to_a)


def embedding_similarity_matrix(
    texts_a: list[str], texts_b: list[str], api_key: Optional[str] = None,
    model: str = "text-embedding-3-small",
) -> np.ndarray:
    """
    Real semantic-embedding cosine similarity, as an alternative to
    tfidf_similarity_matrix -- built after CONFIRMING empirically (not
    theoretically) that TF-IDF fails on true paraphrases with no shared
    vocabulary: "Legitimate baseline initial connection - ARP broadcast
    to all actors" (gold) vs "Local hosts interact within default
    domains on a private IP space." (system) scored 0.0 similarity under
    TF-IDF despite both describing the exact same source sentence.

    Requires an OpenAI API key (falls back to the OPENAI_API_KEY env var
    if not passed explicitly). This is the "real embeddings" swap-in
    flagged as a known limitation when tfidf_similarity_matrix was first
    built -- now justified by concrete failed-alignment evidence, not
    speculation.
    """
    import os
    from openai import OpenAI

    client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))
    all_texts = texts_a + texts_b
    if not all_texts:
        return np.zeros((len(texts_a), len(texts_b)))

    response = client.embeddings.create(model=model, input=all_texts)
    vecs = np.array([e.embedding for e in response.data])
    vecs_a = vecs[: len(texts_a)]
    vecs_b = vecs[len(texts_a):]
    return cosine_similarity(vecs_a, vecs_b)


def find_covered_gold_indices(
    system_texts: list[str], gold_texts: list[str], threshold: float = 0.15,
    similarity_fn: SimilarityFn = tfidf_similarity_matrix,
) -> set[int]:
    """
    Returns the set of gold indices "covered" by at least one system item
    -- independent of whether that system item's single BEST match
    happens to be a different gold item.

    Added after a concrete, confirmed gap in align_by_similarity: that
    function's system_to_gold[i] holds a SINGLE best-match value, so it
    can represent fragmentation (many system items -> one gold item) but
    NOT consolidation (one system item legitimately covering multiple
    gold items). Real example that exposed this: gold = ["I went home",
    "I took off my shoes"], system = ["I went home and took off my
    shoes"] -- the single system item's argmax match picks only ONE of
    the two gold items, so the other is wrongly counted as a missed
    claim (recall=0.5) even though the system's sentence genuinely
    conveys both facts.

    This function answers a different, more permissive question per gold
    item: "does ANY system item's similarity to THIS gold item clear the
    threshold" -- not "is this gold item someone's single best match".
    Used specifically for extraction recall, where "was this content
    covered at all" is the right question. NOT used for grounding-status
    or evidence-matching accuracy, or for actor coreference -- those need
    a genuine 1:1 pairing to compare specific field values (a combined
    claim has no single well-defined grounding-status to compare against
    two different gold statuses), so they correctly keep using
    align_by_similarity's single-best-match semantics unchanged.
    """
    if not gold_texts:
        return set()
    if not system_texts:
        return set()
    sim = similarity_fn(system_texts, gold_texts)
    covered = set()
    for j in range(len(gold_texts)):
        if sim[:, j].max() >= threshold:
            covered.add(j)
    return covered


@dataclass
class AlignmentResult:
    # Maps a system index -> matched gold index, or None if unmatched
    # (score below threshold, or no gold items at all).
    system_to_gold: dict[int, Optional[int]]
    # Maps a gold index -> list of system indices matched to it (usually
    # 0 or 1, but MORE than one indicates fragmentation -- e.g. the same
    # real entity split into two system actor_ids).
    gold_to_systems: dict[int, list[int]]
    similarity_matrix: np.ndarray
    threshold: float


def align_by_similarity(
    system_texts: list[str],
    gold_texts: list[str],
    threshold: float = 0.15,
    similarity_fn: SimilarityFn = tfidf_similarity_matrix,
) -> AlignmentResult:
    """
    Each system item is matched to its single BEST-scoring gold item, if
    that score clears `threshold` -- NOT a 1:1 optimal assignment. This is
    deliberate: 1:1-only matching cannot represent fragmentation (multiple
    system actors that are really the same gold entity), which is exactly
    the failure mode this whole Evaluator exists to measure (see the
    kali/attacker/kali_host worked example). CEAF's own internal alignment
    step (in coreference_metrics.py) does its own separate 1:1 matching as
    part of ITS specific algorithm -- that is not this function's job.
    """
    sim = similarity_fn(system_texts, gold_texts)
    system_to_gold: dict[int, Optional[int]] = {}
    gold_to_systems: dict[int, list[int]] = {i: [] for i in range(len(gold_texts))}

    for i in range(len(system_texts)):
        if sim.shape[1] == 0:
            system_to_gold[i] = None
            continue
        best_j = int(np.argmax(sim[i]))
        best_score = sim[i, best_j]
        if best_score >= threshold:
            system_to_gold[i] = best_j
            gold_to_systems[best_j].append(i)
        else:
            system_to_gold[i] = None

    return AlignmentResult(system_to_gold, gold_to_systems, sim, threshold)


# Formal ordering-constraint rubric (5 categories) for comparing candidate
# similarity functions -- not just eyeballing a couple of scores. Real,
# domain-specific examples throughout (drawn from this project's own gold
# samples), since a network-security "minor" wording difference can be a
# functionally severe error (protocol/port/actor swapped), which a metric
# calibrated on general-domain text may not weigh the same way -- exactly
# why generic sentence pairs aren't good enough test cases here.
RUBRIC_CASES = {
    "identical": [
        ("kali sends unsolicited ARP replies claiming the gateway's identity",
         "kali sends unsolicited ARP replies claiming the gateway's identity"),
    ],
    "unrelated": [
        # Genuinely different PCAPs/actions -- no factual overlap at all
        ("the infected host scans a large range of external IP addresses on a single, non-standard UDP port",
         "the client requests network configuration and the server responds with an assigned tunnel IP"),
        ("kali sends unsolicited ARP replies claiming the gateway's identity",
         "the source host sends TCP SYN packets to a single target host across a range of destination ports"),
    ],
    "paraphrase": [
        ("kali is a very evil attacker",
         "an offensive framework host named 'kali'"),
        ("the victim host fetches an executable file from a separate, disposable-looking domain",
         "the victim downloads the ransomware payload from a throwaway domain"),
    ],
    "error_minor": [
        # Same action TYPE, one factual detail wrong (protocol/port here)
        ("the infected host scans a large range of external IP addresses on a single, non-standard UDP port",
         "the infected host scans a large range of external IP addresses on port 445 (SMB)"),
    ],
    "error_severe": [
        # Different action entirely, sharing only actor names/verbs
        ("kali sends a phishing email to the victim",
         "kali sends spoofed ARP replies to the victim"),
    ],
}


@dataclass
class RubricTestResult:
    """
    Structured result of run_rubric_test -- separated from printing so
    this is usable both from alignment_cli.py (prints it) and from
    pipeline_runner.py's --evaluate mode (includes it alongside the main
    EvaluationReport, in both console text and the saved JSON).
    """
    method_name: str
    raw_scores: dict  # category -> list of (score, text_a, text_b)
    checks: list  # list of (check_name, passed)
    all_passed: bool

    def to_text(self) -> str:
        lines = [f"=== Rubric test: {self.method_name} ===", "", "-- Raw scores by category --"]
        for category, entries in self.raw_scores.items():
            for score, a, b in entries:
                lines.append(f"  [{category}] {score:.3f}  \"{a[:45]}...\" <-> \"{b[:45]}...\"")
        lines.append("")
        lines.append("-- Ordering constraints --")
        for name, passed in self.checks:
            lines.append(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        lines.append("")
        lines.append("RESULT: " + ("ALL CONSTRAINTS PASSED" if self.all_passed else "SOME CONSTRAINTS FAILED -- see above"))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "method_name": self.method_name,
            "raw_scores": {
                cat: [{"score": float(s), "text_a": a, "text_b": b} for s, a, b in entries]
                for cat, entries in self.raw_scores.items()
            },
            "checks": [{"name": n, "passed": p} for n, p in self.checks],
            "all_passed": self.all_passed,
        }


def run_rubric_test(similarity_fn, method_name: str = "unnamed", **kwargs) -> RubricTestResult:
    """
    Runs the full 5-category rubric and checks the ORDERING CONSTRAINT
    directly, not just raw scores: unrelated should be low, identical
    should be ~1, paraphrase should be high, and errors should score
    strictly between "unrelated" and "paraphrase" -- with error_severe
    below error_minor. Returns a RubricTestResult -- call .to_text() to
    print it, or .to_dict() to serialize it.
    """
    def scores_for(category):
        return [similarity_fn([a], [b])[0, 0] for a, b in RUBRIC_CASES[category]]

    identical = scores_for("identical")
    unrelated = scores_for("unrelated")
    paraphrase = scores_for("paraphrase")
    error_minor = scores_for("error_minor")
    error_severe = scores_for("error_severe")

    raw_scores = {
        category: [(score, a, b) for score, (a, b) in zip(scores_for(category), RUBRIC_CASES[category])]
        for category in RUBRIC_CASES
    }

    checks = [
        ("identical ~= 1 (>0.9)", all(s > 0.9 for s in identical)),
        ("unrelated ~= 0 (<0.3)", all(s < 0.3 for s in unrelated)),
        ("paraphrase scores high (>0.5)", all(s > 0.5 for s in paraphrase)),
        ("max(unrelated) < min(error_severe)", max(unrelated) < min(error_severe)),
        ("max(error_severe) < min(error_minor)", max(error_severe) < min(error_minor)),
        ("max(error_minor) < min(paraphrase)", max(error_minor) < min(paraphrase)),
    ]
    all_passed = all(passed for _, passed in checks)

    return RubricTestResult(method_name=method_name, raw_scores=raw_scores, checks=checks, all_passed=all_passed)