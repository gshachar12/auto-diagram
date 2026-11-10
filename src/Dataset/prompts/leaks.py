"""
The leak test.

  Responsibility: prove, per rendered prompt, that a solver was not told
  the answer or anything that stands in for it.

  Five things must never reach a solver:

    the expected verdict   -- the whole experiment is whether it can decide;
    the pair type          -- "mutation" says REFUTED, "swap" says not
                              SUPPORTED, "no_pcap" says NOT_VERIFIABLE;
    the claim's provenance -- whether a human wrote or edited it, and what
                              it supersedes, hints at how trustworthy it is;
    the source paper       -- the paper states the attack, so naming it
                              turns verification into recall;
    any Preprocessor cluster -- that would make the labels depend on the
                              algorithm the experiment exists to evaluate.

  The check is mechanical and runs over the rendered text, not the
  template, because a template is innocent until something is interpolated
  into it. The verdict vocabulary itself is unavoidable -- the model has to
  be told the three allowed answers -- so a verdict word counts as a leak
  only when it appears attached to the words that would make it an
  instruction about this item.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: Words that turn a verdict mention into an instruction about this item.
_EXPECTATION_CUES = (
    "expected", "expectation", "correct answer", "ground truth", "the answer is",
    "should be", "known to be", "gold", "label is",
)

#: Pair types, as words. "source" is excluded: it is an ordinary English
#: word that legitimately appears in a prompt ("the source address"), and
#: it is also the one pair type that gives nothing away.
_PAIR_TYPE_WORDS = ("mutation", "mutated", "swap", "swapped", "no_pcap")

_PROVENANCE_WORDS = ("provenance", "supersedes", "reviewed by", "written by an agent", "human-edited")

_CLUSTER_WORDS = ("cluster", "fingerprint_index", "preprocessor", "reduced_representation")

#: Words that appear in a source's title AND legitimately in any prompt
#: about packet captures. Matching on these turns the source check into a
#: false alarm on the criteria text itself -- which it did, until a title
#: reading "DEMO scenario: TCP port scan (synthetic claims)" flagged the
#: criteria's own use of the word "claims".
_GENERIC_TITLE_WORDS = frozenset(
    """
    attack attacks capture captures claim claims data dataset datasets demo detection
    evaluation example figure flows intrusion logs network networks packet packets
    pcaps sample samples scenario scenarios set steps synthetic system systems table
    traffic verdict version
    """.split()
)


def _distinctive_tokens(title: str) -> list[str]:
    """
    The parts of a title that could only come from that title.

    A single generic word is not evidence; a name, an acronym or a year
    attached to a name is.
    """
    tokens = [t.lower() for t in re.split(r"[^\w-]+", title) if len(t) >= 6]
    return [t for t in tokens if t not in _GENERIC_TITLE_WORDS and not t.isdigit()]


def _title_bigrams(title: str) -> list[str]:
    words = [w.lower() for w in re.split(r"[^\w-]+", title) if w]
    return [f"{a} {b}" for a, b in zip(words, words[1:]) if len(a) > 2 and len(b) > 2]


@dataclass(frozen=True)
class LeakFound:
    kind: str
    detail: str
    excerpt: str


def _excerpt(text: str, position: int, width: int = 60) -> str:
    return text[max(0, position - width): position + width].replace("\n", " ")


def scan_for_leaks(
    rendered: str,
    *,
    expected: str | None = None,
    pair_type: str | None = None,
    source_title: str | None = None,
    extra_forbidden: list[str] | None = None,
) -> list[LeakFound]:
    """Every leak in one rendered prompt. Empty list means clean."""
    found: list[LeakFound] = []
    haystack = rendered.lower()

    # 1. The expected verdict, but only where it reads as an instruction.
    if expected:
        for match in re.finditer(re.escape(expected.lower()), haystack):
            window = haystack[max(0, match.start() - 80): match.start()]
            cue = next((c for c in _EXPECTATION_CUES if c in window), None)
            if cue:
                found.append(LeakFound("expected_verdict", f"{expected} after {cue!r}", _excerpt(rendered, match.start())))

    for cue in _EXPECTATION_CUES:
        position = haystack.find(cue)
        if position != -1 and cue not in ("gold",):
            # Even without a verdict beside it, these phrasings have no
            # business in a solver prompt.
            found.append(LeakFound("expectation_language", cue, _excerpt(rendered, position)))

    # 2. The pair type.
    for word in _PAIR_TYPE_WORDS:
        if re.search(rf"\b{re.escape(word)}\b", haystack):
            found.append(LeakFound("pair_type", word, _excerpt(rendered, haystack.find(word))))
    if pair_type and pair_type != "source" and pair_type.lower() in haystack:
        found.append(LeakFound("pair_type", pair_type, _excerpt(rendered, haystack.find(pair_type.lower()))))

    # 3. Provenance.
    for word in _PROVENANCE_WORDS:
        if word in haystack:
            found.append(LeakFound("provenance", word, _excerpt(rendered, haystack.find(word))))

    # 4. The source.
    if source_title:
        # Match on the distinctive part, not on whole-string equality: a
        # prompt that names the dataset is as leaky as one that names the
        # paper. Generic words are excluded, or the criteria text's own
        # vocabulary would flag every prompt.
        for token in _distinctive_tokens(source_title)[:6]:
            if re.search(rf"\b{re.escape(token)}\b", haystack):
                found.append(LeakFound("source", token, _excerpt(rendered, haystack.find(token))))
        for bigram in _title_bigrams(source_title):
            if bigram in haystack:
                found.append(LeakFound("source", bigram, _excerpt(rendered, haystack.find(bigram))))

    # 5. The clustering pipeline.
    for word in _CLUSTER_WORDS:
        if word in haystack:
            found.append(LeakFound("cluster", word, _excerpt(rendered, haystack.find(word))))

    for word in extra_forbidden or []:
        if word.lower() in haystack:
            found.append(LeakFound("forbidden", word, _excerpt(rendered, haystack.find(word.lower()))))

    return found


def assert_clean(rendered: str, **context: Any) -> None:
    leaks = scan_for_leaks(rendered, **context)
    if leaks:
        raise AssertionError(
            "rendered prompt leaks: "
            + "; ".join(f"{leak.kind}={leak.detail!r} near …{leak.excerpt}…" for leak in leaks)
        )
