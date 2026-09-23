"""
Standalone CLI for testing alignment similarity functions directly
against specific texts -- isolated from the full Evaluator pipeline, so
a new candidate function (or a fix to an existing one) can be checked in
seconds against known problem cases, without running the whole pipeline.

Usage examples:

    # Quick 1-vs-1 pair check
    python3 -m evaluator.alignment_cli \
        --system "kali is a very evil attacker" \
        --gold "an offensive framework host named 'kali'"

    # Full N-vs-M matrix (repeat --system / --gold as needed)
    python3 -m evaluator.alignment_cli \
        --system "kali is a very evil attacker" \
        --system "kali sends a phishing email to the victim" \
        --gold "an offensive framework host named 'kali'" \
        --gold "kali sends spoofed ARP replies to the victim"

    # N-vs-M matrix extracted directly from description files (parses
    # "Step N — Title" format; falls back to whole-file-as-one-text if no
    # step headers are found)
    python3 -m evaluator.alignment_cli \
        --system-file system_output.txt --gold-file ransomware_01_baseline.txt \
        --method tfidf

    # Re-run this project's own two confirmed TF-IDF failure cases,
    # against any method, with one flag -- no retyping needed
    python3 -m evaluator.alignment_cli --known-cases --method tfidf
    python3 -m evaluator.alignment_cli --known-cases --method local_embedding

    # Choosing a different method (once its dependencies are installed
    # -- see each function's docstring in alignment.py for exact setup)
    python3 -m evaluator.alignment_cli --known-cases --method alignscore \
        --alignscore-ckpt /path/to/AlignScore-base.ckpt

Adding a new candidate function later: implement it in alignment.py with
the same signature as the existing ones (texts_a, texts_b) -> np.ndarray,
then add one line to METHODS below -- nothing else in this file needs to
change. This is the "isolated, swappable" part: alignment.py's functions
are the only thing that needs touching to add or replace a method.
"""
from __future__ import annotations

import argparse
import re

from .alignment import (
    tfidf_similarity_matrix,
    embedding_similarity_matrix,
    local_embedding_similarity_matrix,
    alignscore_similarity_matrix,
    run_rubric_test,
)

# The one place a new candidate similarity function gets registered.
METHODS = {
    "tfidf": tfidf_similarity_matrix,
    "embedding": embedding_similarity_matrix,
    "local_embedding": local_embedding_similarity_matrix,
    "alignscore": alignscore_similarity_matrix,
}

_STEP_HEADER_RE = re.compile(r"^Step\s+\d+\s*[—-]\s*.+$", re.MULTILINE)


def extract_steps_from_file(path: str) -> list[str]:
    """
    Parses a "Step N — Title" / indented-description text file (the
    format this project's description .txt files and extracted_descriptions
    reference files use) into a list of individual claim texts, one per
    step -- so a whole description file can be pointed at directly instead
    of retyping each step as a separate --system/--gold argument.

    Each returned entry is the step's BODY text only (not its title) --
    kept consistent with how gold/system claim texts are compared
    elsewhere in this project (plain descriptive sentences, no separate
    title field). Multi-line, word-wrapped body text is collapsed back
    into a single flowing string (the wrapping in the source file is for
    readability only, not meaningful line structure).

    Falls back to treating the WHOLE file as a single text (one-item
    list) if no "Step N —" headers are found at all -- e.g. for a
    natural-prose description file with no step segmentation. Prints a
    warning in that case rather than failing silently, since it changes
    what's being compared (one big text vs several atomic claims).
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    matches = list(_STEP_HEADER_RE.finditer(text))
    if not matches:
        print(f"[warning] No 'Step N —' headers found in {path} -- "
              f"treating the entire file as a single text.")
        whole = re.sub(r"\s+", " ", text).strip()
        return [whole] if whole else []

    steps = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = re.sub(r"\s+", " ", text[start:end]).strip()
        if body:
            steps.append(body)
    return steps


# This project's own confirmed TF-IDF failure cases -- kept here so any
# new method can be checked against them with one flag, not retyped.
KNOWN_CASES = [
    (
        "kali is a very evil attacker",
        "an offensive framework host named 'kali'",
        "should score with confident margin (same real-world claim, different wording) -- "
        "TF-IDF confirmed to score this only 0.151, barely above a typical 0.15 threshold "
        "(a real weak spot, though not as dramatic as first documented -- corrected after "
        "direct re-verification found the original '0.0' claim was inaccurate)",
    ),
    (
        "kali sends a phishing email to the victim",
        "kali sends spoofed ARP replies to the victim",
        "should be a LOW match (different, unrelated events) -- "
        "TF-IDF confirmed to score this 0.381, wrongly above a 0.2 threshold (false positive)",
    ),
]

# RUBRIC_CASES and run_rubric_test now live in alignment.py, so they're
# shared with pipeline_runner.py's --evaluate mode too -- imported above.
def main():
    parser = argparse.ArgumentParser(
        description="Test an alignment similarity function directly against specific texts."
    )
    parser.add_argument("--method", choices=list(METHODS.keys()), default="tfidf",
                         help="Which similarity function to test (default: tfidf).")
    parser.add_argument("--system", action="append", default=[],
                         help="A system-side text. Repeatable for an N-vs-M matrix.")
    parser.add_argument("--gold", action="append", default=[],
                         help="A gold-side text. Repeatable for an N-vs-M matrix.")
    parser.add_argument("--system-file", type=str, default=None,
                         help="Path to a 'Step N — Title' formatted text file -- each step's "
                              "body is extracted as its own system text (added to any --system "
                              "values given). Falls back to treating the whole file as one text "
                              "if no step headers are found.")
    parser.add_argument("--gold-file", type=str, default=None,
                         help="Same as --system-file, for the gold side.")
    parser.add_argument("--known-cases", action="store_true",
                         help="Ignore --system/--gold and run this project's own two "
                              "confirmed TF-IDF failure cases instead.")
    parser.add_argument("--rubric-test", action="store_true",
                         help="Run the full 5-category ordering-constraint rubric "
                              "(identical/unrelated/paraphrase/error_minor/error_severe) "
                              "and report PASS/FAIL for each constraint. Ignores --system/--gold.")
    # alignscore-specific options (ignored by other methods)
    parser.add_argument("--alignscore-model", default="roberta-base")
    parser.add_argument("--alignscore-ckpt", default=None,
                         help="Path to a downloaded AlignScore checkpoint. Required if "
                              "--method alignscore is used.")
    parser.add_argument("--alignscore-device", default="cpu")
    # local_embedding-specific option (ignored by other methods)
    parser.add_argument("--local-embedding-model", default="all-MiniLM-L6-v2")
    args = parser.parse_args()

    similarity_fn = METHODS[args.method]

    kwargs = {}
    if args.method == "alignscore":
        if not args.alignscore_ckpt:
            parser.error("--method alignscore requires --alignscore-ckpt")
        kwargs = {"model": args.alignscore_model, "ckpt_path": args.alignscore_ckpt, "device": args.alignscore_device}
    elif args.method == "local_embedding":
        kwargs = {"model_name": args.local_embedding_model}

    if args.rubric_test:
        result = run_rubric_test(similarity_fn, method_name=args.method, **kwargs)
        print(result.to_text())
        return

    if args.known_cases:
        system_texts = [c[0] for c in KNOWN_CASES]
        gold_texts = [c[1] for c in KNOWN_CASES]
        notes = [c[2] for c in KNOWN_CASES]
    else:
        system_texts = list(args.system)
        gold_texts = list(args.gold)
        if args.system_file:
            system_texts += extract_steps_from_file(args.system_file)
        if args.gold_file:
            gold_texts += extract_steps_from_file(args.gold_file)
        if not system_texts or not gold_texts:
            parser.error("Provide at least one --system/--system-file and one "
                         "--gold/--gold-file text, or use --known-cases.")
        notes = None

    print(f"=== Method: {args.method} ===\n")

    if args.known_cases:
        # Each case run in ISOLATION (its own similarity_fn call) --
        # confirmed necessary: batching multiple cases into one matrix
        # call changes TF-IDF's jointly-fitted vocabulary and shifts the
        # resulting scores away from the originally-documented values
        # (case 1 measured 0.087 when batched with case 2, vs the
        # documented 0.0 found when tested alone).
        for i, (sys_text, gold_text, note) in enumerate(KNOWN_CASES):
            sim = similarity_fn([sys_text], [gold_text], **kwargs)
            score = sim[0, 0]
            print(f"Case {i+1}: score={score:.3f}")
            print(f"  system: \"{sys_text}\"")
            print(f"  gold:   \"{gold_text}\"")
            print(f"  ({note})")
            print()
    else:
        sim = similarity_fn(system_texts, gold_texts, **kwargs)
        # Full N-vs-M matrix, labeled for readability
        header = "".join(f"{f'gold[{j}]':>10}" for j in range(len(gold_texts)))
        print(f"{'':>10}{header}")
        for i, row in enumerate(sim):
            row_str = "".join(f"{v:>10.3f}" for v in row)
            print(f"sys[{i}]:  {row_str}")
        print()
        print("system texts:")
        for i, t in enumerate(system_texts):
            print(f"  [{i}] {t}")
        print("gold texts:")
        for j, t in enumerate(gold_texts):
            print(f"  [{j}] {t}")


if __name__ == "__main__":
    main()