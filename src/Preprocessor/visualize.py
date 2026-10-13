"""
PAnGEA — interactive HTML viewer for preprocessor output.

Renders every cluster as a bubble (area = packet count, colour = tier);
clicking a bubble shows its fingerprint, scale, timing, tier signals,
grounder text and sample packets. The page is self-contained apart from
d3 and fonts loaded from public CDNs.

Usage (from src/):
    # run the pipeline and visualise in one step
    python -m Preprocessor.visualize <pcap_file> <description_file> [-o out.html]

    # visualise a saved ReducerOutput JSON (as printed by Preprocessor.preprocessor)
    python -m Preprocessor.visualize <output.json> [-o out.html]
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from Preprocessor.layer2_fingerprint import DEFAULT_DELTA_T
from Preprocessor.layer4_analysis import (
    _PRIMARY_TFIDF_THRESHOLD,
    _PRIMARY_ZSCORE_THRESHOLD,
    _REMNANT_TFIDF_THRESHOLD,
)

_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "visualizer_template.html")
_DATA_PLACEHOLDER = "__PANGEA_DATA__"
_DOC_HEAD = (
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
    "</head>\n<body>\n"
)
_DOC_TAIL = "\n</body>\n</html>\n"


def render_html(
    output: dict,
    source: Optional[str] = None,
    description_file: Optional[str] = None,
    delta_t: float = DEFAULT_DELTA_T,
    fragment: bool = False,
) -> str:
    """
    Build the viewer page for one ReducerOutput (as a dict, e.g. from asdict()).

    fragment=True omits the <!doctype>/<html>/<body> wrapper, for hosts that
    supply their own document skeleton.
    """
    payload = {
        "output": output,
        "meta": {
            "source": source,
            "description_file": description_file,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "thresholds": {
                "tfidf_primary": _PRIMARY_TFIDF_THRESHOLD,
                "tfidf_remnant": _REMNANT_TFIDF_THRESHOLD,
                "zscore":        _PRIMARY_ZSCORE_THRESHOLD,
                "delta_t":       delta_t,
            },
        },
    }
    # Escape "</" so description text can never close the <script> tag early.
    data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")

    with open(_TEMPLATE_PATH, "r", encoding="utf-8") as f:
        page = f.read().replace(_DATA_PLACEHOLDER, data, 1)

    return page if fragment else _DOC_HEAD + page + _DOC_TAIL


def main() -> None:
    parser = argparse.ArgumentParser(description="Render preprocessor output as an interactive HTML page.")
    parser.add_argument("inputs", nargs="+",
                        help="<output.json>  or  <pcap_file> <description_file_or_text>")
    parser.add_argument("-o", "--output", help="HTML file to write (default: next to the input, *_clusters.html)")
    parser.add_argument("--token-budget", type=int, default=10000)
    parser.add_argument("--delta-t", type=float, default=DEFAULT_DELTA_T)
    parser.add_argument("--fragment", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    description_file = None
    if len(args.inputs) == 1:
        source = args.inputs[0]
        with open(source, "r", encoding="utf-8") as f:
            output = json.load(f)
    elif len(args.inputs) == 2:
        from Preprocessor.preprocessor import run_preprocessing

        source, description = args.inputs
        if os.path.isfile(description):
            description_file = description
            with open(description, "r", encoding="utf-8") as f:
                description = f.read()
        with open(source, "rb") as f:
            pcap_bytes = f.read()
        output = asdict(run_preprocessing(
            pcap_bytes=pcap_bytes,
            attack_description=description,
            token_budget=args.token_budget,
            delta_t=args.delta_t,
        ))
    else:
        parser.error("expected <output.json> or <pcap_file> <description>")

    out_path = args.output or os.path.splitext(source)[0] + "_clusters.html"
    html = render_html(
        output,
        source=os.path.basename(source),
        description_file=os.path.basename(description_file) if description_file else None,
        delta_t=args.delta_t,
        fragment=args.fragment,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
