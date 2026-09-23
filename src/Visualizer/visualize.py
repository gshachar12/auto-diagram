"""
Visualizer's public entry point.

`generate_diagram()` is the only function pipeline_runner.py needs to call.
It always writes the `.d2` source file; rendering to image formats is
best-effort on top of that (see renderer.py -- a missing `d2` binary
degrades to "source written, nothing rendered", not an exception).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from Visualizer.d2_builder import build_d2_source
from Visualizer.renderer import render as render_d2

logger = logging.getLogger(__name__)


@dataclass
class VisualizerResult:
    d2_path: str
    rendered_paths: dict[str, str] = field(default_factory=dict)  # format -> path, only successes
    warnings: list[str] = field(default_factory=list)


def generate_diagram(
    actors,
    steps,
    resolved_actors=None,
    grounded_steps=None,
    output_dir: str = ".",
    base_filename: str = "traffic_diagram",
    render_formats: tuple[str, ...] = ("svg",),
    title: Optional[str] = None,
    evidence_link_base: Optional[str] = None,
) -> VisualizerResult:
    """
    Builds the D2 diagram of the described traffic and (best-effort)
    renders it.

    The diagram's shape (nodes/edges) always comes from the raw
    `actors`/`steps` (Step Extractor's output). `resolved_actors` and
    `grounded_steps` (Evidence Matcher's output) are optional decoration:
    when given, each actor node and step edge is colored and annotated
    with a tooltip showing its evidence-matcher result (resolved
    endpoint / grounding status / linked packet & aggregate counts); when
    omitted, the same diagram is still produced, just in a neutral
    "not yet grounded" style throughout.

    Args:
        actors: `list[Actor]` from Step Extractor.
        steps: `list[Step]` from Step Extractor.
        resolved_actors: optional `list[Actor]` from Evidence Matcher.
        grounded_steps: optional `list[GroundedStep]` from Evidence Matcher.
        output_dir: directory the `.d2` file (and any rendered images) are
            written into. Created if it doesn't exist.
        base_filename: filename stem, e.g. "traffic_diagram" ->
            traffic_diagram.d2, traffic_diagram.svg, traffic_diagram.png.
        render_formats: which image formats to render, e.g. ("svg",),
            ("svg", "png"), or () to only write the .d2 source and skip
            rendering entirely.
        title: optional diagram title.
        evidence_link_base: optional path/URL to Evidence Matcher's
            diagnostic JSON, passed straight through to
            `d2_builder.build_d2_source` -- see its docstring for exactly
            what gets linked and the caveat about JSON having no real
            fragment anchors.

    Returns:
        VisualizerResult with the path to the written .d2 file, a dict of
        format -> path for every image that rendered successfully (formats
        that failed to render, e.g. because the `d2` CLI isn't installed,
        are simply absent from this dict -- check `is_d2_available()` in
        Visualizer.renderer if you need to distinguish "not attempted"
        from "attempted and failed"), and any non-fatal warnings from
        diagram construction (e.g. a step that couldn't be drawn as an
        edge because it had fewer than 2 actor_refs).
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    build_result = build_d2_source(
        actors=actors,
        steps=steps,
        resolved_actors=resolved_actors,
        grounded_steps=grounded_steps,
        title=title,
        evidence_link_base=evidence_link_base,
    )
    for w in build_result.warnings:
        logger.warning("Visualizer: %s", w)

    d2_path = out_dir / f"{base_filename}.d2"
    d2_path.write_text(build_result.d2_source, encoding="utf-8")
    logger.info(
        "Visualizer: wrote D2 source (%d actor node(s), %d step-derived edge(s) requested) to %s",
        len(actors), len(steps), d2_path,
    )

    rendered_paths: dict[str, str] = {}
    for fmt in render_formats:
        image_path = out_dir / f"{base_filename}.{fmt}"
        if render_d2(d2_path, image_path):
            rendered_paths[fmt] = str(image_path)

    return VisualizerResult(
        d2_path=str(d2_path),
        rendered_paths=rendered_paths,
        warnings=build_result.warnings,
    )
