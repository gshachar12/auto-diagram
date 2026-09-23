"""
D2 source builder.

Builds the D2 diagram *text* (no rendering happens here -- see
`Visualizer.renderer` for that). Kept separate from rendering so the D2
source can be unit-tested/inspected without a `d2` binary available, and so
`pipeline_runner.py` can still get a `.d2` file written even in
environments where the CLI isn't installed.

LAYOUT: this renders as a D2 *sequence diagram* (`shape: sequence_diagram`
at the root). That gives us, for free, exactly the shape requested:
  - actors become vertical lifelines/columns, left-to-right in the order
    `actors` is given (i.e. Step Extractor's order)
  - steps become horizontal messages, top-to-bottom in the order `steps`
    is given (i.e. chronological/narrative order) -- each row is one
    "phase" of the traffic
This replaced an earlier generic-node-graph layout, which for any
non-trivial step count produced a tangle of long curved edges with no
left-to-right/top-to-bottom reading order.

Design, in one paragraph: the diagram's SHAPE (which actor columns and
message rows exist) is driven entirely by the raw `actors`/`steps` from
Step Extractor -- never by Evidence Matcher. Evidence Matcher's output
(`resolved_actors`, `grounded_steps`) is used ONLY to decorate that fixed
shape: it picks each lifeline/message's color class, prepends a status
glyph to message labels, and fills in tooltips. This means the diagram
still renders (in a neutral "ungrounded" style) even if Evidence Matcher
hasn't run yet or is passed as None -- see `generate_diagram` in
visualize.py for how the two optional args are threaded through.

Field-name assumptions (taken from how pipeline_runner.py itself uses these
objects -- adjust here if Grounder.models ever renames something):
  Actor:   actor_id, role, description_ref, resolved_endpoints, resolution_basis
  Step:    step_id, text, actor_refs, expected_indicators
             (.protocol, .port, .flags, .direction, .volume_pattern,
              .cardinality_pattern, .ip_hint, .indicator_description)
  GroundedStep: step, grounding
             (.status [enum w/ .value], .linked_packets, .linked_aggregate_refs, .notes)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from Visualizer.icon_map import icon_and_shape_for_role

_VALID_BARE_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Actor lifeline color, by Evidence Matcher resolution state.
_ACTOR_CLASSES = """\
  actorResolved: {
    style: {
      fill: "#d6f5d6"
      stroke: "#2e9e44"
      stroke-width: 2
      font-color: "#14401c"
    }
  }
  actorUnresolved: {
    style: {
      fill: "#f9d6d6"
      stroke: "#c0392b"
      stroke-width: 2
      font-color: "#4a1414"
    }
  }
  actorUngrounded: {
    style: {
      fill: "#e3e9f7"
      stroke: "#5b6fb8"
      stroke-width: 2
      font-color: "#1c2540"
    }
  }
"""

# Message (step edge) color, by Evidence Matcher grounding status.
_EDGE_CLASSES = """\
  edgeGrounded: {
    style: {
      stroke: "#2e9e44"
      stroke-width: 2
    }
  }
  edgeUnsupported: {
    style: {
      stroke: "#c0392b"
      stroke-dash: 4
      stroke-width: 2
    }
  }
  edgeUncertain: {
    style: {
      stroke: "#d4a017"
      stroke-dash: 2
      stroke-width: 2
    }
  }
  edgeUngrounded: {
    style: {
      stroke: "#8a94ad"
      stroke-dash: 6
      stroke-width: 1
    }
  }
"""

# Visible "note box" attached under a grounded/ungrounded message, showing
# the Evidence Matcher result as text you can actually read in a static
# export (an SVG/PNG has no hover state, so this can't live in a tooltip
# alone -- tooltips are still set too, for interactive D2 viewers).
_NOTE_CLASSES = """\
  noteGrounded: {
    style: {
      fill: "#f6fbf0"
      stroke: "#2e9e44"
      stroke-dash: 3
      font-color: "#27500a"
      font-size: 12
    }
  }
  noteUnsupported: {
    style: {
      fill: "#fff5f5"
      stroke: "#c0392b"
      stroke-dash: 3
      font-color: "#501313"
      font-size: 12
    }
  }
  noteUncertain: {
    style: {
      fill: "#fffaf0"
      stroke: "#d4a017"
      stroke-dash: 3
      font-color: "#5c4300"
      font-size: 12
    }
  }
  noteUngrounded: {
    style: {
      fill: "#f4f6f9"
      stroke: "#8a94ad"
      stroke-dash: 3
      font-color: "#3a4152"
      font-size: 12
    }
  }
"""

_CLASSES_BLOCK = "classes: {\n" + _ACTOR_CLASSES + _EDGE_CLASSES + _NOTE_CLASSES + "}\n"

_NOTE_CLASS_BY_STATUS = {
    "grounded": "noteGrounded",
    "unsupported": "noteUnsupported",
    "uncertain_needs_drilldown": "noteUncertain",
}

# Prepended to each message label so the grounding status reads at a glance
# even before the color/dash style registers -- and survives even if a
# renderer strips color (e.g. a black-and-white printout).
_STATUS_GLYPH = {
    "grounded": "\u2713",                    # check
    "unsupported": "\u2717",                 # cross
    "uncertain_needs_drilldown": "?",
}
_STATUS_GLYPH_UNGROUNDED = "\u25cb"          # hollow circle: no grounding data at all


@dataclass
class BuildResult:
    d2_source: str
    warnings: list[str]


def _d2_id(raw: str) -> str:
    """
    Returns a safe D2 map key for `raw`. Bare (unquoted) if it already looks
    like a normal identifier, otherwise wrapped in double quotes -- D2 keys
    accept quoted arbitrary strings, so this never has to reject an
    actor_id/step_id, only decide whether it needs quoting.
    """
    return raw if _VALID_BARE_ID.match(raw) else '"{}"'.format(raw.replace('"', '\\"'))


def _d2_str(text: str) -> str:
    """Escapes `text` for use inside a double-quoted D2 string literal."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _truncate(text: str, limit: int = 90) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "\u2026"


def _actor_tooltip(actor, resolved_actor, evidence_matcher_ran: bool) -> str:
    lines = []
    desc_ref = getattr(actor, "description_ref", None)
    if desc_ref:
        lines.append(f"description: {_truncate(str(desc_ref), 140)}")

    if resolved_actor is not None:
        endpoints = getattr(resolved_actor, "resolved_endpoints", None)
        basis = getattr(resolved_actor, "resolution_basis", None)
        if endpoints:
            lines.append(f"resolved to: {', '.join(str(e) for e in endpoints)}")
        else:
            lines.append("UNRESOLVED -- no matching endpoint found")
        if basis:
            lines.append(f"resolution basis: {basis}")
    elif evidence_matcher_ran:
        lines.append("not present in Evidence Matcher output")
    else:
        lines.append("Evidence Matcher has not run yet")

    return _d2_str("\n".join(lines))


def _indicator_summary(step) -> str:
    ei = getattr(step, "expected_indicators", None)
    if ei is None:
        return ""
    parts = []
    if getattr(ei, "protocol", None):
        parts.append(str(ei.protocol))
    if getattr(ei, "port", None) is not None:
        parts.append(f"port {ei.port}")
    if getattr(ei, "direction", None):
        parts.append(str(ei.direction))
    return " / ".join(parts)


@dataclass
class GroundingInfo:
    css_class: str          # edge style class, e.g. "edgeGrounded"
    note_class: Optional[str]  # note-box style class, None if nothing to show
    glyph: str               # status glyph prefixed onto the message label
    status: Optional[str]    # raw status string, or None if ungrounded
    tooltip: str              # escaped, for hover (interactive D2 viewers)
    note_lines: list[str]    # unescaped lines for the visible note box, empty if none


def _grounding_info(step, grounding) -> GroundingInfo:
    """
    Builds every piece of grounding-derived decoration for one step's
    message: which edge-color class to use, the status glyph, the hover
    tooltip, and the lines for a visible "note box" (a second, small
    self-message placed right under the main one) -- because a static
    SVG/PNG export has no hover state, the evidence summary needs to be
    readable as actual text, not just tucked into a tooltip.
    """
    indicator_summary = _indicator_summary(step)
    tooltip_lines = []
    if indicator_summary:
        tooltip_lines.append(f"expected: {indicator_summary}")

    if grounding is None:
        tooltip_lines.append("no grounding data for this step")
        return GroundingInfo(
            css_class="edgeUngrounded", note_class=None, glyph=_STATUS_GLYPH_UNGROUNDED,
            status=None, tooltip=_d2_str("\n".join(tooltip_lines)), note_lines=[],
        )

    status = getattr(getattr(grounding, "status", None), "value", str(getattr(grounding, "status", "")))
    linked_packets = getattr(grounding, "linked_packets", []) or []
    linked_aggregates = getattr(grounding, "linked_aggregate_refs", []) or []
    notes = getattr(grounding, "notes", None)

    tooltip_lines.append(f"status: {status}")
    tooltip_lines.append(f"linked packets: {len(linked_packets)}")
    tooltip_lines.append(f"linked aggregates: {len(linked_aggregates)}")
    if notes:
        tooltip_lines.append(f"notes: {_truncate(str(notes), 140)}")

    css_class = {
        "grounded": "edgeGrounded",
        "unsupported": "edgeUnsupported",
        "uncertain_needs_drilldown": "edgeUncertain",
    }.get(status, "edgeUngrounded")
    glyph = _STATUS_GLYPH.get(status, _STATUS_GLYPH_UNGROUNDED)
    note_class = _NOTE_CLASS_BY_STATUS.get(status, "noteUngrounded")

    note_lines = [f"Evidence: {status}", f"{len(linked_packets)} packet(s), {len(linked_aggregates)} aggregate(s) linked"]
    if notes:
        note_lines.append(_truncate(str(notes), 100))

    return GroundingInfo(
        css_class=css_class, note_class=note_class, glyph=glyph, status=status,
        tooltip=_d2_str("\n".join(tooltip_lines)), note_lines=note_lines,
    )


def build_d2_source(
    actors,
    steps,
    resolved_actors=None,
    grounded_steps=None,
    title: Optional[str] = None,
    evidence_link_base: Optional[str] = None,
) -> BuildResult:
    """
    Builds D2 sequence-diagram source for the traffic diagram: actors as
    columns (lifelines), steps as time-ordered rows (messages).

    Args:
        actors: raw `list[Actor]` from Step Extractor -- drives which
            actor lifelines exist and their left-to-right order.
        steps: raw `list[Step]` from Step Extractor -- drives which
            messages exist, top-to-bottom in the given order.
        resolved_actors: optional `list[Actor]` from Evidence Matcher (same
            actor_ids as `actors`, now carrying resolved_endpoints). If
            None, every lifeline is drawn in the neutral "ungrounded"
            style rather than green/red.
        grounded_steps: optional `list[GroundedStep]` from Evidence
            Matcher. If None, every message is drawn in the neutral
            "ungrounded" style (hollow-circle glyph) rather than
            green/red/yellow (check/cross/question-mark glyph).
        title: optional diagram title.
        evidence_link_base: optional path/URL to Evidence Matcher's
            diagnostic output (pipeline_runner.py writes this as
            "03c_evidence_matcher_output.json" when output_dir is set).
            When given, every grounded/ungrounded message and its note
            box become clickable D2 links to
            f"{evidence_link_base}#{step_id}" -- interactive D2 viewers
            (and the SVG/HTML `<a>` output d2 produces) will open that
            file. NOTE: `#step_id` is not a real JSON fragment identifier
            -- plain JSON has no addressable anchors -- so this reliably
            opens the right *file* but you'll still need to search it for
            the step_id once there. If None (default), no links are added.

    Returns:
        BuildResult(d2_source, warnings) -- warnings list human-readable
        strings for anything skipped/adjusted (e.g. a step with fewer than
        2 actor_refs can't be a message between two lifelines, so it's
        rendered as a self-message on its one actor instead; this is
        reported here too).
    """
    warnings: list[str] = []
    resolved_by_id = {a.actor_id: a for a in (resolved_actors or [])}
    grounding_by_step_id = {
        gs.step.step_id: gs.grounding for gs in (grounded_steps or [])
    }

    lines: list[str] = []
    if title:
        lines.append(f"# {title}")
    lines.append("shape: sequence_diagram")
    lines.append("")
    lines.append(_CLASSES_BLOCK)

    if title:
        lines.append(f'title: {{ label: "{_d2_str(title)}"; near: top-center }}')
        lines.append("")

    # --- actor lifelines (columns), in Step Extractor's order ---------- #
    known_actor_ids = {a.actor_id for a in actors}
    for actor in actors:
        node_id = _d2_id(actor.actor_id)
        role = getattr(actor, "role", "") or ""
        desc_ref = getattr(actor, "description_ref", None)
        resolved = resolved_by_id.get(actor.actor_id)

        if resolved is not None:
            css_class = "actorResolved" if getattr(resolved, "resolved_endpoints", None) else "actorUnresolved"
        else:
            css_class = "actorUngrounded"

        icon_url, shape = icon_and_shape_for_role(role, desc_ref)
        label = _d2_str(f"{actor.actor_id}\n({role})" if role else str(actor.actor_id))

        lines.append(f'{node_id}: "{label}" {{')
        lines.append(f"  shape: {shape}")
        lines.append(f'  icon: {icon_url}')
        lines.append(f"  class: {css_class}")
        lines.append(f'  tooltip: "{_actor_tooltip(actor, resolved, evidence_matcher_ran=resolved_actors is not None)}"')
        lines.append("}")

    lines.append("")

    # --- messages (rows), in Step Extractor's chronological order ----- #
    for step in steps:
        actor_refs = list(getattr(step, "actor_refs", []) or [])
        grounding = grounding_by_step_id.get(step.step_id)
        info = _grounding_info(step, grounding)
        label = _d2_str(f"{info.glyph} {step.step_id}: {_truncate(step.text)}")
        link_line = f'  link: "{_d2_str(f"{evidence_link_base}#{step.step_id}")}"' if evidence_link_base else None

        unknown_refs = [r for r in actor_refs if r not in known_actor_ids]
        if unknown_refs:
            warnings.append(
                f"step {step.step_id}: actor_refs {unknown_refs} not found in actors list; "
                "message(s) involving them may add stray lifelines"
            )

        if len(actor_refs) == 0:
            warnings.append(
                f"step {step.step_id}: has 0 actor_refs -- can't place it on the sequence "
                "diagram at all; skipped entirely"
            )
            continue

        if len(actor_refs) == 1:
            warnings.append(
                f"step {step.step_id}: has only 1 actor_ref -- rendered as a self-message "
                f"on {actor_refs[0]} rather than a cross-lifeline message"
            )
            note_anchor_id = _d2_id(actor_refs[0])
            lines.append(f'{note_anchor_id} -> {note_anchor_id}: "{label}" {{')
            lines.append(f"  class: {info.css_class}")
            lines.append(f'  tooltip: "{info.tooltip}"')
            if link_line:
                lines.append(link_line)
            lines.append("}")
        else:
            pair_count = len(actor_refs) - 1
            for j in range(pair_count):
                src_id = _d2_id(actor_refs[j])
                dst_id = _d2_id(actor_refs[j + 1])
                edge_label = label if pair_count == 1 else _d2_str(
                    f"{info.glyph} {step.step_id} ({j + 1}/{pair_count}): {_truncate(step.text, 60)}"
                )
                lines.append(f'{src_id} -> {dst_id}: "{edge_label}" {{')
                lines.append(f"  class: {info.css_class}")
                lines.append(f'  tooltip: "{info.tooltip}"')
                if link_line:
                    lines.append(link_line)
                lines.append("}")
            note_anchor_id = _d2_id(actor_refs[-1])

        # --- visible note box, right under the message it explains ---- #
        # A static SVG/PNG export has no hover state, so the grounding
        # result (status, linked-evidence counts, notes) is written out as
        # actual text here -- not just left in the tooltip above -- as a
        # second, smaller self-message on the destination actor, styled
        # like a callout via the note* classes.
        if info.note_lines:
            note_label = _d2_str("\n".join(info.note_lines))
            lines.append(f'{note_anchor_id} -> {note_anchor_id}: "{note_label}" {{')
            lines.append(f"  class: {info.note_class}")
            if link_line:
                lines.append(link_line)
            lines.append("}")

    return BuildResult(d2_source="\n".join(lines) + "\n", warnings=warnings)
