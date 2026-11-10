"""
The steps file: one `sources/<paper_id>/steps.json` per paper.

  Responsibility: the uniform record of a paper's attack steps as the paper
  itself presents them, the capture that paper published, and -- per step --
  what was actually found in that capture.

  This replaces the per-paper CSVs under `pcaps/datasets/`, which had a
  different column set in every folder and so could not be validated,
  diffed or joined. The rules the format exists to enforce:

    The paper's wording wins.   `verbatim` is a diagram label or a sentence,
                                copied. A paraphrase lives only in
                                `normalized`, in one fixed template, so the
                                two can never be confused for each other.
    One step is one arrow.      Or one numbered item in the paper's own list.
                                A step that does several things stays one
                                step with `compound` set; splitting into
                                atomic claims is extraction's job, not this
                                file's.
    Unknown is a value.         Every field is always present; what is not
                                known is `null` with `needs_review` set,
                                never omitted and never filled with a guess.
    The capture decides.        A `pcap_check` of "found" has to carry the
                                packets and the display filter that found
                                them, and the validator rejects it if it
                                does not. Nothing here may be written from
                                reading the paper alone.

  JSON is the source of truth. `steps.md` is generated from it and carries a
  banner saying so; a CSV, if one is wanted, is derived with the same
  columns. Editing either by hand loses the edit on the next render.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field

from .ids import file_sha256
from .manifest import REPO_ROOT

SOURCES_DIR = "sources"

STEP_TYPES = ("message", "internal", "outcome", "other")
CHECK_STATUSES = ("found", "not_found", "unchecked")

MD_COLUMNS = ("ID", "Phase", "Location", "Verbatim", "Normalized", "Type", "PCAP check")

GENERATED_BANNER = (
    "<!-- GENERATED FROM steps.json BY `./pangea steps render` - DO NOT EDIT BY HAND -->"
)


class Paper(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    authors: str | None
    venue: str | None
    year: int | None
    url: str | None
    license: str | None


class PcapRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str | None
    sha256: str | None
    size_bytes: int | None
    packet_count: int | None
    origin_url: str | None
    matches_figure: str | None
    match_note: str | None


class PcapCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["found", "not_found", "unchecked"]
    packets: list[int] = Field(default_factory=list)
    filter: str
    note: str


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    seq: int
    phase: str | None
    source_location: str
    verbatim: str
    normalized: str
    actor: str | None
    target: str | None
    protocol: str | None
    step_type: Literal["message", "internal", "outcome", "other"]
    compound: bool
    pcap_check: PcapCheck
    extracted_by: Literal["agent", "human"]
    needs_review: bool


class StepsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paper: Paper
    pcap: PcapRef
    steps: list[Step]


# --------------------------------------------------------------------------
# validation


class Problem(BaseModel):
    """One validation failure, located precisely enough to fix it."""

    model_config = ConfigDict(extra="forbid")

    path: str
    where: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - formatting only
        return f"{self.path}: {self.where}: {self.message}"


def _key_order_problems(raw: Any, model: type[BaseModel], where: str, path: str) -> list[Problem]:
    """Field order is part of the format, so a reordered file is a failure.

    Uniformity is the point of the file: a reader, a diff and a reviewer all
    rely on step N's fields appearing in the same places in every paper.
    """
    if not isinstance(raw, dict):
        return []
    expected = [name for name in model.model_fields if name in raw]
    actual = [key for key in raw if key in model.model_fields]
    if actual != expected:
        return [Problem(path=path, where=where,
                        message=f"field order is {actual}, expected {expected}")]
    return []


def validate_payload(raw: Any, path: str, repo_root: Path | None = None) -> tuple[StepsFile | None, list[Problem]]:
    """Validate one parsed steps.json. Returns the model (if it parsed) and every problem."""
    root = repo_root or REPO_ROOT
    problems: list[Problem] = []

    if not isinstance(raw, dict):
        return None, [Problem(path=path, where="file", message="top level is not an object")]

    try:
        doc = StepsFile.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError, kept broad on purpose
        for line in str(exc).splitlines():
            line = line.strip()
            if line and not line.startswith("For further information"):
                problems.append(Problem(path=path, where="schema", message=line))
        return None, problems

    problems += _key_order_problems(raw, StepsFile, "root", path)
    problems += _key_order_problems(raw.get("paper"), Paper, "paper", path)
    problems += _key_order_problems(raw.get("pcap"), PcapRef, "pcap", path)
    for index, raw_step in enumerate(raw.get("steps") or []):
        where = f"steps[{index}]"
        problems += _key_order_problems(raw_step, Step, where, path)
        if isinstance(raw_step, dict):
            problems += _key_order_problems(raw_step.get("pcap_check"), PcapCheck,
                                            f"{where}.pcap_check", path)

    problems += _cross_field_problems(doc, path, root)
    return doc, problems


def _cross_field_problems(doc: StepsFile, path: str, root: Path) -> list[Problem]:
    problems: list[Problem] = []

    if not doc.steps:
        problems.append(Problem(path=path, where="steps", message="no steps"))

    seen: dict[str, int] = {}
    for index, step in enumerate(doc.steps):
        where = f"steps[{index}] {step.step_id}"

        if step.step_id in seen:
            problems.append(Problem(path=path, where=where,
                                    message=f"duplicate step_id (also steps[{seen[step.step_id]}])"))
        seen[step.step_id] = index

        expected_id = f"{doc.paper.id}-S{step.seq:02d}"
        if step.step_id != expected_id:
            problems.append(Problem(path=path, where=where,
                                    message=f"step_id does not match the id scheme, expected {expected_id}"))

        if step.seq != index + 1:
            problems.append(Problem(path=path, where=where,
                                    message=f"seq is {step.seq}, expected {index + 1} (gaps and reordering are not allowed)"))

        check = step.pcap_check
        if check.status == "found":
            if not check.packets:
                problems.append(Problem(path=path, where=where,
                                        message='pcap_check "found" with no packets'))
            if not check.filter.strip():
                problems.append(Problem(path=path, where=where,
                                        message='pcap_check "found" with no filter'))
        if any(number < 1 for number in check.packets):
            problems.append(Problem(path=path, where=where,
                                    message="packet numbers are 1-based; found one below 1"))

        # A null is allowed anywhere, but on an arrow between two parties it
        # means the arrow could not be read, which is a reviewer's call.
        # `phase` may be null because the paper has no phases, and an
        # internal or outcome step legitimately carries no protocol, so
        # neither of those counts.
        if step.step_type == "message" and not step.needs_review:
            missing = [name for name, value in
                       (("actor", step.actor), ("target", step.target), ("protocol", step.protocol))
                       if value is None]
            if missing:
                problems.append(Problem(path=path, where=where,
                                        message=f"message step with null {', '.join(missing)} but needs_review is false"))

    problems += _pcap_problems(doc, path, root)
    return problems


def _pcap_problems(doc: StepsFile, path: str, root: Path) -> list[Problem]:
    """The capture has to be the one the hashes claim, or every check above is about another file."""
    problems: list[Problem] = []
    ref = doc.pcap
    cites_packets = any(step.pcap_check.status == "found" for step in doc.steps)

    if ref.file is None:
        if cites_packets:
            problems.append(Problem(path=path, where="pcap",
                                    message='steps cite packets but pcap.file is null'))
        return problems

    capture = (root / ref.file).resolve()
    if not capture.is_file():
        problems.append(Problem(path=path, where="pcap", message=f"no such file: {ref.file}"))
        return problems

    if ref.size_bytes is not None and capture.stat().st_size != ref.size_bytes:
        problems.append(Problem(path=path, where="pcap",
                                message=f"size_bytes is {ref.size_bytes}, file is {capture.stat().st_size}"))

    if ref.sha256 is not None:
        actual = file_sha256(capture)
        if actual != ref.sha256:
            problems.append(Problem(path=path, where="pcap",
                                    message=f"sha256 mismatch: recorded {ref.sha256}, file is {actual}"))
    elif cites_packets:
        problems.append(Problem(path=path, where="pcap",
                                message="steps cite packets but pcap.sha256 is null, so the citations are unanchored"))

    if ref.packet_count is not None:
        over = sorted({n for step in doc.steps for n in step.pcap_check.packets if n > ref.packet_count})
        if over:
            problems.append(Problem(path=path, where="pcap",
                                    message=f"packets cited beyond packet_count={ref.packet_count}: {over[:5]}"))
    return problems


def validate_file(path: Path, repo_root: Path | None = None) -> tuple[StepsFile | None, list[Problem]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, [Problem(path=str(path), where="file", message=f"invalid JSON: {exc}")]
    return validate_payload(raw, str(path), repo_root)


def steps_files(root: Path | None = None) -> list[Path]:
    base = (root or REPO_ROOT) / SOURCES_DIR
    return sorted(base.glob("*/steps.json"))


# --------------------------------------------------------------------------
# views: JSON is the source of truth, these are generated from it


def _check_cell(check: PcapCheck) -> str:
    if check.status != "found":
        return check.status
    shown = ", ".join(str(n) for n in check.packets[:6])
    if len(check.packets) > 6:
        shown += f", … ({len(check.packets)} total)"
    return f"found: {shown}"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(doc: StepsFile) -> str:
    paper = doc.paper
    head = [
        GENERATED_BANNER,
        "",
        f"# {paper.title}",
        "",
    ]
    byline = " · ".join(str(x) for x in (paper.authors, paper.venue, paper.year) if x)
    if byline:
        head += [byline, ""]
    if paper.url:
        head += [paper.url, ""]

    ref = doc.pcap
    head += ["## Capture", ""]
    if ref.file is None:
        head += ["No capture.", ""]
    else:
        head += [
            f"`{ref.file}`",
            "",
            f"- sha256 `{ref.sha256}`",
            f"- {ref.size_bytes} bytes, {ref.packet_count} packets",
            f"- origin: {ref.origin_url}",
            f"- matches: {ref.matches_figure}",
            "",
        ]
    if ref.match_note:
        head += [ref.match_note, ""]

    counts: dict[str, int] = {}
    for step in doc.steps:
        counts[step.pcap_check.status] = counts.get(step.pcap_check.status, 0) + 1
    tally = ", ".join(f"{counts[s]} {s}" for s in CHECK_STATUSES if s in counts)
    flagged = sum(1 for step in doc.steps if step.needs_review)
    head += [
        "## Steps",
        "",
        f"{len(doc.steps)} steps — {tally}. {flagged} flagged for review.",
        "",
        "| " + " | ".join(MD_COLUMNS) + " |",
        "|" + "|".join("---" for _ in MD_COLUMNS) + "|",
    ]

    rows = []
    for step in doc.steps:
        mark = " ⚠" if step.needs_review else ""
        kind = step.step_type + (" (compound)" if step.compound else "")
        rows.append("| " + " | ".join(_md_escape(cell) for cell in (
            step.step_id + mark,
            step.phase or "—",
            step.source_location,
            step.verbatim,
            step.normalized,
            kind,
            _check_cell(step.pcap_check),
        )) + " |")

    notes = [step for step in doc.steps if step.pcap_check.note or step.needs_review]
    tail: list[str] = []
    if notes:
        tail += ["", "## Notes", ""]
        for step in notes:
            prefix = "⚠ " if step.needs_review else ""
            tail.append(f"- **{step.step_id}** — {prefix}{step.pcap_check.note}".rstrip())
            if step.pcap_check.filter:
                tail.append(f"  - filter: `{step.pcap_check.filter}`")

    return "\n".join(head + rows + tail) + "\n"


def csv_rows(doc: StepsFile) -> list[list[str]]:
    rows = [list(MD_COLUMNS)]
    for step in doc.steps:
        rows.append([
            step.step_id,
            step.phase or "",
            step.source_location,
            step.verbatim,
            step.normalized,
            step.step_type + (" (compound)" if step.compound else ""),
            _check_cell(step.pcap_check),
        ])
    return rows


def render_csv(doc: StepsFile) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerows(csv_rows(doc))
    return buffer.getvalue()


def json_schema() -> dict[str, Any]:
    schema = StepsFile.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "PAnGEA steps file"
    schema["description"] = (
        "One steps.json per paper: the attack steps exactly as the paper or its "
        "diagram presents them, the paper's capture, and a per-step check against it."
    )
    return schema
