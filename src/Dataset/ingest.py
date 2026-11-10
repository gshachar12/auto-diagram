"""
Ingest the dataset folders under pcaps/datasets/ into the source registry.

  Responsibility: turn what is on disk -- a folder per published dataset,
  holding steps transcribed verbatim from a paper, a `source.md` recording
  exactly where they came from, and sometimes a sample capture -- into
  registry rows, with a verification checklist per source and per capture.

  This is milestone M0's output, built from local files rather than from
  the web. What it must never do is improve on what is written down:

    Nothing is inferred.  Title, provenance and URLs are read out of
                          source.md. A dataset with no stated licence gets
                          `UNVERIFIED`, not a guess.
    Nothing is hidden.    A folder with no capture is still registered, and
                          the reason it has none (a gated download form)
                          becomes a failed checklist item rather than a
                          missing row.
    Claims are not made here. Steps are stored verbatim in `source_steps`.
                          Turning a step into an atomic claim with an
                          executable condition is the extraction agent's
                          job (B2), under review.
    Direction coverage is left unknown. `both_directions` stays None unless
                          the source says. Absence claims are judged against
                          it, so a guess becomes a wrong verdict later.

  Packet counts here are real: every capture is opened and counted with the
  PCAP service, and the count is checked against any figure stated in
  source.md. A mismatch is recorded as a failed check, not smoothed over.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .ids import content_id, file_sha256
from .manifest import REPO_ROOT
from .pcap import PcapService, PcapServiceError
from .schemas import CaptureMetadata, Pcap, Source
from .storage.db import Database
from .storage.repository import Repository, utc_now

DATASETS_DIR = "pcaps/datasets"

#: CSV columns that most plainly carry the step's text, best first. The
#: files come from different papers and do not share a schema.
TEXT_COLUMNS = ("attack_step", "description", "attack_name", "attack_type", "technique", "step", "scenario")
ORDER_COLUMNS = ("step_order", "row_order", "step", "order")

_URL = re.compile(r"https?://[^\s)>\]]+")
_PACKETS_STATED = re.compile(r"([\d,]+)\s+packets", re.IGNORECASE)
_BYTES_STATED = re.compile(r"([\d,]{6,})\s+bytes", re.IGNORECASE)


def _int(text: str) -> int | None:
    try:
        return int(text.replace(",", ""))
    except (ValueError, AttributeError):
        return None


def _title_of(source_md: str, fallback: str) -> str:
    for line in source_md.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def _step_text(row: dict[str, str]) -> str:
    """
    The most descriptive cell of a row, with the rest kept in `fields`.

    These CSVs have no common schema -- one has `attack_step`, another only
    `description`, a third only a tactic and a technique id -- so the text
    column is chosen per row and the whole row is stored regardless.
    """
    for column in TEXT_COLUMNS:
        value = (row.get(column) or "").strip()
        if value:
            return value
    return " | ".join(f"{k}={v}" for k, v in row.items() if v)


def _step_order(row: dict[str, str]) -> str:
    for column in ORDER_COLUMNS:
        value = (row.get(column) or "").strip()
        if value:
            return value
    return ""


def _steps_files(folder: Path) -> list[Path]:
    return sorted(p for p in folder.glob("*.csv"))


def _captures(folder: Path) -> list[Path]:
    return sorted(p for p in folder.iterdir() if p.suffix.lower() in (".pcap", ".pcapng", ".cap"))


def ingest_datasets(
    *,
    db: Database,
    datasets_dir: str | Path = DATASETS_DIR,
    service: PcapService | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Register every dataset folder. Returns a summary for the CLI."""
    root = repo_root or REPO_ROOT
    folder_root = Path(datasets_dir)
    if not folder_root.is_absolute():
        folder_root = root / folder_root
    if not folder_root.is_dir():
        raise FileNotFoundError(f"no dataset directory at {folder_root}")

    repo = Repository(db)
    registered: list[dict[str, Any]] = []

    for folder in sorted(p for p in folder_root.iterdir() if p.is_dir()):
        source_md_path = folder / "source.md"
        source_md = source_md_path.read_text(encoding="utf-8") if source_md_path.exists() else ""
        source_id = content_id("src", ["datasets", folder.name])

        if db.one("SELECT source_id FROM sources WHERE source_id = ?", (source_id,)):
            registered.append({"source": folder.name, "skipped": "already registered"})
            continue

        repo.add_source(
            Source(
                source_id=source_id,
                title=_title_of(source_md, folder.name),
                urls=sorted(set(_URL.findall(source_md)))[:20],
                license="UNVERIFIED",
                origin=str(folder.relative_to(root)),
                notes=source_md[:4000],
            )
        )
        repo.add_verification_check(
            source_id=source_id,
            item="provenance recorded (source.md names the table/section the steps came from)",
            status="pass" if source_md else "fail",
            notes="" if source_md else "no source.md in this folder",
        )
        repo.add_verification_check(
            source_id=source_id,
            item="licence / reuse terms recorded",
            status="unverified",
            notes="source.md records provenance, not a licence. To be confirmed before use.",
        )

        steps = _ingest_steps(repo, db, source_id, folder, root)
        repo.add_verification_check(
            source_id=source_id,
            item="steps transcribed verbatim",
            status="pass" if steps else "fail",
            notes=f"{steps} step rows" if steps else "no steps CSV found",
        )

        captures = _ingest_captures(repo, source_id, folder, source_md, service, root)
        if not captures:
            repo.add_verification_check(
                source_id=source_id,
                item="sample capture obtained",
                status="fail",
                notes="No capture in this folder; see source.md for why (e.g. a gated download form).",
            )
        repo.add_verification_check(
            source_id=source_id,
            item="every step located in the capture",
            status="unverified",
            notes="Manual check, still to do (M0).",
        )
        repo.add_verification_check(
            source_id=source_id, item="keep / drop decision", status="unverified",
            notes="Project owner's decision; not made by the ingest.",
        )
        registered.append({"source": folder.name, "source_id": source_id, "steps": steps, "captures": captures})

    return {"datasets_dir": str(folder_root), "registered": registered}


def _ingest_steps(repo: Repository, db: Database, source_id: str, folder: Path, root: Path) -> int:
    total = 0
    for csv_path in _steps_files(folder):
        with open(csv_path, newline="", encoding="utf-8-sig") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=1):
                cleaned = {k: (v or "").strip() for k, v in row.items() if k}
                if not any(cleaned.values()):
                    continue
                origin = str(csv_path.relative_to(root))
                db.insert(
                    "source_steps",
                    dict(
                        step_id=content_id("stp", [source_id, origin, row_number]),
                        source_id=source_id,
                        origin_file=origin,
                        row_number=row_number,
                        step_order=_step_order(cleaned),
                        text=_step_text(cleaned),
                        fields=json.dumps(cleaned, ensure_ascii=False),
                        created_at=utc_now(),
                    ),
                )
                total += 1
    return total


def _ingest_captures(
    repo: Repository,
    source_id: str,
    folder: Path,
    source_md: str,
    service: PcapService | None,
    root: Path,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for capture in _captures(folder):
        relative = str(capture.relative_to(root))
        pcap_id = content_id("pcap", ["datasets", relative])
        summary = None
        error = ""
        if service is not None:
            try:
                summary = service.summary(capture)
            except PcapServiceError as exc:
                error = str(exc)

        digest = summary.sha256 if summary else file_sha256(capture)
        repo.add_pcap(
            Pcap(
                pcap_id=pcap_id,
                source_id=source_id,
                path=relative,
                sha256=digest,
                size_bytes=capture.stat().st_size,
                packet_count=summary.packet_count if summary else None,
                capture_metadata=CaptureMetadata(
                    vantage_point="UNVERIFIED — see source.md",
                    both_directions=None,
                    known_gaps=[],
                    notes=(
                        f"link type {summary.link_type}; "
                        f"window {summary.first_packet_epoch}–{summary.last_packet_epoch}"
                        if summary else "not opened yet"
                    ),
                ),
                license="UNVERIFIED",
                origin=f"{folder.name}; provenance in {folder.name}/source.md",
            )
        )
        repo.add_verification_check(
            source_id=source_id, pcap_id=pcap_id, item="capture present and hashed", status="pass",
            notes=f"sha256 {digest[:16]}…, {capture.stat().st_size} bytes",
        )
        repo.add_verification_check(
            source_id=source_id, pcap_id=pcap_id,
            item="opened and counted with tshark",
            status="pass" if summary else "fail",
            notes=f"{summary.packet_count} packets" if summary else (error or "PCAP service unavailable"),
        )

        # Cross-check against any count the source itself states.
        stated = _stated_packet_count(source_md, capture.name)
        if stated is not None and summary is not None:
            matches = stated == summary.packet_count
            repo.add_verification_check(
                source_id=source_id, pcap_id=pcap_id,
                item="packet count matches the figure stated in source.md",
                status="pass" if matches else "fail",
                notes=f"source.md says {stated}, tshark counts {summary.packet_count}",
            )
        results.append(
            {
                "pcap_id": pcap_id,
                "path": relative,
                "packets": summary.packet_count if summary else None,
                "error": error or None,
            }
        )
    return results


def _stated_packet_count(source_md: str, capture_name: str) -> int | None:
    """
    A packet count written in source.md for this capture, if there is one.

    Only the sentence mentioning the file by name is consulted; these files
    often describe several captures, and matching the wrong one would turn
    a cross-check into a false alarm.
    """
    for paragraph in source_md.split("\n\n"):
        if capture_name in paragraph:
            found = _PACKETS_STATED.search(paragraph)
            if found:
                return _int(found.group(1))
    return None
