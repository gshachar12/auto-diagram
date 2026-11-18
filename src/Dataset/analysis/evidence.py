"""
Derived verification: what the capture says about what a model said.

  Responsibility: for one model call, re-execute the condition the model
  wrote against the pair's own capture and record what came back. These are
  the fields the spec calls derived -- reexecuted_packets, cited_verified,
  cited_unverified, fabricated_count, sufficiency_ok, necessity_ok -- and
  they are computed here and nowhere else.

  How each one is obtained, all through the PCAP service so the filter is
  compiled before it runs and the scan stays bounded:

    re-execution   the condition as written, run on the capture.
    cited packets  `(condition) && frame.number in {…}` -- which of the
                   packets the model named actually satisfy its own
                   condition. Asking the question this way is exact and
                   bounded, where comparing against a truncated list of
                   returned packets would call a packet unverified merely
                   because the output cap cut the list before it.
    fabricated     a cited packet number past the end of the capture (or
                   below 1). It cannot be a mis-read packet; it is not in
                   the file.
    sufficiency    run the condition on the cited packets alone: does the
                   evidence the model offered, by itself, still give the
                   verdict it gave?
    necessity      run the condition with the cited packets removed: does
                   the verdict flip once that evidence is gone? If it does
                   not, the citation was decoration, not evidence.

  Nothing is guessed. A missing capture, a filter tshark refuses, a capture
  too large for the scan budget and an answer with no condition at all are
  each recorded as NULL with a `status` and a `note` saying which one it
  was. A zero in any of these columns means the capture was asked and
  answered zero.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..pcap import FilterError, PcapService, PcapServiceError
from ..schemas import Verdict

#: Why a call has no derived verification. Stored verbatim in `status`.
STATUS_OK = "ok"
STATUS_NO_SERVICE = "no_pcap_service"
STATUS_NO_CAPTURE = "no_capture"
STATUS_CAPTURE_MISSING = "capture_missing"
STATUS_CAPTURE_TOO_LARGE = "capture_too_large"
STATUS_NO_CONDITION = "no_condition"
STATUS_NOT_EXECUTABLE = "condition_not_executable"
STATUS_PCAP_ERROR = "pcap_error"


@dataclass
class CallFact:
    """One row of analysis_call_facts, before it is stored."""

    call_id: str
    reexecuted_packets: list[int] = field(default_factory=list)
    reexecuted_count: int | None = None
    truncated: bool = False
    cited_verified: list[int] = field(default_factory=list)
    cited_unverified: list[int] = field(default_factory=list)
    fabricated_count: int | None = None
    sufficiency_ok: bool | None = None
    necessity_ok: bool | None = None
    status: str = STATUS_OK
    note: str = ""

    def as_row(self, analysis_id: str) -> dict[str, Any]:
        return {
            "analysis_id": analysis_id,
            "call_id": self.call_id,
            "reexecuted_packets": json.dumps(self.reexecuted_packets),
            "reexecuted_count": self.reexecuted_count,
            "truncated": int(self.truncated),
            "cited_verified": json.dumps(self.cited_verified),
            "cited_unverified": json.dumps(self.cited_unverified),
            "fabricated_count": self.fabricated_count,
            "sufficiency_ok": None if self.sufficiency_ok is None else int(self.sufficiency_ok),
            "necessity_ok": None if self.necessity_ok is None else int(self.necessity_ok),
            "status": self.status,
            "note": self.note,
        }


def membership_filter(numbers: list[int]) -> str:
    """`frame.number in {12,15,88}` -- the exact, bounded way to ask about a set."""
    return "frame.number in {" + ",".join(str(n) for n in sorted(set(numbers))) + "}"


def _verdict_from_matches(match_count: int) -> str:
    """
    The mechanical reading of a filter's result.

    SUPPORTED when something matches, REFUTED when nothing does. This is
    only ever compared against a model's own SUPPORTED/REFUTED answer;
    NOT_VERIFIABLE is a judgement about the capture, not about a match
    count, so a call that abstained is never scored here.
    """
    return str(Verdict.SUPPORTED) if match_count > 0 else str(Verdict.REFUTED)


class EvidenceChecker:
    """
    Re-executes conditions, with one cache per (capture, filter).

    The PCAP service already caches by content in the database; this adds
    an in-process memo because one run asks the same few questions hundreds
    of times -- every repeat of every prompt of every model tends to write
    the same condition -- and a dictionary lookup beats a round trip.
    """

    def __init__(
        self,
        *,
        service: PcapService | None,
        repo_root: Path,
        max_capture_bytes: int | None,
        reexecution_limit: int,
        max_cited_packets: int,
    ) -> None:
        self.service = service
        self.root = repo_root
        self.max_capture_bytes = max_capture_bytes
        self.reexecution_limit = int(reexecution_limit)
        self.max_cited_packets = int(max_cited_packets)
        self._queries: dict[tuple[str, str], Any] = {}
        self.counts: dict[str, int] = {}

    # -- running one query -------------------------------------------------

    def _query(self, capture: dict[str, Any], display_filter: str):
        key = (capture["pcap_id"], display_filter)
        if key not in self._queries:
            self._queries[key] = self.service.query(
                self.root / capture["path"], display_filter, limit=self.reexecution_limit
            )
        return self._queries[key]

    def _record(self, status: str) -> None:
        self.counts[status] = self.counts.get(status, 0) + 1

    # -- the fact ----------------------------------------------------------

    def fact(
        self,
        *,
        call_id: str,
        capture: dict[str, Any] | None,
        packet_count: int | None,
        condition: str | None,
        cited: list[int],
        verdict: str | None,
    ) -> CallFact:
        """Everything the capture can say about one call. NULL where it cannot."""
        fact = CallFact(call_id=call_id)

        if self.service is None:
            fact.status = STATUS_NO_SERVICE
            fact.note = "tshark was not available to this analysis, so nothing was re-executed"
            self._record(fact.status)
            return fact
        if capture is None:
            fact.status = STATUS_NO_CAPTURE
            fact.note = "this pair carries no capture (a leakage probe), so there is nothing to re-execute"
            self._record(fact.status)
            return fact

        path = self.root / capture["path"]
        if not path.is_file():
            fact.status = STATUS_CAPTURE_MISSING
            fact.note = f"{capture['path']} is not on disk"
            self._record(fact.status)
            return fact
        if self.max_capture_bytes and capture["size_bytes"] > self.max_capture_bytes:
            fact.status = STATUS_CAPTURE_TOO_LARGE
            fact.note = (
                f"{capture['size_bytes'] / 1e6:.1f} MB is over the analysis scan budget "
                f"({self.max_capture_bytes / 1e6:.0f} MB); re-execution was not attempted"
            )
            self._record(fact.status)
            return fact

        # Fabricated packets can be found without the condition: a number
        # past the end of the file is fabricated whatever the filter says.
        cited = [n for n in cited if isinstance(n, int)][: self.max_cited_packets]
        if packet_count is not None:
            fact.fabricated_count = sum(1 for n in cited if n < 1 or n > packet_count)

        if not condition or not condition.strip():
            fact.status = STATUS_NO_CONDITION
            fact.note = "the answer carried no executable condition"
            self._record(fact.status)
            return fact

        try:
            full = self._query(capture, condition)
        except FilterError as exc:
            fact.status = STATUS_NOT_EXECUTABLE
            fact.note = f"tshark refused the condition: {exc}"
            self._record(fact.status)
            return fact
        except PcapServiceError as exc:
            fact.status = STATUS_PCAP_ERROR
            fact.note = f"{type(exc).__name__}: {exc}"
            self._record(fact.status)
            return fact

        fact.reexecuted_packets = [int(p["number"]) for p in full.packets]
        fact.reexecuted_count = full.match_count
        fact.truncated = bool(full.truncated)

        if cited:
            try:
                verified = self._query(capture, f"({condition}) && {membership_filter(cited)}")
                fact.cited_verified = sorted({int(p["number"]) for p in verified.packets})
                fact.cited_unverified = sorted(set(cited) - set(fact.cited_verified))

                # Sufficiency and necessity are statements about a verdict,
                # so they are only defined where the model gave one of the
                # two verdicts a match count can speak to.
                if verdict in (str(Verdict.SUPPORTED), str(Verdict.REFUTED)):
                    fact.sufficiency_ok = _verdict_from_matches(verified.match_count) == verdict
                    without = self._query(capture, f"({condition}) && !({membership_filter(cited)})")
                    fact.necessity_ok = _verdict_from_matches(without.match_count) != verdict
                else:
                    fact.note = (
                        "sufficiency and necessity are not defined for an abstention: "
                        "NOT_VERIFIABLE is a judgement about the capture, not a match count"
                    )
            except PcapServiceError as exc:
                fact.status = STATUS_PCAP_ERROR
                fact.note = f"cited-packet check failed: {type(exc).__name__}: {exc}"
                self._record(fact.status)
                return fact
        else:
            fact.note = "the answer cited no packets, so there is nothing to verify or to remove"

        self._record(fact.status)
        return fact
