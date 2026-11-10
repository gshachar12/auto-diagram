"""
Building (claim x capture) pairs.

  Responsibility: turn reviewed claims into the items a panel is actually
  asked about -- and prove, before storing one, that each item is the kind
  of item it claims to be.

  The four types and what each is for:

    source    the claim against its own capture. Baseline agreement.
    mutation  the same claim with exactly ONE detail changed -- a port, a
              protocol, a direction, a magnitude, an order. Expected
              REFUTED, and the expectation is only worth anything because
              it is checked: the mutated condition must find nothing on
              that capture. Contradiction detection.
    swap      the claim against a different scenario's capture. Scored as
              "not SUPPORTED" rather than REFUTED, because REFUTED would
              assume a closed world on a capture the claim never came from.
              It tests whether models actually read the file.
    no_pcap   the claim with no capture at all. Expected NOT_VERIFIABLE.
              The SUPPORTED rate here is the knowledge-leakage indicator.

  Nothing is kept on the strength of its name. A mutation whose condition
  still matches is discarded and logged -- and that discard is itself a
  finding, because it means the original condition was too loose to
  distinguish the two claims. A swap that turns out supported is discarded
  for the same reason: the scenarios were not as different as assumed.

  Mutations operate on the structured predicate, not on the filter string.
  Changing `predicate["port"]` is one checkable change; editing a filter by
  substring is not, and "exactly one detail" is the whole premise.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .ids import content_id
from .manifest import REPO_ROOT
from .pcap import PcapService, PcapServiceError
from .schemas import (
    Claim,
    ClaimKind,
    Condition,
    ExpectedBasis,
    MutationType,
    Pair,
    PairType,
    Provenance,
    Verdict,
)
from .storage.db import Database
from .storage.repository import Repository

#: Protocol swaps that keep a filter syntactically valid while changing what
#: it means. Chosen to be plainly different, not subtly: a mutation the
#: panel could arguably call SUPPORTED is not a control.
PROTOCOL_SWAPS: dict[str, str] = {
    "tcp": "icmp", "udp": "icmp", "dns": "arp", "http": "ftp", "ftp": "http",
    "smtp": "dns", "arp": "dns", "icmp": "dns", "modbus": "dns", "telnet": "dns",
}

#: Ports that are not what the claim says. Validated like everything else.
PORT_SWAPS: tuple[int, ...] = (9, 2222, 61234)

FLAG_SWAPS: dict[str, str] = {
    "syn": "fin", "fin": "syn", "reset": "syn", "ack": "urg", "push": "urg",
}


@dataclass
class BuildStats:
    source: int = 0
    mutation: int = 0
    swap: int = 0
    no_pcap: int = 0
    discarded: int = 0
    skipped_unvalidatable: int = 0

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


# -- mutation generation --------------------------------------------------

@dataclass(frozen=True)
class Mutation:
    mutation_type: MutationType
    display_filter: str
    predicate: dict[str, Any]
    text: str
    detail: str


def _mutate_port(condition: Condition, text: str) -> list[Mutation]:
    found = re.search(r"\b((?:tcp|udp)\.(?:port|dstport|srcport))\s*==\s*(\d+)", condition.display_filter)
    if not found:
        return []
    field, original = found.group(1), int(found.group(2))
    mutations = []
    for port in PORT_SWAPS:
        if port == original:
            continue
        mutations.append(
            Mutation(
                MutationType.PORT,
                condition.display_filter.replace(f"{field} == {original}", f"{field} == {port}"),
                {**condition.predicate, "port": port},
                text.replace(str(original), str(port)) if str(original) in text else f"{text} (on port {port})",
                f"port {original} -> {port}",
            )
        )
    return mutations


def _mutate_protocol(condition: Condition, text: str) -> list[Mutation]:
    for protocol, replacement in PROTOCOL_SWAPS.items():
        if re.search(rf"\b{protocol}\b", condition.display_filter):
            mutated = re.sub(rf"\b{protocol}\b", replacement, condition.display_filter, count=0)
            # A whole-filter protocol swap can leave fields that do not exist
            # on the new protocol (tcp.flags on icmp); fall back to the bare
            # protocol, which is still exactly one changed detail.
            if "." in condition.display_filter and replacement not in ("tcp", "udp"):
                mutated = replacement
            return [
                Mutation(
                    MutationType.PROTOCOL, mutated, {**condition.predicate, "protocol": replacement},
                    re.sub(rf"\b{protocol}\b", replacement, text, flags=re.I) if re.search(rf"\b{protocol}\b", text, re.I)
                    else f"{text} (over {replacement.upper()})",
                    f"protocol {protocol} -> {replacement}",
                )
            ]
    return []


def _mutate_flags(condition: Condition, text: str) -> list[Mutation]:
    found = re.search(r"tcp\.flags\.(\w+)\s*==\s*1", condition.display_filter)
    if not found:
        return []
    flag = found.group(1)
    replacement = FLAG_SWAPS.get(flag)
    if not replacement:
        return []
    return [
        Mutation(
            MutationType.PROTOCOL,
            condition.display_filter.replace(f"tcp.flags.{flag} == 1", f"tcp.flags.{replacement} == 1"),
            {**condition.predicate, "flags": [replacement]},
            re.sub(rf"\b{flag}\b", replacement, text, flags=re.I) if re.search(rf"\b{flag}\b", text, re.I)
            else f"{text} (with {replacement.upper()} rather than {flag.upper()})",
            f"flag {flag} -> {replacement}",
        )
    ]


def _mutate_direction(condition: Condition, text: str) -> list[Mutation]:
    if "ip.src" not in condition.display_filter and "ip.dst" not in condition.display_filter:
        return []
    swapped = condition.display_filter.replace("ip.src", "\x00").replace("ip.dst", "ip.src").replace("\x00", "ip.dst")
    return [
        Mutation(
            MutationType.DIRECTION, swapped, {**condition.predicate, "direction": "reversed"},
            f"{text} (with the direction reversed)", "source and destination exchanged",
        )
    ]


def mutations_for(condition: Condition, text: str) -> list[Mutation]:
    """Every one-change mutation this condition admits, best first."""
    return (
        _mutate_port(condition, text)
        + _mutate_flags(condition, text)
        + _mutate_protocol(condition, text)
        + _mutate_direction(condition, text)
    )


# -- the builder -----------------------------------------------------------

class PairBuilder:
    def __init__(
        self,
        *,
        db: Database,
        service: PcapService | None = None,
        repo_root: Path | None = None,
        max_capture_bytes: int | None = None,
        mutations_per_claim: int = 1,
        swaps_per_claim: int = 1,
    ) -> None:
        self.db = db
        self.repo = Repository(db)
        self.service = service
        self.root = repo_root or REPO_ROOT
        self.max_capture_bytes = max_capture_bytes
        self.mutations_per_claim = mutations_per_claim
        self.swaps_per_claim = swaps_per_claim
        self.stats = BuildStats()

    # -- inputs ------------------------------------------------------------

    def live_claims(self) -> list[dict[str, Any]]:
        """
        Claims a panel may be asked about: not superseded, not rejected.

        A superseded claim has been replaced by its own next version, and a
        rejected one was judged unusable by a reviewer. Neither becomes a
        pair, and neither is deleted.
        """
        rejected = {r["claim_id"] for r in self.db.query("SELECT claim_id FROM claim_reviews WHERE action = 'reject'")}
        superseded = {r["supersedes"] for r in self.db.query("SELECT supersedes FROM claims WHERE supersedes IS NOT NULL")}
        rows = []
        for row in self.db.query("SELECT * FROM claims WHERE mutation_of IS NULL ORDER BY claim_id"):
            if row["claim_id"] in rejected or row["claim_id"] in superseded:
                continue
            claim = dict(row)
            claim["condition"] = json.loads(claim["condition"]) if claim["condition"] else None
            rows.append(claim)
        return rows

    def captures(self) -> dict[str, list[dict[str, Any]]]:
        """source_id -> its captures."""
        by_source: dict[str, list[dict[str, Any]]] = {}
        for row in self.db.query("SELECT * FROM pcaps ORDER BY path"):
            by_source.setdefault(row["source_id"], []).append(dict(row))
        return by_source

    def _too_large(self, capture: dict[str, Any]) -> bool:
        return bool(self.max_capture_bytes and capture["size_bytes"] > self.max_capture_bytes)

    def _matches(self, capture: dict[str, Any], display_filter: str) -> int | None:
        """How many packets match, or None if the question could not be put."""
        if self.service is None:
            return None
        try:
            return self.service.query(self.root / capture["path"], display_filter, limit=1).match_count
        except PcapServiceError:
            return None

    # -- building ----------------------------------------------------------

    def build(self, *, limit: int | None = None) -> dict[str, Any]:
        claims = self.live_claims()
        if limit:
            claims = claims[:limit]
        by_source = self.captures()
        existing = {r["pair_id"] for r in self.db.query("SELECT pair_id FROM pairs")}

        for claim in claims:
            captures = by_source.get(claim["source_id"], [])
            self._build_for_claim(claim, captures, by_source, existing)
        return {"stats": self.stats.as_dict(), "claims_considered": len(claims)}

    def _add(self, pair: Pair, existing: set[str]) -> bool:
        if pair.pair_id in existing:
            return False
        self.repo.add_pair(pair)
        existing.add(pair.pair_id)
        return True

    def _build_for_claim(
        self,
        claim: dict[str, Any],
        captures: list[dict[str, Any]],
        by_source: dict[str, list[dict[str, Any]]],
        existing: set[str],
    ) -> None:
        level = int(claim["level"])
        condition = claim["condition"]

        # no_pcap: every claim gets one. No capture, nothing to validate.
        if self._add(
            Pair(
                pair_id=content_id("pair", ["no_pcap", claim["claim_id"]]),
                claim_id=claim["claim_id"], pair_type=PairType.NO_PCAP, pcap_id=None,
                expected=Verdict.NOT_VERIFIABLE, expected_basis=ExpectedBasis.CONSTRUCTION, level=level,
                notes="Leakage probe: the claim with no capture.",
            ),
            existing,
        ):
            self.stats.no_pcap += 1

        if level >= 4:
            # An abstention item: expected NOT_VERIFIABLE by construction, and
            # there is no condition to run, so nothing else applies.
            for capture in captures[:1]:
                if self._add(
                    Pair(
                        pair_id=content_id("pair", ["source", claim["claim_id"], capture["pcap_id"]]),
                        claim_id=claim["claim_id"], pair_type=PairType.SOURCE, pcap_id=capture["pcap_id"],
                        expected=Verdict.NOT_VERIFIABLE, expected_basis=ExpectedBasis.CONSTRUCTION, level=level,
                        notes=f"Level {level}: abstention test, reason {claim['reason_code']}.",
                    ),
                    existing,
                ):
                    self.stats.source += 1
            return

        if not condition or not captures:
            return

        display_filter = condition["display_filter"]
        for capture in captures:
            source_pair_id = content_id("pair", ["source", claim["claim_id"], capture["pcap_id"]])
            if source_pair_id in existing:
                # Already built and validated: go straight on to the
                # mutations and swaps, which check their own existence.
                self._build_mutations(claim, condition, capture, existing)
                self._build_swaps(claim, condition, capture, by_source, existing)
                break
            if self._too_large(capture):
                self.repo.add_discard(
                    kind="pair", ref_id=claim["claim_id"],
                    reason="capture too large to validate within the configured budget",
                    details={"pcap_id": capture["pcap_id"], "size_bytes": capture["size_bytes"]},
                )
                self.stats.skipped_unvalidatable += 1
                continue

            matches = self._matches(capture, display_filter)
            if matches is None:
                self.repo.add_discard(
                    kind="pair", ref_id=claim["claim_id"],
                    reason="condition could not be executed on this capture",
                    details={"pcap_id": capture["pcap_id"], "filter": display_filter},
                )
                self.stats.skipped_unvalidatable += 1
                continue
            if matches == 0:
                # The claim's own condition finds nothing on its own capture.
                # Extraction already flagged this; it must not quietly become
                # a source pair expected to be SUPPORTED.
                self.repo.add_discard(
                    kind="pair", ref_id=claim["claim_id"],
                    reason="condition finds nothing on the claim's own capture",
                    details={"pcap_id": capture["pcap_id"], "filter": display_filter},
                )
                self.stats.discarded += 1
                continue

            if self._add(
                Pair(
                    pair_id=source_pair_id,
                    claim_id=claim["claim_id"], pair_type=PairType.SOURCE, pcap_id=capture["pcap_id"],
                    expected=Verdict.SUPPORTED, expected_basis=ExpectedBasis.AUTHOR, level=level,
                    notes=f"Condition holds here: {matches} packets match.",
                ),
                existing,
            ):
                self.stats.source += 1

            self._build_mutations(claim, condition, capture, existing)
            self._build_swaps(claim, condition, capture, by_source, existing)
            break  # one capture per claim is enough for the pair set

    def _build_mutations(
        self, claim: dict[str, Any], condition: dict[str, Any], capture: dict[str, Any], existing: set[str]
    ) -> None:
        kept = 0
        base = Condition(
            kind=ClaimKind(claim["kind"]), display_filter=condition["display_filter"],
            predicate=condition.get("predicate") or {}, parameters=condition.get("parameters") or {},
        )
        for mutation in mutations_for(base, claim["atomic_text"]):
            if kept >= self.mutations_per_claim:
                return
            mutated_id = content_id("clm", [claim["claim_id"], "mut", mutation.detail])
            pair_id = content_id("pair", ["mutation", mutated_id, capture["pcap_id"]])
            if pair_id in existing:
                # Stored on an earlier build, and validated then. Counting it
                # is what stops a rebuild from adding a second mutation.
                kept += 1
                continue
            matches = self._matches(capture, mutation.display_filter)
            if matches is None:
                self.repo.add_discard(
                    kind="mutation", ref_id=claim["claim_id"],
                    reason="mutated condition could not be executed",
                    details={"filter": mutation.display_filter, "change": mutation.detail},
                )
                continue
            if matches > 0:
                # The mutation is still true, so it is not a REFUTED item --
                # and the original condition was too loose to tell the two
                # claims apart, which is worth recording.
                self.repo.add_discard(
                    kind="mutation", ref_id=claim["claim_id"],
                    reason="mutation still matches the capture, so it is not a refutation",
                    details={
                        "filter": mutation.display_filter, "change": mutation.detail,
                        "matches": matches, "pcap_id": capture["pcap_id"],
                    },
                )
                self.stats.discarded += 1
                continue

            mutated_claim = Claim(
                claim_id=mutated_id,
                source_id=claim["source_id"], source_location=claim["source_location"],
                source_step_text=claim["source_step_text"], atomic_text=mutation.text,
                level=int(claim["level"]), kind=ClaimKind(claim["kind"]),
                condition=Condition(
                    kind=ClaimKind(claim["kind"]), display_filter=mutation.display_filter,
                    predicate=mutation.predicate, parameters=base.parameters,
                ),
                mutation_of=claim["claim_id"], mutation_type=mutation.mutation_type,
                provenance=Provenance.AGENT,
            )
            if self.db.one("SELECT claim_id FROM claims WHERE claim_id = ?", (mutated_claim.claim_id,)) is None:
                self.repo.add_claim(mutated_claim)
            if self._add(
                Pair(
                    pair_id=pair_id,
                    claim_id=mutated_claim.claim_id, pair_type=PairType.MUTATION, pcap_id=capture["pcap_id"],
                    expected=Verdict.REFUTED, expected_basis=ExpectedBasis.CONSTRUCTION, level=int(claim["level"]),
                    notes=f"One change: {mutation.detail}. Validated: 0 packets match on this capture.",
                ),
                existing,
            ):
                self.stats.mutation += 1
                kept += 1

    def _build_swaps(
        self,
        claim: dict[str, Any],
        condition: dict[str, Any],
        own: dict[str, Any],
        by_source: dict[str, list[dict[str, Any]]],
        existing: set[str],
    ) -> None:
        kept = 0
        for source_id, captures in by_source.items():
            if source_id == claim["source_id"] or kept >= self.swaps_per_claim:
                continue
            for other in captures:
                pair_id = content_id("pair", ["swap", claim["claim_id"], other["pcap_id"]])
                if pair_id in existing:
                    kept += 1
                    break
                if self._too_large(other):
                    continue
                matches = self._matches(other, condition["display_filter"])
                if matches is None:
                    continue
                if matches > 0:
                    # Supported on the other capture too: the scenarios are
                    # not as different as the swap assumes, so this is not a
                    # control item.
                    self.repo.add_discard(
                        kind="swap", ref_id=claim["claim_id"],
                        reason="claim is also supported on the other capture, so the swap is not a control",
                        details={"pcap_id": other["pcap_id"], "matches": matches},
                    )
                    self.stats.discarded += 1
                    continue
                if self._add(
                    Pair(
                        pair_id=pair_id,
                        claim_id=claim["claim_id"], pair_type=PairType.SWAP, pcap_id=other["pcap_id"],
                        expected=None, expected_basis=ExpectedBasis.CONSTRUCTION, level=int(claim["level"]),
                        notes="Scored as not-SUPPORTED. Validated: 0 packets match on this capture.",
                    ),
                    existing,
                ):
                    self.stats.swap += 1
                    kept += 1
                    break


def discard_log(db: Database, kind: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT * FROM discards"
    params: tuple[Any, ...] = ()
    if kind:
        sql += " WHERE kind = ?"
        params = (kind,)
    return [dict(row) for row in db.query(sql + " ORDER BY created_at DESC, rowid DESC", params)]
