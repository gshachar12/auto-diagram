"""
The extraction agent: source steps -> atomic claims.

  Responsibility: take the steps as the authors wrote them and produce, for
  each one, claims that are atomic (one checkable statement each),
  classified by level, and -- for levels 1 to 3 -- carrying an executable
  condition that can be run against the capture.

  What this does NOT do is decide whether a claim is true. It writes the
  condition; the capture answers. For every level 1-3 claim the condition
  is immediately run against the source's own captures, and the result is
  stored. A claim whose condition finds nothing on the very capture it was
  extracted from is not quietly dropped and not quietly kept: it is
  flagged, because exactly one of three things is wrong -- the condition is
  too narrow, the step was misread, or the capture is not the one the step
  describes -- and only a human can say which.

  Provenance is per claim: everything here is `agent`. A reviewer's edit
  becomes a new version marked `human`, and the agent's original stays
  readable (claims are append-only, corrections carry `supersedes`).

  Every model call is written to `llm_calls` before its output is used. An
  output nobody can read later is an output nobody can audit.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .ids import content_id
from .manifest import REPO_ROOT
from .pcap import PcapService, PcapServiceError
from .schemas import Claim, ClaimKind, Condition, Provenance, ReasonCode
from .storage.db import Database
from .storage.repository import Repository, utc_now

EXTRACTION_SYSTEM_PROMPT = """\
You split a single step of a described network attack into atomic claims.

One claim = one checkable condition. Split conjunctions, resolve pronouns,
make quantifiers explicit. For each claim record who sends it, which action,
to whom, over which protocol/port/field, how many (a threshold), and any time
relation.

Classify every claim:
  1 packet-level     a packet with particular properties exists
  2 protocol-level   a particular protocol message was sent
  3 sequence-level   one event happened before another
  4 semantic-level   intent -- NOT_VERIFIABLE, reason code INTENT
  5 outcome-level    success or failure -- NOT_VERIFIABLE, reason code OUTCOME

For levels 1-3 give an executable condition: a tshark display filter plus the
structured fields it was built from. For levels 4-5 give no condition and a
reason code from: NOT_EXPRESSIBLE, ENCRYPTED, OUT_OF_WINDOW, INTENT, OUTCOME,
VAGUE_QUANTIFIER, INCOMPLETE_CAPTURE.

Return JSON: {"claims": [{"atomic_text", "level", "kind", "reason_code",
"display_filter", "predicate", "parameters"}]}.
"""


class ExtractionClient(Protocol):
    """Same shape as the repo's shared LLMClient: prompts in, JSON out."""

    model_id: str
    model_version: str

    def complete_json(self, system_prompt: str, user_prompt: str) -> dict:
        ...


@dataclass
class ConditionCheck:
    claim_id: str
    pcap_id: str
    display_filter: str
    match_count: int | None
    holds: bool | None
    error: str | None = None


# -- the heuristic stand-in ----------------------------------------------

#: (pattern, kind, display filter, predicate) for the mock extractor. These
#: are deliberately coarse: the mock exists so the pipeline and the review
#: queue can be exercised without an API key, not to do the agent's job.
_RULES: tuple[tuple[str, ClaimKind, str, dict[str, Any]], ...] = (
    (r"\b(port )?scan|nmap|portscan", ClaimKind.QUANTITATIVE,
     "tcp.flags.syn == 1 && tcp.flags.ack == 0", {"protocol": "tcp", "flags": ["syn"], "distinct": "tcp.dstport"}),
    (r"\bdns\b|domain name|resolver|exfiltrat", ClaimKind.EXISTENTIAL,
     "dns", {"protocol": "dns"}),
    (r"\btelnet\b", ClaimKind.PROTOCOL, "tcp.port == 23", {"protocol": "tcp", "port": 23}),
    (r"\bssh\b", ClaimKind.PROTOCOL, "tcp.port == 22", {"protocol": "tcp", "port": 22}),
    (r"\bftp\b", ClaimKind.PROTOCOL, "tcp.port == 21", {"protocol": "tcp", "port": 21}),
    (r"\bhttp\b|web|wordpress|wpdiscuz|webshell", ClaimKind.PROTOCOL,
     "http.request", {"protocol": "http", "field": "http.request"}),
    (r"\bmail|smtp|phish|email", ClaimKind.PROTOCOL, "smtp", {"protocol": "smtp"}),
    (r"\barp\b|spoof", ClaimKind.PROTOCOL, "arp.opcode == 2", {"protocol": "arp", "opcode": 2}),
    (r"brute[- ]?forc|credential|password", ClaimKind.QUANTITATIVE,
     "tcp.flags.syn == 1 && tcp.flags.ack == 0", {"protocol": "tcp", "repeated": True}),
    (r"command and control|c&c|c2\b|beacon", ClaimKind.EXISTENTIAL,
     "tcp || udp", {"repeated": True}),
    (r"modbus|s7comm|iec|scada|plc", ClaimKind.PROTOCOL, "modbus", {"protocol": "modbus"}),
)

#: Wording that marks a step as an intention or an outcome rather than an
#: observable event. These become deliberate abstention items.
_INTENT = re.compile(r"\bin order to\b|\battempt|\bto gain\b|\bintends?\b|\bgoal\b|\breconnaiss", re.I)
_OUTCOME = re.compile(r"\bsucceed|\bsuccessful|\bcompromis|\bgain(ed)? access|\bescalat|\bpersist|\binfect", re.I)


class HeuristicExtractionClient:
    """
    A rule-based stand-in for the extraction model.

    Not an LLM and not pretending to be one: it matches keywords and emits
    conditions from a small table. Its purpose is that the extraction
    pipeline, the condition checks and the review queue can all be built,
    tested and demonstrated before any API key exists -- and its output goes
    through exactly the same review as a model's would.
    """

    model_id = "heuristic-extractor"
    model_version = "heuristic-extractor-0.1"

    def complete_json(self, system_prompt: str, user_prompt: str) -> dict:
        step = ""
        for line in user_prompt.splitlines():
            if line.startswith("STEP:"):
                step = line[5:].strip()
        claims: list[dict[str, Any]] = []

        for pattern, kind, display_filter, predicate in _RULES:
            if re.search(pattern, step, re.I):
                claims.append(
                    {
                        "atomic_text": f"The capture contains traffic matching this step: {step}",
                        "level": 1 if kind is ClaimKind.EXISTENTIAL else (2 if kind is ClaimKind.PROTOCOL else 1),
                        "kind": str(kind),
                        "display_filter": display_filter,
                        "predicate": predicate,
                        "parameters": {},
                    }
                )
                break

        if _OUTCOME.search(step):
            claims.append(
                {"atomic_text": f"The step succeeded: {step}", "level": 5,
                 "kind": str(ClaimKind.SEMANTIC), "reason_code": str(ReasonCode.OUTCOME)}
            )
        elif _INTENT.search(step):
            claims.append(
                {"atomic_text": f"The actor intended: {step}", "level": 4,
                 "kind": str(ClaimKind.SEMANTIC), "reason_code": str(ReasonCode.INTENT)}
            )

        if not claims:
            # No rule matched: say so rather than invent a condition. The
            # step still reaches the review queue, as an item a human must
            # decide about.
            claims.append(
                {"atomic_text": step, "level": 4, "kind": str(ClaimKind.SEMANTIC),
                 "reason_code": str(ReasonCode.NOT_EXPRESSIBLE)}
            )
        return {"claims": claims}


# -- the agent ------------------------------------------------------------

class ExtractionAgent:
    def __init__(
        self,
        *,
        db: Database,
        client: ExtractionClient | None = None,
        service: PcapService | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self.db = db
        self.repo = Repository(db)
        self.client = client or HeuristicExtractionClient()
        self.service = service
        self.root = repo_root or REPO_ROOT

    def extract_source(self, source_id: str, *, limit: int | None = None) -> dict[str, Any]:
        """Extract claims for every not-yet-extracted step of one source."""
        done = {
            row["source_location"]
            for row in self.db.query("SELECT DISTINCT source_location FROM claims WHERE source_id = ?", (source_id,))
        }
        steps = [
            dict(row)
            for row in self.db.query(
                "SELECT * FROM source_steps WHERE source_id = ? ORDER BY origin_file, row_number", (source_id,)
            )
            if f"{row['origin_file']}#{row['row_number']}" not in done
        ]
        if limit:
            steps = steps[:limit]

        captures = [dict(row) for row in self.db.query("SELECT * FROM pcaps WHERE source_id = ?", (source_id,))]
        made: list[str] = []
        checks: list[ConditionCheck] = []

        for step in steps:
            user_prompt = self._render_prompt(step, captures)
            try:
                payload = self.client.complete_json(EXTRACTION_SYSTEM_PROMPT, user_prompt)
                error = None
            except Exception as exc:  # a failed extraction is data too
                payload, error = {"claims": []}, str(exc)
            self.repo.add_llm_call(
                purpose="extraction",
                ref_id=step["step_id"],
                model_id=self.client.model_id,
                model_version=self.client.model_version,
                prompt=user_prompt,
                raw_response=json.dumps(payload, ensure_ascii=False),
                parsed=payload,
                error=error,
            )
            for index, item in enumerate(payload.get("claims", [])):
                claim = self._to_claim(source_id, step, index, item)
                if claim is None:
                    continue
                self.repo.add_claim(claim)
                made.append(claim.claim_id)
                checks.extend(self.check_claim(claim, captures))

        return {
            "source_id": source_id,
            "steps_processed": len(steps),
            "claims": len(made),
            "checks": [c.__dict__ for c in checks],
            "claims_without_support": sum(1 for c in checks if c.holds is False),
        }

    def _render_prompt(self, step: dict[str, Any], captures: list[dict[str, Any]]) -> str:
        """
        What the extraction model is shown.

        The capture list is included so conditions can name fields that
        actually exist in these files. The expected verdict does not appear
        because there is none yet -- extraction happens before any pair.
        """
        lines = [f"STEP: {step['text']}", f"SOURCE FILE: {step['origin_file']} row {step['row_number']}"]
        if step.get("fields"):
            lines.append(f"ORIGINAL ROW: {step['fields']}")
        for capture in captures:
            metadata = json.loads(capture["capture_metadata"])
            lines.append(
                f"CAPTURE: {capture['path']} ({capture['packet_count']} packets; "
                f"both directions: {metadata.get('both_directions')})"
            )
        return "\n".join(lines)

    def _to_claim(self, source_id: str, step: dict[str, Any], index: int, item: dict[str, Any]) -> Claim | None:
        level = int(item.get("level", 4))
        condition = None
        if item.get("display_filter") and level <= 3:
            condition = Condition(
                kind=ClaimKind(item.get("kind", "existential")),
                display_filter=item["display_filter"],
                predicate=item.get("predicate") or {},
                parameters=item.get("parameters") or {},
            )
        try:
            return Claim(
                claim_id=content_id("clm", [source_id, step["step_id"], index, item.get("atomic_text", "")]),
                source_id=source_id,
                source_location=f"{step['origin_file']}#{step['row_number']}",
                source_step_text=step["text"],
                atomic_text=item.get("atomic_text", "").strip(),
                level=level,
                kind=ClaimKind(item.get("kind", "semantic")),
                reason_code=ReasonCode(item["reason_code"]) if item.get("reason_code") else None,
                condition=condition,
                provenance=Provenance.AGENT,
            )
        except (ValueError, KeyError):
            # A malformed claim is dropped from the dataset but not from the
            # record: the raw response is already in llm_calls.
            self.repo.add_discard(
                kind="claim", ref_id=step["step_id"], reason="extraction produced a claim that failed validation",
                details={"item": item},
            )
            return None

    # -- condition checks -------------------------------------------------

    def check_claim(self, claim: Claim, captures: list[dict[str, Any]]) -> list[ConditionCheck]:
        """
        Run a claim's condition on its source's captures.

        A level 1-3 condition is supposed to hold on the capture the step
        came from. When it does not, the row says so and the claim is
        flagged for review -- the capture may simply not be the one the
        figure describes, and that is a finding about the dataset.
        """
        if claim.condition is None or self.service is None:
            return []
        results: list[ConditionCheck] = []
        for capture in captures:
            try:
                outcome = self.service.query(self.root / capture["path"], claim.condition.display_filter, limit=5)
                check = ConditionCheck(
                    claim.claim_id, capture["pcap_id"], claim.condition.display_filter,
                    outcome.match_count, outcome.match_count > 0,
                )
            except PcapServiceError as exc:
                check = ConditionCheck(
                    claim.claim_id, capture["pcap_id"], claim.condition.display_filter, None, None, str(exc)
                )
            self._store_check(check)
            results.append(check)
        return results

    def _store_check(self, check: ConditionCheck) -> None:
        self.db.conn.execute(
            "INSERT OR REPLACE INTO claim_condition_checks "
            "(claim_id, pcap_id, display_filter, match_count, holds, error, checked_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (check.claim_id, check.pcap_id, check.display_filter, check.match_count,
             None if check.holds is None else int(check.holds), check.error, utc_now()),
        )
        self.db.conn.commit()


def extract_all(
    *, db: Database, service: PcapService | None = None, client: ExtractionClient | None = None,
    source_ids: list[str] | None = None, limit_per_source: int | None = None,
) -> dict[str, Any]:
    agent = ExtractionAgent(db=db, client=client, service=service)
    targets = source_ids or [
        row["source_id"] for row in db.query("SELECT source_id FROM sources ORDER BY title")
    ]
    return {"sources": [agent.extract_source(source_id, limit=limit_per_source) for source_id in targets]}
