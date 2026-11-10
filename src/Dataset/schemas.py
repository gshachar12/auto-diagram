"""
Record types for the dataset.

  Responsibility: the vocabulary of the experiment -- verdicts, claim levels,
  reason codes, pair types -- and the shape of every row that is stored. The
  SQLite schema (storage/db.py) mirrors these; these are the validating
  boundary, SQLite is the durable one.

  The closed lists here are closed on purpose. A reason code that is not in
  `ReasonCode` is a format error in a model's answer, which is data worth
  recording, not a new category to accept silently.

  Conditions are structured (`Condition.predicate`) and compile to a tshark
  display filter rather than being free text. A mutation has to change
  exactly one detail -- a port, a protocol, a direction, a magnitude, an
  order -- and that is only mechanically checkable if the detail is a field
  rather than a substring of a filter expression.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Verdict(StrEnum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


class ReasonCode(StrEnum):
    """Closed list. Required whenever a verdict is NOT_VERIFIABLE."""

    NOT_EXPRESSIBLE = "NOT_EXPRESSIBLE"
    ENCRYPTED = "ENCRYPTED"
    OUT_OF_WINDOW = "OUT_OF_WINDOW"
    INTENT = "INTENT"
    OUTCOME = "OUTCOME"
    VAGUE_QUANTIFIER = "VAGUE_QUANTIFIER"
    INCOMPLETE_CAPTURE = "INCOMPLETE_CAPTURE"


class ClaimKind(StrEnum):
    """How a claim is verified -- fixes the evidence unit and the rules."""

    EXISTENTIAL = "existential"
    PROTOCOL = "protocol"
    ABSENCE = "absence"
    QUANTITATIVE = "quantitative"
    SEQUENCE = "sequence"
    SEMANTIC = "semantic"


class PairType(StrEnum):
    SOURCE = "source"
    MUTATION = "mutation"
    SWAP = "swap"
    NO_PCAP = "no_pcap"


class ExpectedBasis(StrEnum):
    """Where an expected verdict comes from. Never 'ground truth'."""

    CONSTRUCTION = "construction"
    AUTHOR = "author"
    NONE = "none"


class MutationType(StrEnum):
    PORT = "port"
    PROTOCOL = "protocol"
    DIRECTION = "direction"
    MAGNITUDE = "magnitude"
    ORDER = "order"


class Provenance(StrEnum):
    AGENT = "agent"
    HUMAN = "human"


class UncertaintySource(StrEnum):
    AMBIGUOUS_CONDITION = "ambiguous_condition"
    PARTIAL_CAPTURE = "partial_capture"
    UNCLEAR_THRESHOLD = "unclear_threshold"
    ENCRYPTED_CONTENT = "encrypted_content"
    OTHER = "other"


class PacketTag(StrEnum):
    SUPPORTS = "SUPPORTS"
    REFUTES = "REFUTES"
    SCOPE = "SCOPE"
    NONE = "NONE"


class ReviewAction(StrEnum):
    ACCEPT = "accept"
    EDIT = "edit"
    SPLIT = "split"
    MERGE = "merge"
    REJECT = "reject"


ClaimLevel = Literal[1, 2, 3, 4, 5]

#: Levels 4 and 5 are abstention tests: the system should refuse, not guess.
ABSTAIN_LEVELS: frozenset[int] = frozenset({4, 5})


class Record(BaseModel):
    """Base for stored records: unknown fields are an error, not ignored."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class CaptureMetadata(Record):
    """
    The closed-world statement for one capture.

    An absence claim ("no response was sent") can only be REFUTED or
    SUPPORTED relative to what the capture could have seen, so this travels
    with every PCAP and is quoted to the models verbatim.
    """

    vantage_point: str
    # None means "not established yet". A capture whose direction coverage
    # is unknown must not be recorded as one-directional, and must not be
    # recorded as bidirectional either: absence claims are judged against
    # this field, so a guess here becomes a wrong verdict later.
    both_directions: bool | None = None
    known_gaps: list[str] = Field(default_factory=list)
    notes: str = ""


class Source(Record):
    """A paper, figure or lab scenario that claims are extracted from."""

    source_id: str
    title: str
    authors: list[str] = Field(default_factory=list)
    venue: str = ""
    year: int | None = None
    urls: list[str] = Field(default_factory=list)
    license: str = "UNVERIFIED"
    origin: str = ""
    notes: str = ""


class Pcap(Record):
    """
    A capture file. Never redistributed -- we store its hash and origin.

    `packet_count` is None until the PCAP service has actually opened the
    file; an unopened capture stays visibly unverified rather than being
    assumed good.
    """

    pcap_id: str
    source_id: str | None
    path: str
    sha256: str
    size_bytes: int
    packet_count: int | None = None
    capture_metadata: CaptureMetadata
    license: str = "UNVERIFIED"
    origin: str = ""


class Condition(Record):
    """
    An executable condition: what is actually run against a capture.

    `display_filter` is the executable form. `predicate` is the structured
    form it was compiled from, and is what mutations operate on -- changing
    `predicate['port']` is a single, checkable change, whereas editing the
    filter string is not.
    """

    kind: ClaimKind
    display_filter: str
    predicate: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)


class Claim(Record):
    """
    One atomic claim: one checkable condition.

    Versioned, never edited in place. A review that changes a claim stores a
    new row whose `supersedes` points at the previous `claim_id`, so the
    decomposition the models actually saw stays recoverable.
    """

    claim_id: str
    source_id: str
    source_location: str
    source_step_text: str
    atomic_text: str
    level: ClaimLevel
    kind: ClaimKind
    reason_code: ReasonCode | None = None
    condition: Condition | None = None
    mutation_of: str | None = None
    mutation_type: MutationType | None = None
    provenance: Provenance = Provenance.AGENT
    version: int = 1
    supersedes: str | None = None

    @model_validator(mode="after")
    def _abstain_levels_need_a_reason(self) -> "Claim":
        # A missing field has to be validated on the model, not the field:
        # a field validator never fires for a value that was never supplied,
        # which is exactly the case this has to catch.
        if self.level in ABSTAIN_LEVELS and self.reason_code is None:
            raise ValueError(f"level {self.level} claims are NOT_VERIFIABLE and need a reason code")
        return self


class Pair(Record):
    """A (claim, PCAP) item put to the panel. `pcap_id` is None for no_pcap."""

    pair_id: str
    claim_id: str
    pair_type: PairType
    pcap_id: str | None
    expected: Verdict | None
    expected_basis: ExpectedBasis
    level: ClaimLevel
    notes: str = ""

    @model_validator(mode="after")
    def _no_pcap_pairs_carry_no_pcap(self) -> "Pair":
        if self.pair_type is PairType.NO_PCAP and self.pcap_id is not None:
            raise ValueError("a no_pcap pair must not reference a capture")
        return self


class ModelSpec(Record):
    """
    One panel member. `version` is an exact version string, never an alias.

    `family` is the unit of analysis: two sizes of the same family are not
    independent votes and are collapsed to one in the panel statistics.
    """

    model_id: str
    family: str
    version: str
    adapter: str
    supports_tools: bool
    temperature: float
    max_output_tokens: int = 2048


class SolverAnswer(Record):
    """What a solver model is asked to return (spec 8.3)."""

    verdict: Verdict
    reason_code: ReasonCode | None = None
    condition: str = ""
    cited_packets: list[int] = Field(default_factory=list)
    criteria_checks: dict[str, bool] = Field(default_factory=dict)
    survey: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _not_verifiable_needs_a_reason(self) -> "SolverAnswer":
        # An abstention with no reason code is an incomplete answer, and the
        # reason codes are the closed list the abstention analysis counts.
        if self.verdict is Verdict.NOT_VERIFIABLE and self.reason_code is None:
            raise ValueError("NOT_VERIFIABLE requires a reason code")
        return self


class CallRecord(Record):
    """
    One model call. Append-only; the unit of `results.jsonl`.

    A failed call is still a record: `format_error`, a refusal or a tool
    error are findings about the model, so they are stored exactly like a
    successful answer and counted in the operational metrics.
    """

    call_id: str
    run_id: str
    pair_id: str
    model_id: str
    model_family: str
    model_version: str
    prompt_id: str
    prompt_hash: str
    prompt_rendered: str = ""
    repeat: int = 0
    temperature: float = 0.0
    raw_response: str = ""
    parsed: dict[str, Any] | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    format_error: bool = False
    error: str | None = None
    latency_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    timestamp: str = ""
