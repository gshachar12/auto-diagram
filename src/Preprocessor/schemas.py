"""
PAnGEA — Preprocessing stage schemas.

Shared dataclasses for the Reducer's output, matching the functional spec:
  - R1 Aggregate Traceability
  - R3 Referential Integrity
  - R4 Temporal Order Preservation
  - R5 Budget Compliance (best-effort + explicit flag, no silent truncation)
  - R6 Protocol/Attack-Type Agnosticism (enforced by fingerprint logic, not schema)

R2 (Description-Blindness) is an interface requirement, not a schema concern —
it's enforced by never wiring Attack Description into Reducer's function
signature at all (see reducer.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class BudgetStatus(str, Enum):
    WITHIN_BUDGET = "within_budget"
    EXCEEDED = "exceeded"


@dataclass
class AggregateRef:
    """Statistics for packets folded into a compressed pattern (R3)."""
    fingerprint_key: str
    count: int
    total_bytes: int
    unique_sources: list[str]
    unique_destinations: list[str]


@dataclass
class ReducedItem:
    """A single retained item in the reduced representation.

    Always carries a reference back to the original PCAP (R1). May be a raw
    sample (packet_id populated) and/or carry aggregate stats (aggregate
    populated) if it is the representative sample of a compressed pattern.
    """
    packet_id: int
    timestamp: str            # ISO-8601, preserves original capture ordering (R4)
    protocol: str
    src: str
    dst: str
    length: int
    info: str
    fingerprint_key: str
    aggregate: Optional[AggregateRef] = None


@dataclass
class CompressionStats:
    raw_packet_count_in: int
    packet_count_out: int
    estimated_tokens_out: int
    dropped_parse_failures: int
    compression_ratio: float


@dataclass
class ReducerOutput:
    """Full output contract of the Reducer."""
    reduced_representation: list[ReducedItem]
    fingerprint_index: dict[str, AggregateRef]   # reusable lookup structure for the Grounder
    compression_stats: CompressionStats
    budget_status: BudgetStatus
    budget_status_detail: Optional[str] = None    # e.g. last processed packet id/timestamp if exceeded
    filter_string_used: Optional[str] = None
