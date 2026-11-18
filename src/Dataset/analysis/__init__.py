"""
The analysis service (B5).

Computed from stored responses only: this package calls no model and asks
no question that is not answered by a row already in the database or by
re-running a condition against a capture through the PCAP service.
"""
from __future__ import annotations

from .evidence import CallFact, EvidenceChecker  # noqa: F401
from .metrics import CallView, ItemView, MetricRow, MetricSet, expected_outcome  # noqa: F401
from .service import (  # noqa: F401
    ANALYSIS_CODE_VERSION,
    AnalysisError,
    AnalysisParams,
    AnalysisResult,
    analyse,
    diff,
    latest_analysis,
    latest_run_id,
    list_analyses,
    load_call_facts,
    load_metrics,
    what_if,
)
