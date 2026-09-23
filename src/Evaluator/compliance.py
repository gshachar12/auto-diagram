"""
PAnGEA Evaluator -- Grounder Compliance Testing (no ground truth needed).

These are binary invariant checks that should hold on EVERY run,
regardless of whether a labeled gold sample exists for it -- see the
"Grounder Compliance Testing" section added to evaluator_testbench.docx.
Each check was added because a real run violated it at least once.
"""
from __future__ import annotations

from dataclasses import dataclass

from .schemas import SystemSample


@dataclass
class ComplianceResult:
    check_name: str
    passed: bool
    violations: list[str]


def check_grounded_requires_evidence(sample: SystemSample) -> ComplianceResult:
    """A status of 'grounded' with zero linked evidence is an internal
    contradiction -- found in a real run where the LLM self-reported
    'grounded' status on a plausible-sounding narrative with no evidence
    actually cited."""
    violations = []
    for claim in sample.claims:
        if claim.grounding_status == "grounded" and not claim.linked_fingerprint_keys:
            violations.append(f"step_id={claim.step_id}: status=grounded with no linked evidence")
    return ComplianceResult("grounded_requires_evidence", len(violations) == 0, violations)


def check_resolved_ip_is_observed(sample: SystemSample) -> ComplianceResult:
    """Every resolved actor endpoint must be an IP actually observed in
    this sample's traffic -- catches a hallucinated resolution that was
    never in the candidate set (the same principle as evidence_matcher.py's
    own hallucination guard, re-checked independently here)."""
    violations = []
    for actor in sample.actors:
        for ip in actor.resolved_endpoints:
            if sample.observed_ips and ip not in sample.observed_ips:
                violations.append(f"actor_id={actor.actor_id}: resolved to {ip}, never observed in traffic")
    return ComplianceResult("resolved_ip_is_observed", len(violations) == 0, violations)


def check_no_unexplained_duplicate_resolution(sample: SystemSample) -> ComplianceResult:
    """Flags (does not fail) when multiple actors resolve to the same IP --
    sometimes genuinely correct (a shared host), so this is reported for
    review, not auto-failed. Included in Compliance Testing as a
    visibility net, per the earlier design discussion."""
    ip_to_actors: dict[str, list[str]] = {}
    for actor in sample.actors:
        for ip in actor.resolved_endpoints:
            ip_to_actors.setdefault(ip, []).append(actor.actor_id)
    violations = [
        f"IP {ip} shared by actors: {actor_ids}"
        for ip, actor_ids in ip_to_actors.items() if len(actor_ids) > 1
    ]
    # Note: `passed=True` even with violations present -- this check is
    # advisory (review-worthy), not a hard failure, unlike the other two.
    return ComplianceResult("no_unexplained_duplicate_resolution", True, violations)


def run_all_compliance_checks(sample: SystemSample) -> list[ComplianceResult]:
    return [
        check_grounded_requires_evidence(sample),
        check_resolved_ip_is_observed(sample),
        check_no_unexplained_duplicate_resolution(sample),
    ]