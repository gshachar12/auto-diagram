"""
Grounder (top-level stage).

Per PANGEA_SPEC ("LLM Grounder"):
  Purpose: the stage where the traffic description and the packet-level evidence
  (Reduced PCAP) are brought together for the first time. Decomposes a free-text
  description into atomic, checkable Steps, and determines - for each Step -
  whether it is supported by the traffic evidence, unsupported, or uncertain
  enough to require deeper investigation.

  Inputs:
    - Network Traffic Description (free text)
    - Reduced PCAP (from Preprocessor) -- as EvidenceItem list
    - Fingerprint_index (from Preprocessor, reused rather than rebuilt) --
      as EvidenceAggregate dict

  Outputs:
    - Matching JSON: actors[] (role -> IP mapping) and Steps[] (Step -> grounding)

Internally this is just wiring: Step Extractor never sees the PCAP; Evidence
Matcher never re-derives Steps. That separation is load-bearing (spec R2-style
separation of forces / avoids the Step Extractor being biased by the evidence).
"""
from __future__ import annotations

import json


from .steps_extractor import StepExtractor
from .evidence_matcher import EvidenceMatcher
from .llm_client import LLMClient
from .models import MatchingResult, EvidenceItem, EvidenceAggregate, ExpectedIndicators, Step


class Grounder:
    def __init__(self, llm_client: LLMClient):
        self.step_extractor = StepExtractor(llm_client)
        self.evidence_matcher = EvidenceMatcher(llm_client)

    def run(
        self,
        traffic_description: str,
        reduced_pcap: list[EvidenceItem],
        fingerprint_index: dict[str, EvidenceAggregate],
    ) -> MatchingResult:
        """
        Args:
            traffic_description: free text. Seen ONLY by step_extractor --
                never forwarded into evidence_matcher.match() as text (R2
                -style separation).
            reduced_pcap: EvidenceItem list (the generic evidence shape
                EvidenceMatcher depends on).
            fingerprint_index: EvidenceAggregate dict, same shape note.
        """
        # 1. Step Extractor: text -> actors + steps. No PCAP access (by design).
        actors, steps = self.step_extractor.extract(traffic_description)

        # 2. Evidence Matcher: resolve actors to IPs AND ground each step,
        #    in a single call.
        resolved_actors, grounded_steps = self.evidence_matcher.match(
            actors, steps, reduced_pcap, fingerprint_index,
        )

        return MatchingResult(actors=resolved_actors, Steps=grounded_steps)


# --------------------------------------------------------------------------
# Organized output helpers -- mirrors evidence_matcher.py's
# _serialize_result / _print_summary pattern, one level up (whole
# MatchingResult, not just resolved_actors/grounded_steps separately).
# --------------------------------------------------------------------------

def _print_summary(result: MatchingResult) -> None:
    print("=" * 70)
    print("GROUNDER RESULT")
    print("=" * 70)

    print("\nACTORS")
    print("-" * 70)
    for a in result.actors:
        ips = ", ".join(a.resolved_endpoints) if a.resolved_endpoints else "UNRESOLVED"
        print(f"  {a.actor_id:12s} ({a.role:10s}) -> {ips}")
        print(f"    basis: {a.resolution_basis}")

    print("\nStepS")
    print("-" * 70)
    status_symbol = {
        "grounded": "\u2713",
        "unsupported": "\u2717",
        "uncertain_needs_drilldown": "?",
    }
    for gs in result.Steps:
        g = gs.grounding
        symbol = status_symbol.get(g.status.value, " ")
        print(f"  [{symbol}] {gs.step.step_id}: {g.status.value}")
        print(f"      text: {gs.step.text}")
        if g.linked_packets:
            print(f"      linked_packets: {len(g.linked_packets)}")
        if g.linked_aggregate_refs:
            keys = ", ".join(r.fingerprint_key for r in g.linked_aggregate_refs)
            print(f"      linked_aggregates: {keys}")
        print(f"      notes: {g.notes}")
        print()

    total = len(result.Steps)
    grounded = sum(1 for gs in result.Steps if gs.grounding.status.value == "grounded")
    unsupported = sum(1 for gs in result.Steps if gs.grounding.status.value == "unsupported")
    uncertain = sum(1 for gs in result.Steps if gs.grounding.status.value == "uncertain_needs_drilldown")
    resolved_actors = sum(1 for a in result.actors if a.resolved_endpoints)

    print("=" * 70)
    print(f"SUMMARY: {resolved_actors}/{len(result.actors)} actors resolved | "
          f"{total} Steps total: grounded={grounded} unsupported={unsupported} "
          f"uncertain={uncertain}")
    print("=" * 70)


def main():
    """
    Example usage of Grounder, mirroring evidence_matcher.py's main():
    reads inputs from JSON/text files, writes an organized JSON output
    file, and prints a readable console summary.

    Expects, in the current working directory:
      - traffic_description.txt   (plain text)
      - reduced_representation.json   {"reduced_representation": [...]}
      - fingerprint_index.json        {"fingerprint_index": {...}}
    """
    import os

    with open("traffic_description.txt", "r", encoding="utf-8") as f:
        traffic_description = f.read().strip()

    with open("reduced_representation.json", "r") as f:
        data = json.load(f)
        reduced_pcap = [EvidenceItem(**item) for item in data["reduced_representation"]]

    with open("fingerprint_index.json", "r") as f:
        data = json.load(f)
        fingerprint_index = {k: EvidenceAggregate(**v) for k, v in data["fingerprint_index"].items()}

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("error: set OPENAI_API_KEY -- Step Extractor has no algorithmic fallback.")
        return

    try:
        from .llm_client import OpenAIClient
    except ImportError:
        from llm_client import OpenAIClient

    llm_client = OpenAIClient(api_key=api_key, model="gpt-4o")
    grounder = Grounder(llm_client=llm_client)

    result = grounder.run(traffic_description, reduced_pcap, fingerprint_index)

    _print_summary(result)

    output_path = "matching_result.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    print(f"\nWrote full results to: {output_path}")


if __name__ == "__main__":
    main()