"""
Rendering a prompt variant for one item.

  Responsibility: produce the exact text a solver is sent, and a hash of
  the variant that produced it.

  The criteria are loaded once from criteria.md and are byte-identical in
  every variant that includes them at all. A variant changes how they are
  presented -- numbered, wrapped in XML, preceded by a role -- never what
  they say. That is the only way "the prompt effect" means anything: if two
  variants differed in content, a difference in answers would be about the
  content, not the presentation.

  What goes into a prompt: the claim, the capture's own description of
  itself (including its closed-world statement, which the criteria say to
  judge absence claims against), the tool, and the output schema. What
  never goes in is in leaks.py, and is checked there rather than trusted
  here.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..ids import content_hash, content_id

PROMPT_DIR = Path(__file__).resolve().parent.parent / "config" / "prompts"

TOOL_DESCRIPTION = """\
You have one tool, pcap_query. Call it with a tshark display filter and a
limit; it returns how many packets in this capture match, and the first few
of them (number, time, source, destination, protocol, info). Call it as often
as you need. It reads the capture read-only and cannot change anything."""

OUTPUT_INSTRUCTIONS = """\
Answer with one JSON object and nothing else:

{{
  "verdict": {labels},
  "reason_code": "<required only when NOT_VERIFIABLE; one of NOT_EXPRESSIBLE,
                  ENCRYPTED, OUT_OF_WINDOW, INTENT, OUTCOME, VAGUE_QUANTIFIER,
                  INCOMPLETE_CAPTURE>",
  "condition": "<the executable condition you used>",
  "cited_packets": [<packet numbers from the tool's output>],
  "criteria_checks": {{"executable": true, "sufficient": true, "minimal": true,
                      "in_window": true, "conflict_flagged": false}},
  "survey": {{"confidence": <1 very low .. 5 very high>,
             "uncertainty_source": "ambiguous_condition | partial_capture |
                                    unclear_threshold | encrypted_content | other"}}
}}"""

#: The paraphrase dimension. Both say the same thing; a separate reviewer
#: has to confirm that before a run, which is a human step, not a test.
_TASK_WORDING = {
    "a": (
        "Decide whether the claim below is supported by this packet capture, "
        "refuted by it, or not verifiable from it."
    ),
    "b": (
        "Below is a claim about a packet capture. Determine, from the capture alone, "
        "whether it holds, whether the capture contradicts it, or whether the capture "
        "cannot settle it."
    ),
}


@dataclass(frozen=True)
class PromptVariant:
    label: str
    dimension: str
    role: str | None
    criteria_style: str
    label_order: list[str]
    wording: str

    @property
    def identity(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "dimension": self.dimension,
            "role": self.role,
            "criteria_style": self.criteria_style,
            "label_order": self.label_order,
            "wording": self.wording,
        }


@dataclass(frozen=True)
class RenderedPrompt:
    prompt_id: str
    prompt_hash: str
    label: str
    dimension: str
    system: str
    user: str

    @property
    def full_text(self) -> str:
        return f"{self.system}\n\n{self.user}"


class PromptBuilder:
    def __init__(self, prompt_dir: Path | None = None) -> None:
        self.dir = prompt_dir or PROMPT_DIR
        self.criteria = (self.dir / "criteria.md").read_text(encoding="utf-8").strip()
        config = yaml.safe_load((self.dir / "variants.yaml").read_text(encoding="utf-8"))
        self.set_version = int(config.get("prompt_set_version", 1))
        self.variants = [PromptVariant(**item) for item in config["variants"]]

    # -- identity ----------------------------------------------------------

    def variant(self, label: str) -> PromptVariant:
        for variant in self.variants:
            if variant.label == label:
                return variant
        raise KeyError(f"no prompt variant {label!r}")

    def prompt_hash(self, variant: PromptVariant) -> str:
        """
        Hash the variant, not one rendering of it.

        The hash has to be stable across items -- it identifies "which
        prompt was used", and every item renders different text. The
        criteria are included so that editing criteria.md produces new
        hashes, and therefore a new run.
        """
        return content_hash(
            {"set_version": self.set_version, "variant": variant.identity, "criteria": self.criteria}
        )

    def prompt_id(self, variant: PromptVariant) -> str:
        return content_id("prm", {"set_version": self.set_version, "label": variant.label})

    @property
    def set_hash(self) -> str:
        return content_hash(
            {"set_version": self.set_version, "criteria": self.criteria,
             "variants": [v.identity for v in self.variants]}
        )

    # -- rendering ---------------------------------------------------------

    def _criteria_block(self, variant: PromptVariant) -> str:
        if variant.criteria_style == "none":
            return ""  # the control: no criteria, which is the point of it
        if variant.criteria_style == "xml":
            return f"<criteria>\n{self.criteria}\n</criteria>"
        return self.criteria

    def render(
        self,
        variant: PromptVariant,
        *,
        claim_text: str,
        capture: dict[str, Any] | None,
        thresholds: dict[str, Any] | None = None,
    ) -> RenderedPrompt:
        """
        Build the prompt for one (variant, claim, capture).

        `capture` is the capture's own description of itself -- path-free,
        so the file name cannot hint at the scenario -- or None for an item
        deliberately given no capture.
        """
        system_parts = []
        if variant.role:
            system_parts.append(variant.role)
        system_parts.append(_TASK_WORDING[variant.wording])
        criteria = self._criteria_block(variant)
        if criteria:
            system_parts.append(criteria)
        system_parts.append(TOOL_DESCRIPTION)
        system_parts.append(
            OUTPUT_INSTRUCTIONS.format(labels=" | ".join(f'"{label}"' for label in variant.label_order))
        )

        user_parts = [f"CLAIM:\n{claim_text}"]
        if capture is None:
            user_parts.append(
                "CAPTURE:\nNo packet capture is available for this claim. The pcap_query tool "
                "will return nothing."
            )
        else:
            user_parts.append("CAPTURE:\n" + json.dumps(capture, indent=2, sort_keys=True))
        if thresholds:
            user_parts.append(
                "PARAMETERS (fixed in advance, use these and no others):\n"
                + json.dumps(thresholds, indent=2, sort_keys=True)
            )
        user_parts.append("Answer with the JSON object only.")

        return RenderedPrompt(
            prompt_id=self.prompt_id(variant),
            prompt_hash=self.prompt_hash(variant),
            label=variant.label,
            dimension=variant.dimension,
            system="\n\n".join(system_parts),
            user="\n\n".join(user_parts),
        )

    @staticmethod
    def capture_view(pcap_row: dict[str, Any], summary: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        What the solver is told about the capture.

        Deliberately excludes the file path and the source: a name like
        `mirai-infection_…pcap` would answer half the question on its own.
        """
        metadata = pcap_row.get("capture_metadata") or {}
        view = {
            "packet_count": pcap_row.get("packet_count"),
            "size_bytes": pcap_row.get("size_bytes"),
            "closed_world": {
                "vantage_point": metadata.get("vantage_point"),
                "both_directions": metadata.get("both_directions"),
                "known_gaps": metadata.get("known_gaps") or [],
            },
        }
        if summary:
            view["first_packet_epoch"] = summary.get("first_packet_epoch")
            view["last_packet_epoch"] = summary.get("last_packet_epoch")
            view["protocol_hierarchy"] = summary.get("protocol_hierarchy")
            view["endpoints"] = summary.get("endpoints")
        return view
