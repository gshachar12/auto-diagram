"""
Step Extractor (Grounder sub-component #1).

  Responsibility: convert free text into a structured list of atomic steps.
  Input: Traffic Description ONLY. Never receives the Reduced PCAP, so its output
          cannot be biased by what evidence happens to exist in the capture.
  What it does:
    - Splits the description into a flat list of atomic steps.
    - For each step, defines any technical term used within the step's own text
      (a prompting instruction, not a separate processing step).
    - Identifies actors referenced in the description (roles such as
      attacker/victim/client/server) - role identification only, not IP resolution.
    - Derives expected_indicators for each step in two layers:
        * Structured hints (protocol, port, flags, direction, volume pattern,
          cardinality pattern) - used for algorithmic matching.
        * Free-text fallback (indicator_description) - used when a step doesn't
          reduce cleanly to structured fields.
  Mechanism: necessarily LLM-based - no viable algorithmic substitute.

  ACTOR-QUALITY INSTRUCTIONS (added after observing real extraction errors,
  not preemptively): the prompt below explicitly targets three failure
  modes actually seen in practice on a real ARP-spoofing scenario:
    1. Entity fragmentation -- the same real-world host ("kali", described
       first as "the offensive framework host" and later simply as "the
       attacker") was split into two separate actor_ids. Evidence tied to
       one fragment then never connects to steps referencing the other.
    2. Entity omission -- named entities explicitly mentioned in the text
       (a gateway/router, a named destination server/domain) were dropped
       entirely from actors[], even though later steps depend on them.
    3. Category error -- "traffic" itself (a direction/flow, not a host)
       was extracted as if it were an actor.
  These are addressed here, in the prompt, because catching them before
  Evidence Matcher/Validator ever see the output is far cheaper than
  catching them after -- garbage actors propagate into every step that
  references them.
"""
from __future__ import annotations

import json
import logging
import os
import re

try:
    from .llm_client import LLMClient
    from .models import Actor, Step, ExpectedIndicators
except ImportError:
    from llm_client import LLMClient
    from models import Actor, Step, ExpectedIndicators

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the Step Extractor stage of a network-traffic grounding pipeline.
You receive ONLY a free-text Network Traffic Description (an attack narrative, a
protocol behavior description, or an ordinary traffic summary). You do NOT have
access to any packet capture - work purely from the text.

Your job:

1. Split the description into a flat list of atomic, checkable chronological steps.
   Each step should be a single verifiable statement (do not bundle multiple facts
   into one step; do not split a single fact into fragments).

2. Within each step's own text, spell out any technical term used (e.g. instead of
   "the host performed a SYN scan", say "the host sent TCP SYN packets to many ports
   without completing the handshake"), so steps are self-contained.

3. Identify actors -- this is the step most likely to go wrong, so follow these
   rules precisely:

   a. AN ACTOR IS A DISCRETE NETWORK ENTITY (a host, device, or service) --
      never an abstraction. Do NOT create an actor for traffic itself, a
      direction, a flow, a protocol, or a relationship between two other
      actors. ("victim_traffic" describing packets going to/from a victim
      is NOT an actor -- the victim is the actor; the direction belongs in
      that step's expected_indicators.direction field instead, e.g.
      "attacker->victim".)

   b. ONE REAL-WORLD ENTITY = ONE actor_id, even if the text refers to it
      differently at different points in the narrative (by name, by role,
      by function). Before finalizing your actor list, re-read the WHOLE
      text and ask: "could any two of my draft actors actually be the same
      underlying host, described in different words as the narrative
      progresses?" If yes, merge them into a single actor_id and combine
      their description_ref to reflect both mentions. A concrete pattern to
      watch for: a host introduced early by name or by its function (e.g.
      "an offensive framework host named X" or "a compromised internal
      server") that is later referred to more generically (e.g. "the
      attacker", "the intruder") in the SAME continuous narrative about the
      same actions -- these are almost always one entity, not two.

   c. EXTRACT EVERY NAMED OR CLEARLY-IDENTIFIABLE NETWORK ENTITY the text
      mentions, not only ones with an adversarial role. This explicitly
      includes: intermediary infrastructure (a default gateway, a router,
      a DNS resolver, a proxy) whenever the text names its role in the
      traffic, and named destination services/domains/servers the traffic
      is directed at or through (e.g. a specific external domain or
      server named in the text). If a step later depends on such an
      entity (e.g. "traffic was routed through the gateway", "the server
      at example.com responded"), that entity MUST have its own actor
      entry -- do not fold it into a generic role or omit it because it
      isn't "the attacker" or "the victim".

   d. Do not invent a second, redundant actor for a group of hosts already
      covered by an existing actor, unless the text gives it a genuinely
      distinct identity or role. (E.g. if "local hosts" and "network
      nodes" both refer to the same unspecified set of ordinary hosts on
      the network with no distinguishing detail between the two mentions,
      that is ONE actor, not two.)

   e. This is ROLE/ENTITY IDENTIFICATION ONLY -- do not attempt to resolve
      any actor to an IP address; you have no packet evidence to do so.

   f. SELF-CHECK BEFORE RETURNING: once you have a draft actor list, verify
      each of the following explicitly, and correct the list if any fail:
        - No actor represents traffic, a direction, or an abstraction
          rather than a concrete host/device/service (rule a).
        - No two actors are actually the same real-world entity under
          different descriptions (rule b).
        - Every named or role-bearing entity mentioned anywhere in the
          text -- including intermediary infrastructure and named
          destination services -- has a corresponding actor (rule c).
        - No actor is a redundant duplicate of another with no
          distinguishing detail (rule d).
          
    g. INTERNAL CONSISTENCY: every actor_id mentioned inside a step's
        `direction` field MUST also appear in that step's `actor_refs` list.
        If a step's direction implies an actor not yet listed in actor_refs,
        either add that actor_id to actor_refs, or omit direction if the
        entity it would reference isn't actually a participant in this step.

4. For each step, derive expected_indicators in two layers:
   a. Structured hints, ONLY when the text clearly implies them:
      - protocol: one of TCP, UDP, ICMP, ARP, DNS, HTTP (or another named protocol)
      - port: a port number, if named or inferable from a named service
      - flags: a list of relevant protocol flags (e.g. ["SYN"], ["SYN","ACK"]).
        For ARP specifically, use the opcode instead (e.g. ["Opcode 2"] for
        an ARP reply, ["Opcode 1"] for an ARP request).
      - direction: expressed using actor_ids, e.g. "attacker->victim"
      - volume_pattern: a short label such as "high", "burst", "steady", "low"
      - cardinality_pattern: a short label such as "one-to-many", "many-to-one",
        "one-to-one"
      Omit any structured field you are not confident about - use JSON null,
      never a placeholder value like 0 or an empty list standing in for "unknown".
   b. indicator_description: a free-text fallback description of what evidence
      would support this step. ALWAYS include this, even when structured fields
      are also present, as a semantic backstop.

Return ONLY a JSON object (no prose, no markdown fences) with this exact shape.
Every field marked "or null" MUST be the JSON literal null when unknown -- never
a placeholder number, empty string, or empty list standing in for "unknown":
{
  "actors": [
    {"actor_id": "<short_snake_case_id>", "role": "<role>", "description_ref": "<quoted or paraphrased reference from the text, combining all mentions if merged per rule 3b>"}
  ],
  "steps": [
    {
      "step_id": "step 1",
      "text": "<self-contained atomic step>",
      "actor_refs": ["<actor_id>", ...],
      "expected_indicators": {
        "protocol": "...",              // string or null
        "port": 80,                     // integer or null
        "flags": ["SYN"],               // list of strings or null
        "direction": "attacker->victim",// string or null
        "volume_pattern": "...",        // string or null
        "cardinality_pattern": "...",   // string or null
        "indicator_description": "..."  // always a non-null string
      }
    }
  ]
}
"""

USER_PROMPT_TEMPLATE = """\
Network Traffic Description:
\"\"\"
{description}
\"\"\"

Extract the actors and atomic steps as instructed. Before returning, run the
self-check in rule 3f explicitly and correct your draft actor list if needed.
Return JSON only.
"""


def parse_and_repair_json(raw_text: str, max_repairs: int = 5) -> dict:
    """
    Attempts to parse JSON, fixing common minor formatting issues.

    NOTE on scope: when the LLM call uses a JSON-mode/structured-output API
    (e.g. OpenAI's response_format={"type": "json_object"}), the response
    is already guaranteed syntactically valid JSON, and this function's
    repair logic is mostly unnecessary insurance for that path. It exists
    as a defensive fallback for LLM backends that do NOT guarantee valid
    JSON output. Because of that, repairs are applied conservatively and
    only when json.loads has already failed -- see the single-quote fix
    below for why order-of-operations here matters.
    """
    cleaned = raw_text.strip()

    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    repairs_applied = 0
    repaired_text = cleaned

    python_literals = [(r"\bTrue\b", "true"), (r"\bFalse\b", "false"), (r"\bNone\b", "null")]
    for pattern, replacement in python_literals:
        new_text, n = re.subn(pattern, replacement, repaired_text)
        if n:
            repaired_text = new_text
            repairs_applied += n

    repaired_text, n = re.subn(r",\s*([}\]])", r"\1", repaired_text)
    repairs_applied += n

    # FIX (previously regressed back to the unsafe unconditional version):
    # only treat this as single-quoted JSON if single-quotes clearly
    # dominate over double-quotes -- otherwise this corrupts legitimate
    # apostrophes inside already-valid double-quoted string values (e.g.
    # step.text containing "the attacker's connection").
    single_count = repaired_text.count("'")
    double_count = repaired_text.count('"')
    if single_count > double_count * 2:
        repaired_text, n = re.subn(r"'([^'\\]*(?:\\.[^'\\]*)*)'", r'"\1"', repaired_text)
        repairs_applied += n

    def _escape_newlines(match: "re.Match") -> str:
        return match.group(1).replace("\n", "\\n").replace("\r", "\\r")

    fixed_control, n = re.subn(r'(".*?")', _escape_newlines, repaired_text, flags=re.DOTALL)
    if n:
        repaired_text = fixed_control
        repairs_applied += n

    # FIX (previously regressed): count actual replacements made, not
    # distinct fix-categories attempted, so this threshold can actually
    # fire.
    if repairs_applied > max_repairs:
        raise ValueError(
            f"JSON payload required {repairs_applied} repairs, exceeding "
            f"max_repairs={max_repairs}; treating as too malformed to trust."
        )

    try:
        parsed = json.loads(repaired_text)
        logger.info("Successfully auto-repaired JSON (%d fixes applied).", repairs_applied)
        return parsed
    except json.JSONDecodeError as err:
        raise ValueError(
            f"Failed to parse or repair JSON payload: {err}\n"
            f"Raw text sample: {raw_text[:200]}..."
        ) from err


class StepExtractor:
    """Wraps the LLM call and turns its JSON response into typed objects."""

    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def extract(self, traffic_description: str) -> tuple[list[Actor], list[Step]]:
        user_prompt = USER_PROMPT_TEMPLATE.format(description=traffic_description.strip())
        raw = self.llm_client.complete_json(SYSTEM_PROMPT, user_prompt)

        if isinstance(raw, str):
            raw = parse_and_repair_json(raw)

        return self._parse(raw)

    @staticmethod
    def _parse(raw: dict) -> tuple[list[Actor], list[Step]]:
        actors = [
            Actor(
                actor_id=a["actor_id"],
                role=a.get("role", ""),
                description_ref=a.get("description_ref", ""),
            )
            for a in raw.get("actors", [])
        ]

        steps: list[Step] = []
        skipped = 0
        for i, c in enumerate(raw.get("steps", [])):
            try:
                ei_raw = c.get("expected_indicators", {}) or {}
                expected_indicators = ExpectedIndicators(
                    protocol=ei_raw.get("protocol"),
                    port=ei_raw.get("port"),
                    flags=ei_raw.get("flags"),
                    direction=ei_raw.get("direction"),
                    volume_pattern=ei_raw.get("volume_pattern"),
                    cardinality_pattern=ei_raw.get("cardinality_pattern"),
                    indicator_description=ei_raw.get("indicator_description"),
                )
                steps.append(
                    Step(
                        step_id=c["step_id"],
                        text=c["text"],
                        expected_indicators=expected_indicators,
                        actor_refs=c.get("actor_refs", []),
                    )
                )
            except (KeyError, TypeError) as e:
                # FIX (previously regressed): a single malformed step used
                # to raise here and lose EVERY step in the batch, not just
                # the bad one. Skip and log instead.
                skipped += 1
                logger.warning("Skipping malformed step at index %d: %s (raw=%r)", i, e, c)

        if skipped:
            logger.warning("Step Extractor: skipped %d malformed step(s) out of %d received.",
                            skipped, len(raw.get("steps", [])))

        return actors, steps


def _to_dict(obj):
    """Helper to convert dataclasses or Pydantic models to dicts."""
    from dataclasses import asdict, is_dataclass
    if is_dataclass(obj):
        return asdict(obj)
    elif hasattr(obj, "model_dump"):  # Pydantic v2
        return obj.model_dump()
    elif hasattr(obj, "dict"):        # Pydantic v1
        return obj.dict()
    return obj


def main():
    try:
        from .llm_client import OpenAIClient
    except ImportError:
        from llm_client import OpenAIClient

    logging.basicConfig(level=logging.INFO)

    file_path = "example_attack_description.txt"
    attack_desc = ""

    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                attack_desc = f.read().strip()
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")

    if not attack_desc:
        attack_desc = (
            "An attacker performed a TCP SYN scan on port 80 of the target web server."
        )

    api_key = os.environ.get("OPENAI_API_KEY")
    print(f"\nOPENAI_API_KEY: {'set' if api_key else 'not set'}")

    if api_key:
        print("\n--- LLM-backed ---")
        client = OpenAIClient(api_key=api_key, model="gpt-4o")

        extractor = StepExtractor(llm_client=client)
        actors, steps = extractor.extract(attack_desc)

        output_data = {
            "actors": [_to_dict(a) for a in actors],
            "steps": [_to_dict(c) for c in steps],
        }

        output_filename = "extraction_output.json"
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"\nSuccessfully extracted {len(actors)} actors and {len(steps)} steps.")
        print(f"Results saved to: {os.path.abspath(output_filename)}")
    else:
        print("\n(set OPENAI_API_KEY to test the LLM-backed path)")


if __name__ == "__main__":
    main()