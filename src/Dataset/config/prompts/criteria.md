When is a claim verified by packets?

A single packet almost never verifies a claim. What verifies it is a
condition, executed over a set of packets — the evidence set.

1. Executable condition. Translate the claim into a condition that can be run
   on the capture: a tshark display filter, plus a time window or a threshold
   where the claim needs one. A claim is SUPPORTED only if the condition holds
   on the evidence set.
2. Sufficiency. The evidence set alone must justify the verdict.
3. Minimality. Keep the evidence set as small as possible, so each packet in
   it is attributable. For a quantitative claim the evidence set is every
   matching packet.
4. Window. The time the claim refers to must fall inside the capture window.
5. No silent conflicts. If counter-evidence of equal weight exists, flag the
   conflict; do not resolve it silently.
6. A failed condition is not automatically REFUTED. REFUTED requires either
   (a) the capture is complete for the relevant path and window and nothing
   matches, or (b) positive evidence contradicting the claim. Otherwise the
   verdict is NOT_VERIFIABLE, usually INCOMPLETE_CAPTURE or ENCRYPTED.
7. The closed-world assumption is explicit per capture. The capture metadata
   states the vantage point, whether both directions were captured, and any
   known gaps. Judge absence claims against it. Where direction coverage is
   unknown, an absence claim is NOT_VERIFIABLE, not REFUTED.

By claim type:

- Existential packet. Evidence: one packet. SUPPORTED when a packet matches.
  REFUTED when none matches and the capture is complete there. NOT_VERIFIABLE
  on truncated headers or partial capture.
- Protocol. Evidence: the reassembled message. SUPPORTED when reassembly
  yields a matching message. REFUTED when the same message carries a different
  value, or is absent in a closed world. NOT_VERIFIABLE when the payload is
  encrypted or segments are missing.
- Absence ("no response"). Evidence: the request and its window. SUPPORTED
  when no response appears within the window in a bidirectional capture.
  REFUTED when a response exists. NOT_VERIFIABLE on a one-directional capture,
  or when the response could fall outside the window.
- Quantitative. Evidence: every packet satisfying the condition. SUPPORTED
  when the count meets the stated threshold. REFUTED when it falls outside
  tolerance. NOT_VERIFIABLE when the quantifier is vague and no threshold is
  given.
- Sequence. Evidence: the two events. SUPPORTED when both exist and the gap
  exceeds the tolerance. REFUTED when the order is reversed beyond it.
  NOT_VERIFIABLE when the gap is smaller than the tolerance, an event is
  missing, or the clock is unreliable.
- Semantic, intent or outcome. No evidence set exists. Always NOT_VERIFIABLE,
  with a reason code. Do not guess.
