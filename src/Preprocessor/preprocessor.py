"""
PAnGEA — Preprocessor.
 
The top-level entry point for the Preprocessing stage. Wires together the
two sub-components per the spec:
 
    Attack Description ──▶ Filter Generator ──▶ filter_string ──┐
                                                                  ▼
    PCAP ─────────────────────────────────────────────────▶ Reducer ──▶ Reduced Representation
 
Deliberately mirrors the R2 boundary at the call-site level: this function
accepts `attack_description` and passes it ONLY to `generate_filter`. The
Reducer is called with the resulting `filter_string`, never the description
itself — there's no code path here that could leak it through.
"""
from __future__ import annotations
 
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional
 
from .filter_generator import generate_filter, LLMClient
from .reducer import reduce_pcap
from .schemas import ReducerOutput
 
 
def run_preprocessing(
    pcap_bytes: bytes,
    attack_description: str,
    token_budget: int,
    filtering_limit: int = 3,
    max_packets: Optional[int] = None,
    llm_client: Optional[LLMClient] = None,
    verbose: bool = False,
) -> ReducerOutput:
    """
    Full Preprocessing stage: Filter Generator -> Reducer.
 
    Args:
        pcap_bytes: raw PCAP file contents.
        attack_description: free text. Seen ONLY by generate_filter — never
            forwarded to reduce_pcap (R2, enforced structurally: reduce_pcap's
            signature has no parameter for it at all).
        token_budget: final, pre-computed token budget for the Reducer's
            output. Computing this (context window - system prompt -
            description - expected output - safety margin) is an
            orchestration-level concern upstream of this function, not the
            Preprocessor's job — see prior spec discussion on why this must
            live outside Preprocessing (R2 also blocks Preprocessing from
            being able to compute it itself, since that would require
            reading the description's own token length).
        filtering_limit: raw samples retained per fingerprint before folding
            into aggregate-only stats.
        max_packets: optional cheap circuit breaker (item count).
        llm_client: optional callable passed through to the Filter
            Generator. If omitted, the deterministic keyword fallback is
            used instead of a live LLM call.
 
    Returns:
        ReducerOutput — the full Preprocessing result (reduced
        representation, fingerprint_index, compression stats, budget status).
    """
    filter_string = generate_filter(attack_description, llm_client=llm_client)
    if verbose:
        print(f"Filter Generator produced filter string:\n{filter_string}\n", file=sys.stderr)
    return reduce_pcap(
        pcap_bytes=pcap_bytes,
        token_budget=token_budget,
        filtering_limit=filtering_limit,
        filter_string=filter_string,
        max_packets=max_packets,
    )
 
 
def reducer_output_to_dict(output: ReducerOutput) -> dict:
    """JSON-serializable form of ReducerOutput (dataclasses -> dicts, enum -> value)."""
    d = asdict(output)
    d["budget_status"] = output.budget_status.value
    return d
 
 
def reducer_output_to_json(output: ReducerOutput, indent: int = 2) -> str:
    return json.dumps(reducer_output_to_dict(output), indent=indent)
 
 
# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
 
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preprocessor",
        description="Run the PAnGEA Preprocessing stage (Filter Generator + Reducer) "
                    "on a PCAP file and emit the reduced representation as JSON.",
    )
    parser.add_argument("pcap_path", type=str, help="Path to the input .pcap/.pcapng file")
    parser.add_argument(
        "--description", type=str, default="",
        help="Attack/traffic description text (seen only by the Filter "
             "Generator, never the Reducer). Omit for a no-op filter.",
    )
    parser.add_argument(
        "--description-file", type=str, default=None,
        help="Path to a text file containing the description, as an "
             "alternative to --description.",
    )
    parser.add_argument(
        "--token-budget", type=int, default=4000,
        help="Final token budget for the reduced output (default: 4000). "
             "Computing this from the model's context window is expected "
             "to happen upstream; this is just the resulting number.",
    )
    parser.add_argument(
        "--filtering-limit", type=int, default=3,
        help="Raw samples retained per fingerprint before aggregating (default: 3).",
    )
    parser.add_argument(
        "--max-packets", type=int, default=None,
        help="Optional cheap circuit breaker on output item count.",
    )
    parser.add_argument(
        "-o", "--output", type=str, default=None,
        help="Write JSON output to this path instead of stdout.",
    )
    return parser
 
 
def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
 
    pcap_path = Path(args.pcap_path)
    if not pcap_path.exists():
        print(f"error: PCAP file not found: {pcap_path}", file=sys.stderr)
        return 1
 
    description = args.description
    if args.description_file:
        desc_path = Path(args.description_file)
        if not desc_path.exists():
            print(f"error: description file not found: {desc_path}", file=sys.stderr)
            return 1
        description = desc_path.read_text()
 
    pcap_bytes = pcap_path.read_bytes()
 
    output = run_preprocessing(
        pcap_bytes=pcap_bytes,
        attack_description=description,
        token_budget=args.token_budget,
        filtering_limit=args.filtering_limit,
        max_packets=args.max_packets,
        verbose=args.verbose,
    )
 
    json_str = reducer_output_to_json(output)
 
    if args.output:
        Path(args.output).write_text(json_str)
        print(f"Wrote reduced representation to {args.output}", file=sys.stderr)
        print(
            f"packets_in={output.compression_stats.raw_packet_count_in} "
            f"packets_out={output.compression_stats.packet_count_out} "
            f"budget_status={output.budget_status.value}",
            file=sys.stderr,
        )
    else:
        print(json_str)
 
    return 0
 
 
if __name__ == "__main__":
    sys.exit(main())
 