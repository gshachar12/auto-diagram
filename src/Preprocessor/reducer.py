"""
PAnGEA — Reducer (Preprocessing sub-component).

Responsibility: compress a raw PCAP into a budget-compliant reduced
representation, while satisfying:

  R1  Referential Integrity     — every output item carries packet_id +
                                   timestamp back to the source PCAP.
  R2  Temporal Order Preservation— output preserves original chronological
                                   order; compression never reorders.
                                   
  R3  Aggregate Traceability     — every dropped/folded packet leaves a
                                   quantitative trace; nothing vanishes
                                   silently.
  R4  Budget Compliance          — best-effort, NOT silent truncation. If
                                   the budget would be exceeded, processing
                                   stops, everything processed so far is
                                   returned, and budget_status is set to
                                   EXCEEDED with the exact stopping point.
  R5  Protocol Agnosticism       — fingerprint logic (fingerprint.py) never
                                   branches on "what kind of attack this
                                   might be" — only on structural protocol
                                   state.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import tempfile
from typing import Optional

import pyshark
    
from Preprocessor.fingerprint import (
    fingerprint_tcp, fingerprint_udp, fingerprint_arp, fingerprint_icmp,
    fingerprint_key_str,
)
from Preprocessor.schemas import (
    AggregateRef, ReducedItem, CompressionStats, ReducerOutput, BudgetStatus,
)
from Preprocessor.token_budget import estimate_item_tokens


def reduce_pcap(
    pcap_bytes: bytes,
    token_budget: int,
    filtering_limit: int = 3,
    filter_string: Optional[str] = None,
    max_packets: Optional[int] = None,
) -> ReducerOutput:
    """
    Reducer entry point.
    """
    reduced_items: list[ReducedItem] = []  # will include both raw and aggregated items, in chronological order
    fingerprint_index: dict[str, AggregateRef] = {}  # maps fingerprint_key -> AggregateRef
    _representative_idx: dict[str, int] = {}  # maps fingerprint_key -> index in reduced_items of representative item
    handshakes_completed: set[str] = set()  # tracks TCP stream ids whose handshake has completed
    total_raw_packets = 0
    dropped_parse_failures = 0
    running_tokens = 0
    budget_status = BudgetStatus.WITHIN_BUDGET
    budget_status_detail: Optional[str] = None
    loop = asyncio.new_event_loop()
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    pcap_path = tmp.name

    try:
        tmp.write(pcap_bytes)
        tmp.close()

        capture_path = pcap_path
        filtered_path: Optional[str] = None

        # NOTE: tshark/pyshark cannot apply a true BPF filter to an
        # already-captured file -- tshark's -f (capture filter) only
        # works during live capture; on offline files tshark only accepts
        # -Y (display filter, Wireshark syntax, e.g. "tcp.port==443") --
        # NOT BPF syntax (e.g. "tcp port 443"), which is what Filter
        # Generator actually produces (validated via `tcpdump -d`, not a
        # Wireshark display-filter validator). Passing a BPF string
        # directly as display_filter fails outright for anything beyond
        # coincidentally-valid-in-both strings like "ip or arp" (the
        # default) -- confirmed via `tshark -Y "tcp port 443"`, which
        # rejects it with "was unexpected in this context".
        #
        # Fix: pre-filter with tcpdump (which DOES support real BPF
        # against -r <file>) into a temp file, then hand pyshark the
        # already-filtered file with no display_filter at all.
        if filter_string and filter_string.strip():
            filtered_fd = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            filtered_path = filtered_fd.name
            filtered_fd.close()
            try:
                subprocess.run(
                    ["tcpdump", "-r", pcap_path, "-w", filtered_path, filter_string],
                    check=True, capture_output=True, timeout=120,
                )
                capture_path = filtered_path
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # Malformed filter or tcpdump failure -- degrade to
                # unfiltered rather than failing the whole stage.
                capture_path = pcap_path

        cap = pyshark.FileCapture(
            capture_path,
            eventloop=loop,
            keep_packets=False,
        )

        try:
            for pkt in cap:
                total_raw_packets += 1

                try:
                    src, dst, l4_proto = _extract_identity(pkt)
                    if l4_proto is None:
                        continue
                    fp = _fingerprint_packet(pkt, l4_proto, handshakes_completed)
                    if fp is None:
                        continue
                    fkey = fingerprint_key_str(fp.l4_proto, fp.state_signature)
                    pkt_length = int(pkt.length)
                    timestamp = pkt.sniff_time.isoformat()
                    packet_id = int(pkt.number)

                    if fkey not in fingerprint_index:
                        item = ReducedItem(
                            packet_id=packet_id,
                            timestamp=timestamp,
                            protocol=pkt.highest_layer,
                            src=src,
                            dst=dst,
                            length=pkt_length,
                            info=fp.info,
                            fingerprint_key=fkey,
                        )

                        item_tokens = estimate_item_tokens(vars(item))

                        if running_tokens + item_tokens > token_budget:
                            budget_status = BudgetStatus.EXCEEDED
                            budget_status_detail = (
                                f"stopped before packet_id={packet_id} "
                                f"(timestamp={timestamp}); "
                                f"{len(reduced_items)} items retained so far"
                            )
                            break

                        reduced_items.append(item)
                        running_tokens += item_tokens
                        _representative_idx[fkey] = len(reduced_items) - 1
                        fingerprint_index[fkey] = AggregateRef(
                            fingerprint_key=fkey,
                            count=1,
                            total_bytes=pkt_length,
                            unique_sources=[src],
                            unique_destinations=[dst],
                        )

                    else:
                        agg = fingerprint_index[fkey]
                        agg.count += 1
                        agg.total_bytes += pkt_length
                        if src not in agg.unique_sources:
                            agg.unique_sources.append(src)
                        if dst not in agg.unique_destinations:
                            agg.unique_destinations.append(dst)

                        if agg.count <= filtering_limit:
                            item = ReducedItem(
                                packet_id=packet_id,
                                timestamp=timestamp,
                                protocol=pkt.highest_layer,
                                src=src,
                                dst=dst,
                                length=pkt_length,
                                info=fp.info,
                                fingerprint_key=fkey,
                            )
                            item_tokens = estimate_item_tokens(vars(item))

                            if running_tokens + item_tokens > token_budget:
                                budget_status = BudgetStatus.EXCEEDED
                                budget_status_detail = (
                                    f"stopped before packet_id={packet_id} "
                                    f"(timestamp={timestamp}); "
                                    f"{len(reduced_items)} items retained so far"
                                )
                                break

                            reduced_items.append(item)
                            running_tokens += item_tokens
                        else:
                            rep_idx = _representative_idx[fkey]
                            reduced_items[rep_idx].aggregate = AggregateRef(
                                fingerprint_key=fkey,
                                count=agg.count,
                                total_bytes=agg.total_bytes,
                                unique_sources=list(agg.unique_sources),
                                unique_destinations=list(agg.unique_destinations),
                            )

                    if max_packets is not None and len(reduced_items) >= max_packets:
                        break

                except (AttributeError, ValueError):
                    dropped_parse_failures += 1
                    continue
        finally:
            cap.close()
    finally:
        for p in (pcap_path, filtered_path):
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
        loop.close()

    compression_ratio = (
        1.0 - (len(reduced_items) / total_raw_packets)
        if total_raw_packets > 0 else 0.0
    )

    stats = CompressionStats(
        raw_packet_count_in=total_raw_packets,
        packet_count_out=len(reduced_items),
        estimated_tokens_out=running_tokens,
        dropped_parse_failures=dropped_parse_failures,
        compression_ratio=round(compression_ratio, 4),
    )

    return ReducerOutput(
        reduced_representation=reduced_items,
        fingerprint_index=fingerprint_index,
        compression_stats=stats,
        budget_status=budget_status,
        budget_status_detail=budget_status_detail,
        filter_string_used=filter_string,
    )


def _extract_identity(pkt) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Layer 2/3 identity extraction. Returns (src, dst, l4_proto) or
    (None, None, None) if the packet has neither IP nor ARP."""
    if hasattr(pkt, "ip"):
        l4_proto = pkt.transport_layer if pkt.transport_layer else "IP_RAW"
        return pkt.ip.src, pkt.ip.dst, l4_proto
    if hasattr(pkt, "arp"):
        src = pkt.arp.src_proto_ipv4 if hasattr(pkt.arp, "src_proto_ipv4") else "N/A"
        dst = pkt.arp.dst_proto_ipv4 if hasattr(pkt.arp, "dst_proto_ipv4") else "N/A"
        return src, dst, "ARP"
    return None, None, None


def _fingerprint_packet(pkt, l4_proto: str, handshakes_completed: set[str]):
    if l4_proto == "TCP":
        return fingerprint_tcp(
            flags_hex=pkt.tcp.flags,
            dst_port=pkt.tcp.dstport,
            stream_id=pkt.tcp.stream,
            handshakes_completed=handshakes_completed,
        )     
    if l4_proto == "UDP":
        return fingerprint_udp(dst_port=pkt.udp.dstport)
    if l4_proto == "ARP":
        sender_mac = pkt.arp.src_hw_mac if hasattr(pkt.arp, "src_hw_mac") else "N/A"
        return fingerprint_arp(opcode=pkt.arp.opcode, sender_mac=sender_mac)
    if hasattr(pkt, "icmp"):
        return fingerprint_icmp(icmp_type=pkt.icmp.type, icmp_code=pkt.icmp.code)
    return None


def save_reducer_output(output: ReducerOutput, file_path: str):
    """Saves ReducerOutput as formatted JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    
    # Serialize Pydantic object
    if hasattr(output, "model_dump_json"):
        json_data = output.model_dump_json(indent=2)
    elif hasattr(output, "json"):
        json_data = output.json(indent=2)
    else:
        json_data = json.dumps(output, default=lambda o: o.__dict__, indent=2)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(json_data)


def main():
    parser = argparse.ArgumentParser(description="Reducer Component")
    parser.add_argument("--pcap", type=str, default="./example_attack.pcap", help="Path to input PCAP file")
    parser.add_argument("--output", type=str, default="./reducer_output.json", help="Path for output JSON file")
    parser.add_argument("--token-budget", type=int, default=25000, help="Token budget limit")
    parser.add_argument("--filtering-limit", type=int, default=2, help="Raw samples to retain per fingerprint")
    parser.add_argument("--filter-string", type=str, default="ip or arp", help="BPF display filter")
    parser.add_argument("--max-packets", type=int, default=30, help="Max packets to process")

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"Error: File '{args.pcap}' does not exist.")
        return

    with open(args.pcap, "rb") as f:
        pcap_bytes = f.read()

    print(f"Processing PCAP: {args.pcap} ...")
    output = reduce_pcap(
        pcap_bytes=pcap_bytes,
        token_budget=args.token_budget,
        filtering_limit=args.filtering_limit,
        filter_string=args.filter_string,
        max_packets=args.max_packets,
    )

    # Save to JSON file
    save_reducer_output(output, args.output)

    # Print summary to console
    print("\n--- Processing Complete ---")
    print(f"Status:             {output.budget_status}")
    print(f"Packets In:         {output.compression_stats.raw_packet_count_in}")
    print(f"Items Out:          {output.compression_stats.packet_count_out}")
    print(f"Tokens Out:         {output.compression_stats.estimated_tokens_out}")
    print(f"Compression Ratio:  {output.compression_stats.compression_ratio * 100:.2f}%")
    print(f"Output Saved To:    {args.output}\n")


if __name__ == "__main__":
    main()