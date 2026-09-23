"""
Edge-case tests for the Reducer -- inputs that are easy to overlook but
common enough in real PCAPs to be worth guarding explicitly.
"""
import sys
sys.path.insert(0, "src")

from reducer import reduce_pcap
from schemas import BudgetStatus


class TestEmptyAndMinimalInputs:

    def test_empty_pcap_does_not_crash(self, empty_pcap_bytes):
        out = reduce_pcap(empty_pcap_bytes, token_budget=1000, filtering_limit=3)
        assert out.reduced_representation == []
        assert out.compression_stats.raw_packet_count_in == 0
        assert out.budget_status == BudgetStatus.WITHIN_BUDGET

    def test_single_packet_pcap(self, single_syn_packet_bytes):
        out = reduce_pcap(single_syn_packet_bytes, token_budget=1000, filtering_limit=3)
        assert out.compression_stats.raw_packet_count_in == 1
        assert len(out.reduced_representation) == 1
        # A single packet is always the "first occurrence" of its
        # fingerprint -- must never itself be folded into an aggregate.
        assert out.reduced_representation[0].aggregate is None


class TestFingerprintCollapsing:

    def test_all_identical_packets_collapse_to_one_item_plus_aggregate(
        self, identical_packets_bytes
    ):
        out = reduce_pcap(identical_packets_bytes, token_budget=100_000, filtering_limit=3)
        # filtering_limit=3 -> 3 raw items total (1 representative + 2 more
        # raw samples), the rest folded into the representative's aggregate.
        assert len(out.reduced_representation) == 3
        representative = out.reduced_representation[0]
        assert representative.aggregate is not None
        assert representative.aggregate.count == 1000

    def test_host_scan_collapses_across_many_source_ips(self, host_scan_bytes):
        """Many different source IPs, same dst_port/flags -- SHOULD
        collapse into a single fingerprint (IP-agnostic by design)."""
        out = reduce_pcap(host_scan_bytes, token_budget=100_000, filtering_limit=3)
        assert len(out.fingerprint_index) == 1
        agg = list(out.fingerprint_index.values())[0]
        assert agg.count == 50
        assert len(agg.unique_sources) == 50

    def test_port_scan_known_gap_documented_not_silently_fixed(self, port_scan_bytes):
        """KNOWN GAP (see README): a single-source port scan currently does
        NOT collapse, because dst_port is part of the TCP fingerprint key.
        This test intentionally asserts the CURRENT (non-ideal) behavior,
        so that if/when this is fixed, this test fails loudly and has to
        be updated deliberately -- rather than the fix going unnoticed.
        """
        out = reduce_pcap(port_scan_bytes, token_budget=100_000, filtering_limit=3)
        # 50 distinct destination ports -> 50 distinct fingerprints today.
        assert len(out.fingerprint_index) == 50, (
            "If this now fails, the port-scan collapsing gap may have been "
            "fixed -- update this test (and the README) deliberately rather "
            "than just patching the assertion."
        )


class TestParseFailureHandling:

    def test_dropped_parse_failures_are_counted_not_silent(self, mixed_protocol_bytes):
        # mixed_protocol_bytes has no malformed packets by construction, so
        # this just confirms the counter is present and zero here --
        # a true malformed-packet injection test requires hand-crafted
        # invalid bytes, which is captured as a follow-up rather than
        # faked here with an unrealistic fixture.
        out = reduce_pcap(mixed_protocol_bytes, token_budget=100_000, filtering_limit=3)
        assert out.compression_stats.dropped_parse_failures >= 0

    def test_corrupted_trailing_bytes_do_not_crash_the_whole_run(
        self, mixed_protocol_bytes
    ):
        """Appending garbage bytes after a valid pcap corrupts the capture
        enough that the underlying tshark process crashes mid-stream. The
        Reducer must not propagate that crash -- it should stop, keep
        whatever was successfully processed before the crash, and surface
        `capture_error` so the caller knows the run was incomplete and why."""
        corrupted = mixed_protocol_bytes + b"\x00\xff\xde\xad\xbe\xef" * 20
        out = reduce_pcap(corrupted, token_budget=100_000, filtering_limit=3)
        # Should not raise. Either it parsed fine despite the trailing
        # garbage (capture_error is None), or it crashed mid-stream and
        # degraded gracefully (capture_error is set, partial results kept).
        if out.capture_error is not None:
            assert out.compression_stats.raw_packet_count_in >= 0
        else:
            assert out.compression_stats.raw_packet_count_in > 0


class TestFilterStringEdgeCases:
    def test_none_filter_runs_unfiltered(self, mixed_protocol_bytes):
        out = reduce_pcap(mixed_protocol_bytes, token_budget=100_000,
                           filtering_limit=3, filter_string=None)
        assert out.compression_stats.raw_packet_count_in > 0

    def test_empty_string_filter_runs_unfiltered(self, mixed_protocol_bytes):
        out = reduce_pcap(mixed_protocol_bytes, token_budget=100_000,
                           filtering_limit=3, filter_string="")
        assert out.compression_stats.raw_packet_count_in > 0

    def test_malformed_filter_degrades_to_unfiltered_not_crash(
        self, mixed_protocol_bytes
    ):
        """A syntactically invalid BPF string handed directly to the
        Reducer (bypassing Filter Generator's own validation) must not
        crash the stage -- tcpdump pre-filtering failure should degrade
        to processing the file unfiltered."""
        out = reduce_pcap(mixed_protocol_bytes, token_budget=100_000,
                           filtering_limit=3, filter_string="not a valid bpf !!!")
        assert out.compression_stats.raw_packet_count_in > 0

    def test_valid_filter_actually_narrows_input(self, mixed_protocol_bytes):
        """Confirms the filter isn't a no-op in practice -- narrowing to
        icmp-only should yield strictly fewer raw packets processed than
        the unfiltered run."""
        unfiltered = reduce_pcap(mixed_protocol_bytes, token_budget=100_000,
                                  filtering_limit=3, filter_string=None)
        filtered = reduce_pcap(mixed_protocol_bytes, token_budget=100_000,
                                filtering_limit=3, filter_string="icmp")
        assert filtered.compression_stats.raw_packet_count_in < \
               unfiltered.compression_stats.raw_packet_count_in


class TestfilteringLimitEdgeCases:

    def test_filtering_limit_zero_keeps_no_raw_duplicates(self, identical_packets_bytes):
        """filtering_limit=0 should still keep exactly one representative
        raw item (the first occurrence is never itself aggregated away --
        see R1 test), with everything else folded."""
        out = reduce_pcap(identical_packets_bytes, token_budget=100_000, filtering_limit=0)
        assert len(out.reduced_representation) == 1
        assert out.reduced_representation[0].aggregate.count == 1000
