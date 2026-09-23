"""
Integration tests: the full Preprocessing stage (Filter Generator -> Reducer)
wired together via preprocessor.py, both as a library call and via the CLI.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")

from preprocessor import run_preprocessing, reducer_output_to_dict
from schemas import BudgetStatus


class TestRunPreprocessingLibraryCall:

    def test_description_actually_narrows_what_reducer_sees(self, mixed_protocol_bytes):
        """Confirms Filter Generator's output is genuinely wired into the
        Reducer -- not just 'runs without error'. A description that maps
        to an icmp-only filter should yield fewer raw packets processed
        than an empty description (no-op filter)."""
        with_description = run_preprocessing(
            pcap_bytes=mixed_protocol_bytes,
            attack_description="the host sent icmp ping requests",
            token_budget=100_000,
        )
        without_description = run_preprocessing(
            pcap_bytes=mixed_protocol_bytes,
            attack_description="",
            token_budget=100_000,
        )
        assert with_description.filter_string_used != without_description.filter_string_used
        assert with_description.compression_stats.raw_packet_count_in <= \
               without_description.compression_stats.raw_packet_count_in

    def test_output_is_json_serializable(self, mixed_protocol_bytes):
        out = run_preprocessing(
            pcap_bytes=mixed_protocol_bytes,
            attack_description="a port scan followed by an https session",
            token_budget=100_000,
        )
        d = reducer_output_to_dict(out)
        json_str = json.dumps(d)  # must not raise
        assert len(json_str) > 0
        assert d["budget_status"] in (s.value for s in BudgetStatus)

    def test_r2_holds_end_to_end(self, mixed_protocol_bytes):
        """The description is never forwarded into the Reducer's own
        output in any recognizable form -- spot-check that the raw
        description text does not leak verbatim into reduced items' info
        strings (a weak but useful smoke check for R2 in practice)."""
        distinctive_description = "XYZZY_UNIQUE_MARKER_STRING attack description"
        out = run_preprocessing(
            pcap_bytes=mixed_protocol_bytes,
            attack_description=distinctive_description,
            token_budget=100_000,
        )
        for item in out.reduced_representation:
            assert "XYZZY_UNIQUE_MARKER_STRING" not in item.info


class TestCLI:

    def test_cli_runs_and_produces_valid_json_output(self, mixed_protocol_bytes, tmp_path):
        pcap_path = tmp_path / "test.pcap"
        pcap_path.write_bytes(mixed_protocol_bytes)
        output_path = tmp_path / "output.json"

        result = subprocess.run(
            [
                sys.executable, "-m", "preprocessor",
                str(pcap_path),
                "--description", "a port scan against the victim",
                "--token-budget", "100000",
                "-o", str(output_path),
            ],
            cwd="src",
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert output_path.exists()

        data = json.loads(output_path.read_text())
        assert "reduced_representation" in data
        assert "fingerprint_index" in data
        assert "budget_status" in data

    def test_cli_missing_pcap_file_exits_nonzero(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "preprocessor", "/nonexistent/file.pcap"],
            cwd="src",
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr.lower()

    def test_cli_description_file_option(self, mixed_protocol_bytes, tmp_path):
        pcap_path = tmp_path / "test.pcap"
        pcap_path.write_bytes(mixed_protocol_bytes)
        desc_path = tmp_path / "description.txt"
        desc_path.write_text("dns queries were observed")
        output_path = tmp_path / "output.json"

        result = subprocess.run(
            [
                sys.executable, "-m", "preprocessor",
                str(pcap_path),
                "--description-file", str(desc_path),
                "-o", str(output_path),
            ],
            cwd="src",
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert output_path.exists()
