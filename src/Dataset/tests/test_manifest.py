"""
A manifest is what makes a number traceable months later, so what it must
contain, and what must change it, is worth pinning down.
"""
from __future__ import annotations

from Dataset.config import Config
from Dataset.manifest import build_manifest, git_commit, pcap_fingerprint

PCAPS = [{"pcap_id": "pcap_1", "sha256": "abc123", "packet_count": 29}]
PROMPTS = [{"prompt_id": "prm_1", "prompt_hash": "deadbeef"}]
MODELS = [{"model_id": "m1", "family": "f", "version": "v1", "temperature": 0.0, "supports_tools": True}]


def _manifest(config: Config):
    return build_manifest(config=config, pcaps=PCAPS, prompts=PROMPTS, models=MODELS, label="test")


def test_manifest_records_everything_that_can_change_a_result(demo_config):
    _, manifest = _manifest(demo_config)
    assert manifest["code"]["git_commit"]
    assert manifest["config"]["config_hash"] == demo_config.config_hash
    assert manifest["config"]["thresholds"]["delta_seconds"] is not None
    assert manifest["pcaps"][0]["sha256"] == "abc123"
    assert manifest["prompts"][0]["prompt_hash"] == "deadbeef"
    assert manifest["models"][0]["version"] == "v1"


def test_run_id_is_stable_for_identical_inputs(demo_config):
    assert _manifest(demo_config)[0] == _manifest(demo_config)[0]


def test_changing_a_threshold_produces_a_different_run(demo_config):
    before, _ = _manifest(demo_config)
    changed = Config(
        experiment={**demo_config.experiment, "thresholds": {**demo_config.experiment["thresholds"], "tau_seconds": 42}},
        models=demo_config.models_raw,
    )
    assert _manifest(changed)[0] != before


def test_changing_a_capture_produces_a_different_run(demo_config):
    before, _ = _manifest(demo_config)
    other, _ = build_manifest(
        config=demo_config,
        pcaps=[{"pcap_id": "pcap_1", "sha256": "0000", "packet_count": 29}],
        prompts=PROMPTS, models=MODELS, label="test",
    )
    assert other != before


def test_git_commit_marks_an_uncommitted_tree(tmp_path):
    # An unknown repo must say UNKNOWN rather than pretend to be clean.
    assert git_commit(tmp_path) == "UNKNOWN"


def test_pcap_fingerprint_reads_a_real_capture():
    fingerprint = pcap_fingerprint("pcaps/PortScanning/portscan.pcap")
    assert len(fingerprint["sha256"]) == 64
    assert fingerprint["size_bytes"] > 0
