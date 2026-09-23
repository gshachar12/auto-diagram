"""
Unit tests for src/preprocessing/filter_generator.py.

The LLM path is tested with a fake `llm_client` callable, matching the
LLMClient abstraction (prompt -> response text) -- no real API key or
network call is needed for any of these.
"""
import sys
sys.path.insert(0, "src")

from filter_generator import (
    generate_filter, NO_OP_FILTER, _generate_via_keywords, _is_valid_bpf,
)


class TestEmptyDescription:

    def test_empty_string_returns_no_op_filter(self):
        assert generate_filter("") == NO_OP_FILTER

    def test_whitespace_only_returns_no_op_filter(self):
        assert generate_filter("   \n\t  ") == NO_OP_FILTER

    def test_none_like_falls_back_safely(self):
        assert generate_filter(None) == NO_OP_FILTER


class TestLLMBackedGeneration:

    def test_valid_llm_response_is_used(self):
        fake_client = lambda prompt: "tcp port 443"
        result = generate_filter("some description", llm_client=fake_client)
        assert result == "tcp port 443"

    def test_llm_response_with_markdown_wrapping_is_cleaned(self):
        fake_client = lambda prompt: "`tcp port 443`"
        result = generate_filter("some description", llm_client=fake_client)
        assert result == "tcp port 443"

    def test_llm_response_with_prefix_label_is_cleaned(self):
        fake_client = lambda prompt: "BPF filter: tcp port 443"
        result = generate_filter("some description", llm_client=fake_client)
        assert result == "tcp port 443"

    def test_llm_exception_falls_back_to_no_op(self):
        def failing_client(prompt):
            raise RuntimeError("simulated API failure")
        result = generate_filter("some description", llm_client=failing_client)
        assert result == NO_OP_FILTER

    def test_llm_returns_syntactically_invalid_bpf_falls_back_to_no_op(self):
        fake_client = lambda prompt: "this is not a bpf filter at all!!"
        result = generate_filter("some description", llm_client=fake_client)
        assert result == NO_OP_FILTER

    def test_llm_returns_empty_string_falls_back_to_no_op(self):
        fake_client = lambda prompt: ""
        result = generate_filter("some description", llm_client=fake_client)
        assert result == NO_OP_FILTER


class TestKeywordFallback:

    def test_no_keyword_match_returns_no_op_filter(self):
        result = _generate_via_keywords("nothing recognizable here at all")
        assert result == NO_OP_FILTER

    def test_single_keyword_match(self):
        result = _generate_via_keywords("the attacker used ssh to connect")
        assert "tcp port 22" in result

    def test_dns_and_tunneling_synonyms_both_match_same_fragment(self):
        r1 = _generate_via_keywords("suspected dns exfiltration")
        r2 = _generate_via_keywords("suspected tunneling activity")
        assert "port 53" in r1
        assert "port 53" in r2

    def test_multiple_keyword_matches_combine_with_or(self):
        result = _generate_via_keywords(
            "the attacker performed a scan, then used ssh, then queried dns"
        )
        assert " or " in result
        assert "tcp port 22" in result
        assert "port 53" in result

    def test_result_is_valid_bpf(self):
        result = _generate_via_keywords("port scan via ssh and dns tunneling")
        assert _is_valid_bpf(result)

    def test_generate_filter_without_llm_client_uses_keyword_fallback(self):
        result = generate_filter("the attacker used ssh")
        assert "tcp port 22" in result


class TestBPFValidation:

    def test_valid_simple_filter(self):
        assert _is_valid_bpf("tcp") is True

    def test_valid_compound_filter(self):
        assert _is_valid_bpf("(tcp port 443) or (udp port 53)") is True

    def test_invalid_garbage_filter(self):
        assert _is_valid_bpf("this is definitely not bpf syntax !!!") is False

    def test_empty_string_is_invalid(self):
        assert _is_valid_bpf("") is False
