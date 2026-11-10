"""
Prompt variants and the leak test.

The leak test is the one that matters: if a solver can read the answer out
of its own prompt, every number downstream is meaningless.
"""
from __future__ import annotations

import pytest

from Dataset.prompts import PromptBuilder, scan_for_leaks
from Dataset.prompts.leaks import assert_clean

CAPTURE = {
    "packet_count": 29,
    "size_bytes": 2228,
    "closed_world": {"vantage_point": "at the scanned host", "both_directions": None, "known_gaps": []},
}
CLAIM = "A single source sends TCP SYN packets to at least 10 distinct ports of one host."


@pytest.fixture
def builder() -> PromptBuilder:
    return PromptBuilder()


def _render(builder, label, **kwargs):
    return builder.render(builder.variant(label), claim_text=CLAIM, capture=CAPTURE, **kwargs)


# -- the variant set -------------------------------------------------------

def test_there_are_several_variants_and_one_control(builder):
    labels = {v.label for v in builder.variants}
    assert 4 <= len(labels) <= 6
    assert "control_no_criteria" in labels


def test_each_variant_changes_exactly_one_dimension(builder):
    base = builder.variant("base")
    for variant in builder.variants:
        if variant.label == "base":
            continue
        differing = [
            field for field in ("role", "criteria_style", "label_order", "wording")
            if getattr(variant, field) != getattr(base, field)
        ]
        assert len(differing) == 1, f"{variant.label} changes {differing}"


def test_the_criteria_text_is_identical_wherever_it_appears(builder):
    rendered = {v.label: _render(builder, v.label).system for v in builder.variants}
    with_criteria = [text for label, text in rendered.items() if label != "control_no_criteria"]
    # Every variant that has criteria contains the criteria verbatim; only
    # the wrapping differs.
    for text in with_criteria:
        assert builder.criteria in text or builder.criteria in text.replace("<criteria>\n", "").replace("\n</criteria>", "")


def test_the_control_variant_has_no_criteria(builder):
    control = _render(builder, "control_no_criteria").system
    assert "Executable condition" not in control
    assert "pcap_query" in control  # it still gets the tool and the schema


def test_label_order_is_respected(builder):
    reversed_labels = _render(builder, "labels_reversed").system
    first = reversed_labels.index("NOT_VERIFIABLE")
    assert first < reversed_labels.index('"SUPPORTED"')


def test_every_variant_has_a_distinct_stable_hash(builder):
    hashes = {builder.prompt_hash(v) for v in builder.variants}
    assert len(hashes) == len(builder.variants)
    assert builder.prompt_hash(builder.variant("base")) == PromptBuilder().prompt_hash(builder.variant("base"))


def test_editing_the_criteria_changes_every_hash(builder, tmp_path):
    (tmp_path / "criteria.md").write_text(builder.criteria + "\nAn extra rule.", encoding="utf-8")
    (tmp_path / "variants.yaml").write_text(
        (PromptBuilder.__init__.__globals__["PROMPT_DIR"] / "variants.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    other = PromptBuilder(tmp_path)
    assert other.set_hash != builder.set_hash
    assert other.prompt_hash(other.variant("base")) != builder.prompt_hash(builder.variant("base"))


# -- what a prompt contains ------------------------------------------------

def test_the_prompt_carries_the_claim_the_capture_and_the_schema(builder):
    rendered = _render(builder, "base", thresholds={"quantity": {"many": 10}})
    assert CLAIM in rendered.user
    assert "closed_world" in rendered.user  # absence claims are judged against it
    assert "PARAMETERS" in rendered.user
    assert "verdict" in rendered.system and "reason_code" in rendered.system


def test_an_item_with_no_capture_says_so_plainly(builder):
    rendered = builder.render(builder.variant("base"), claim_text=CLAIM, capture=None)
    assert "No packet capture is available" in rendered.user


def test_the_capture_view_hides_the_file_name_and_the_source():
    view = PromptBuilder.capture_view(
        {"path": "pcaps/datasets/Gotham-2025/mirai-infection_city-power.pcap", "packet_count": 10,
         "size_bytes": 1, "capture_metadata": {"vantage_point": "v", "both_directions": True}}
    )
    # A file named mirai-infection would answer half the question by itself.
    assert "mirai" not in str(view).lower()
    assert view["closed_world"]["both_directions"] is True


# -- the leak test ---------------------------------------------------------

@pytest.mark.parametrize("label", ["base", "wording_b", "structure_xml", "role_analyst",
                                   "labels_reversed", "control_no_criteria"])
def test_no_variant_leaks(builder, label):
    rendered = _render(builder, label)
    assert_clean(
        rendered.full_text,
        expected="SUPPORTED",
        pair_type="mutation",
        source_title="Gotham Dataset 2025 — attack steps + sample pcaps",
    )


def test_the_scanner_catches_an_expected_verdict():
    leaks = scan_for_leaks("The expected verdict is SUPPORTED.", expected="SUPPORTED")
    assert any(leak.kind == "expected_verdict" for leak in leaks)


def test_the_scanner_catches_expectation_language_even_without_a_verdict():
    assert any(leak.kind == "expectation_language" for leak in scan_for_leaks("The correct answer is below."))


@pytest.mark.parametrize("text", [
    "This claim is a mutation of another claim.",
    "This is a swapped capture.",
    "pair type: no_pcap",
])
def test_the_scanner_catches_the_pair_type(text):
    assert any(leak.kind == "pair_type" for leak in scan_for_leaks(text))


def test_the_scanner_catches_provenance():
    assert any(leak.kind == "provenance" for leak in scan_for_leaks("provenance: human, supersedes clm_1"))


def test_the_scanner_catches_the_source():
    leaks = scan_for_leaks("From the Gotham Dataset 2025 paper.", source_title="Gotham Dataset 2025")
    assert any(leak.kind == "source" for leak in leaks)


def test_the_scanner_catches_a_cluster():
    assert any(leak.kind == "cluster" for leak in scan_for_leaks("See cluster 4 from the preprocessor."))


def test_the_verdict_vocabulary_alone_is_not_a_leak(builder):
    # The model has to be told the three allowed answers; that is not a
    # hint about this item.
    rendered = _render(builder, "base")
    assert "SUPPORTED" in rendered.system
    assert scan_for_leaks(rendered.full_text, expected="SUPPORTED") == []
