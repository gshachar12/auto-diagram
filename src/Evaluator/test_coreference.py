"""
Regression test: validates MUC/B-cubed/CEAF against the exact hand-worked
fragmentation example from the design discussion. Run with:
    python3 -m pytest test_coreference.py -v
or directly:
    python3 test_coreference.py
"""
from evaluator.coreference_metrics import muc_score, b_cubed_score, ceaf_score


def test_fragmentation_example():
    # gold A = {kali, the_attacker, kali_host} (indices 0,1,2) -- ONE real entity
    # gold B = {victim} (index 3); gold C = {gateway} (index 4)
    # system fragments A into two clusters: {0,1} and {2}
    gold_clusters = [{0, 1, 2}, {3}, {4}]
    system_clusters = [{0, 1}, {2}, {3}, {4}]

    muc = muc_score(system_clusters, gold_clusters)
    bcubed = b_cubed_score(system_clusters, gold_clusters)
    ceaf = ceaf_score(system_clusters, gold_clusters)

    assert abs(muc.f1 - 0.667) < 0.01, f"MUC F1 mismatch: {muc.f1}"
    assert abs(bcubed.f1 - 0.846) < 0.01, f"B-cubed F1 mismatch: {bcubed.f1}"
    assert abs(ceaf.f1 - 0.8) < 0.01, f"CEAF F1 mismatch: {ceaf.f1}"
    print("PASS: all three metrics match the hand-worked example")


def test_perfect_match():
    clusters = [{0, 1}, {2}]
    for name, fn in [("MUC", muc_score), ("B-cubed", b_cubed_score), ("CEAF", ceaf_score)]:
        score = fn(clusters, clusters)
        assert abs(score.f1 - 1.0) < 1e-9, f"{name} should be 1.0 on identical clusters, got {score.f1}"
    print("PASS: all three metrics correctly score 1.0 on identical clusters")


if __name__ == "__main__":
    test_fragmentation_example()
    test_perfect_match()
    print("\nAll regression tests passed.")
