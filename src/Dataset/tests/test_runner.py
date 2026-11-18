"""
The run.

What is checked: that the plan is reproducible, that re-running can only
fill gaps, that a pause stops cleanly, that a leak refuses the whole run,
that an unconfigured model becomes a stored failure rather than a crash,
and that a dry run costs nothing.
"""
from __future__ import annotations

import pytest

from Dataset.config import CONFIG_DIR, Config, ConfigError
from Dataset.demo import seed_demo
from Dataset.runner import RunPaused, Runner, Unit
from Dataset.storage.db import Database
from Dataset.storage.repository import Repository


@pytest.fixture
def seeded(tmp_path):
    config = Config.load(CONFIG_DIR / "demo")
    seed_demo(db_path=tmp_path / "d.db", results_path=tmp_path / "r.jsonl", config=config)
    db = Database(tmp_path / "d.db")
    yield db, config, tmp_path
    db.close()


@pytest.fixture
def runner(seeded):
    db, config, tmp_path = seeded
    return Runner(db=db, config=config, results_path=tmp_path / "run.jsonl")


# -- planning --------------------------------------------------------------

def test_the_plan_is_every_combination(runner):
    units = runner.plan(models=["mock-a"], prompts=["base", "wording_b"])
    pairs = len(runner.pairs())
    repeats = int(runner.config.get("run.repeats"))
    assert len(units) == pairs * 1 * 2 * repeats


def test_the_plan_is_shuffled_but_reproducible(runner):
    first = runner.plan(models=["mock-a"])
    second = runner.plan(models=["mock-a"])
    assert first == second                      # same seed, same order
    assert first != sorted(first, key=lambda u: (u.pair_id, u.prompt_label, u.repeat))


def test_rejected_and_superseded_claims_never_reach_a_model(runner, seeded):
    db, _, _ = seeded
    from Dataset.review import apply_action

    pair = runner.pairs()[0]
    before = len(runner.pairs())
    apply_action(db, claim_id=pair["claim_id"], action="reject")
    after = {p["pair_id"] for p in runner.pairs()}
    assert pair["pair_id"] not in after
    assert len(after) < before


# -- the leak gate ---------------------------------------------------------

def test_the_leak_gate_passes_on_the_real_prompts(runner):
    assert runner.check_no_leaks(runner.plan(models=["mock-a"], prompts=["base"])) == []


def test_the_leak_gate_catches_a_leaky_claim(runner, seeded):
    db, _, _ = seeded
    # A claim whose own text names the pair type: the template is innocent,
    # the interpolation is not, which is why the gate renders before it runs.
    db.conn.execute("PRAGMA writable_schema = OFF")
    pair = runner.pairs()[0]
    db.conn.execute("DROP TRIGGER claims_no_update")
    db.conn.execute(
        "UPDATE claims SET atomic_text = ? WHERE claim_id = ?",
        ("This claim is a mutation and the expected verdict is REFUTED.", pair["claim_id"]),
    )
    db.conn.commit()
    problems = runner.check_no_leaks(runner.plan(models=["mock-a"], prompts=["base"]))
    assert problems
    kinds = {leak["kind"] for problem in problems for leak in problem["leaks"]}
    assert "pair_type" in kinds


# -- estimates -------------------------------------------------------------

def test_a_dry_run_estimate_calls_nothing_and_admits_it_is_an_estimate(runner):
    units = runner.plan(models=["mock-a"], prompts=["base"])
    estimate = runner.estimate(units)
    assert estimate["units"] == len(units)
    assert estimate["per_model"]["mock-a"]["calls"] == len(units)
    assert estimate["per_model"]["mock-a"]["tokens_in_estimate"] > 0
    assert "estimate" in estimate["note"]
    # No price configured for a mock, so no invented cost.
    assert estimate["per_model"]["mock-a"]["cost_estimate"] is None


# -- running ---------------------------------------------------------------

def test_a_run_stores_a_call_per_unit(runner, seeded):
    db, _, _ = seeded
    units = runner.plan(models=["mock-a"], prompts=["base"])[:6]
    run_id, manifest = runner.create_run(label="test", units=units)
    summary = runner.execute(run_id, units)
    assert summary["calls"] == len(units)
    assert db.one("SELECT COUNT(*) n FROM calls WHERE run_id = ?", (run_id,))["n"] == len(units)
    assert manifest["prompt_set_hash"]


def test_every_call_stores_the_prompt_it_was_sent(runner, seeded):
    db, _, _ = seeded
    units = runner.plan(models=["mock-a"], prompts=["base"])[:3]
    run_id, _ = runner.create_run(label="test", units=units)
    runner.execute(run_id, units)
    for row in db.query("SELECT prompt_rendered FROM calls WHERE run_id = ?", (run_id,)):
        assert "CLAIM:" in row["prompt_rendered"]


def test_re_running_fills_gaps_and_never_duplicates(runner, seeded):
    db, _, _ = seeded
    units = runner.plan(models=["mock-a"], prompts=["base"])[:6]
    run_id, _ = runner.create_run(label="test", units=units)
    runner.execute(run_id, units[:3])
    second = runner.execute(run_id, units)
    assert second["skipped"] == 3 and second["calls"] == 3
    assert db.one("SELECT COUNT(*) n FROM calls WHERE run_id = ?", (run_id,))["n"] == 6


def test_a_paused_run_stops_between_units_and_resumes(runner, seeded):
    db, _, _ = seeded
    units = runner.plan(models=["mock-a"], prompts=["base"])[:8]
    run_id, _ = runner.create_run(label="test", units=units)
    repo = Repository(db)

    def pause_after_two(index, total):
        if index == 2:
            repo.add_run_event(run_id, "paused", "asked to pause")

    with pytest.raises(RunPaused):
        runner.execute(run_id, units, on_progress=pause_after_two)
    stored = db.one("SELECT COUNT(*) n FROM calls WHERE run_id = ?", (run_id,))["n"]
    # It stopped between units, so every stored call is a whole one.
    assert 0 < stored < len(units)
    assert repo.run_status(run_id) == "paused"

    # And a paused run can be resumed: the pause does not latch forever.
    summary = runner.execute(run_id, units)
    assert summary["skipped"] == stored
    assert db.one("SELECT COUNT(*) n FROM calls WHERE run_id = ?", (run_id,))["n"] == len(units)


def test_a_misconfigured_model_is_stored_as_a_failure(runner, seeded, monkeypatch):
    db, config, _ = seeded
    real = Config.load()  # the shipped panel, where the real models are UNSET
    config.models.append(real.model("openai-primary"))
    config.model_raw["openai-primary"] = real.model_raw["openai-primary"]
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    units = [u for u in runner.plan(models=["openai-primary"], prompts=["base"])][:2]
    run_id, _ = runner.create_run(label="test", units=units)
    summary = runner.execute(run_id, units)
    assert summary["failures"] == len(units)
    rows = db.query("SELECT error, format_error FROM calls WHERE run_id = ?", (run_id,))
    # The gap is visible afterwards rather than being a crash at the time.
    assert all(row["error"] and row["format_error"] for row in rows)


def test_a_run_refuses_to_start_with_unset_thresholds(seeded, tmp_path):
    db, _, _ = seeded
    # Without overrides: the packaged config is the pre-registration and
    # keeps its UNSET sentinels. Reading the deployment's overrides here
    # would make this test depend on whatever the dashboard was last set to.
    shipped = Config.load(apply_overrides=False)
    runner = Runner(db=db, config=shipped, results_path=tmp_path / "x.jsonl")
    with pytest.raises(ConfigError, match="before a run"):
        runner.create_run(label="test", units=[Unit("p", "m", "base", 0)])


def test_the_run_id_changes_when_a_threshold_changes(runner, seeded, tmp_path):
    db, config, _ = seeded
    units = runner.plan(models=["mock-a"], prompts=["base"])[:2]
    first, _ = runner.create_run(label="test", units=units)

    changed = Config(
        experiment={**config.experiment,
                    "thresholds": {**config.experiment["thresholds"], "tau_seconds": 99}},
        models=config.models_raw,
    )
    other = Runner(db=db, config=changed, results_path=tmp_path / "y.jsonl")
    second, _ = other.create_run(label="test", units=units)
    assert second != first  # a config change is a new run, not an edit


def test_a_run_registers_the_variants_it_used(runner):
    """
    Without this, a stored run carries prompt ids and nothing else.

    The dashboard's prompt section and the analysis's per-dimension effect
    both key off `prompt_variants`; a run whose variants were never written
    down can only be read as a list of hashes.
    """
    db = runner.db
    units = runner.plan(models=["mock-a"], prompts=["base", "labels_reversed"])
    runner.create_run(label="test", units=units)
    rows = {row["prompt_id"]: dict(row) for row in db.query("SELECT * FROM prompt_variants")}
    for variant in runner.builder.variants:
        stored = rows[runner.builder.prompt_id(variant)]
        assert stored["label"] == variant.label
        assert stored["dimension"] == variant.dimension
        assert stored["prompt_hash"] == runner.builder.prompt_hash(variant)
        assert stored["template"]
    # Registering twice must not fail: the table is append-only, and an id
    # already stored is left exactly as it is.
    assert runner.register_prompt_variants() == 0
