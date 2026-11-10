"""
The pre-registered parameters, and the control that moves them.

A dashboard slider that edits thresholds looks like exactly the wrong thing
to build, so these tests pin down the three properties that make it
defensible: a change cannot touch a finished run, every change is recorded
with how many runs already had results, and a run still refuses to start
while anything is UNSET.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from Dataset.config import CONFIG_DIR, Config, ConfigError, set_override
from Dataset.demo import seed_demo
from Dataset.parameters import BY_PATH, PARAMETERS, change_log, record_change, runs_with_results
from Dataset.storage.db import Database
from Dataset.web.app import create_app
from Dataset.web.auth import Auth

PASSWORD = "parameters-test-password"


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PANGEA_DATA_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def client(data_dir):
    seed_demo(
        db_path=data_dir / "dataset.db",
        results_path=data_dir / "results.jsonl",
        config=Config.load(CONFIG_DIR / "demo", apply_overrides=False),
    )
    Database(data_dir / "dataset.db").initialise().close()
    store = Auth(data_dir / "auth.json")
    store.set_password(PASSWORD)
    api = TestClient(create_app(store))
    api.post("/api/login", json={"password": PASSWORD})
    return api


# -- the definitions -------------------------------------------------------

def test_every_spec_threshold_has_a_control():
    paths = {p.path for p in PARAMETERS}
    assert paths == {
        "thresholds.delta_seconds", "thresholds.tau_seconds",
        "thresholds.quantity.many", "thresholds.quantity.thousands",
        "thresholds.equivalence_margin.flip_rate", "thresholds.equivalence_margin.accuracy_points",
    }


def test_every_control_explains_what_it_does():
    for parameter in PARAMETERS:
        assert parameter.help and len(parameter.help) > 40
        assert parameter.minimum < parameter.maximum and parameter.step > 0


# -- overrides -------------------------------------------------------------

def test_an_override_fills_an_unset_threshold(data_dir):
    before = Config.load()
    assert "thresholds.tau_seconds" in before.unset()
    set_override("thresholds.tau_seconds", 2.0)
    after = Config.load()
    assert after.get("thresholds.tau_seconds") == 2.0
    assert "thresholds.tau_seconds" not in after.unset()


def test_an_override_changes_the_config_hash(data_dir):
    before = Config.load().config_hash
    set_override("thresholds.delta_seconds", 0.05)
    assert Config.load().config_hash != before


def test_the_packaged_config_keeps_its_sentinels(data_dir):
    # The shipped file is the pre-registration and stays UNSET in git; the
    # override is this deployment's intent, and lives in the data directory.
    set_override("thresholds.delta_seconds", 0.05)
    assert "thresholds.delta_seconds" in Config.load(apply_overrides=False).unset()
    assert (data_dir / "config_overrides.json").exists()


def test_a_run_still_refuses_while_anything_is_unset(data_dir):
    set_override("thresholds.delta_seconds", 0.05)
    with pytest.raises(ConfigError, match="before a run"):
        Config.load().require_frozen()


def test_setting_everything_makes_the_config_runnable(data_dir):
    for parameter in PARAMETERS:
        set_override(parameter.path, parameter.minimum + parameter.step)
    Config.load().require_frozen()


# -- the change log --------------------------------------------------------

def test_a_change_records_how_many_runs_already_had_results(db):
    record_change(db, path="thresholds.tau_seconds", old_value="UNSET", new_value=2.0,
                  config_hash_before="a", config_hash_after="b")
    entry = change_log(db)[0]
    assert entry["old_value"] == "UNSET" and entry["new_value"] == "2.0"
    assert entry["runs_existing"] == 0


def test_the_change_log_is_append_only(db):
    import sqlite3

    record_change(db, path="thresholds.tau_seconds", old_value=None, new_value=1.0,
                  config_hash_before="a", config_hash_after="b")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn.execute("UPDATE config_changes SET new_value = '99'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn.execute("DELETE FROM config_changes")


# -- the endpoints ---------------------------------------------------------

def test_the_api_reports_every_parameter_with_its_range(client):
    payload = client.get("/api/parameters").json()
    assert len(payload["parameters"]) == len(PARAMETERS)
    for entry in payload["parameters"]:
        assert entry["path"] in BY_PATH
        assert entry["min"] < entry["max"]
    assert payload["runs_with_results"] >= 1  # the demo run is in this database


def test_setting_a_parameter_is_applied_and_logged(client):
    response = client.post(
        "/api/parameters", json={"values": {"thresholds.quantity.many": 10}, "note": "pilot values"}
    )
    assert response.status_code == 200
    assert response.json()["changed"] == [{"path": "thresholds.quantity.many", "from": "UNSET", "to": 10}]

    payload = client.get("/api/parameters").json()
    assert next(p for p in payload["parameters"] if p["path"] == "thresholds.quantity.many")["value"] == 10
    entry = payload["changes"][0]
    assert entry["note"] == "pilot values"
    # The number that matters: results already existed when this was moved.
    assert entry["runs_existing"] >= 1


def test_a_value_outside_the_range_is_refused(client):
    assert client.post("/api/parameters", json={"values": {"thresholds.quantity.many": 99999}}).status_code == 400
    assert client.post("/api/parameters", json={"values": {"thresholds.quantity.many": 0}}).status_code == 400


def test_an_unknown_parameter_is_refused(client):
    assert client.post("/api/parameters", json={"values": {"thresholds.made_up": 1}}).status_code == 400


def test_a_non_numeric_value_is_refused(client):
    assert client.post("/api/parameters", json={"values": {"thresholds.tau_seconds": "soon"}}).status_code == 400


def test_an_empty_request_is_refused(client):
    assert client.post("/api/parameters", json={"values": {}}).status_code == 400


def test_parameters_need_a_session(data_dir):
    store = Auth(data_dir / "auth.json")
    store.set_password(PASSWORD)
    api = TestClient(create_app(store))
    assert api.get("/api/parameters").status_code == 401
    assert api.post("/api/parameters", json={"values": {"thresholds.tau_seconds": 2}}).status_code == 401


def test_changing_a_threshold_does_not_touch_a_stored_run(client, data_dir):
    db = Database(data_dir / "dataset.db")
    before = [dict(row) for row in db.query("SELECT run_id, manifest FROM runs")]
    # Deliberately unlike the demo config's own 2.0, so the assertion below
    # distinguishes "the manifest kept its value" from "both happen to match".
    client.post("/api/parameters", json={"values": {"thresholds.tau_seconds": 7.5}})
    after = [dict(row) for row in db.query("SELECT run_id, manifest FROM runs")]
    db.close()
    # The finished run keeps its own thresholds in its own manifest.
    assert before == after
    assert json.loads(after[0]["manifest"])["config"]["thresholds"]["tau_seconds"] == 2.0
    assert Config.load().get("thresholds.tau_seconds") == 7.5
