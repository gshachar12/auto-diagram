"""
The dashboard's login.

The dashboard sits on a shared tailnet with no HTTPS, so these tests care
about the two things that actually keep people out: the server refuses to
serve data without a valid session, and it refuses to serve data at all
when no password has been set.
"""
from __future__ import annotations

import json
import shutil
import time

import pytest
from fastapi.testclient import TestClient

from Dataset.config import CONFIG_DIR, Config
from Dataset.demo import seed_demo
from Dataset.web.app import create_app
from Dataset.web.auth import COOKIE_NAME, Auth, AuthError, generate_passphrase

PASSWORD = "correct-horse-battery"


@pytest.fixture
def auth(tmp_path) -> Auth:
    return Auth(tmp_path / "auth.json")


@pytest.fixture
def client(tmp_path, monkeypatch):
    seed_demo(
        db_path=tmp_path / "dataset.db",
        results_path=tmp_path / "results.jsonl",
        config=Config.load(CONFIG_DIR / "demo"),
    )
    monkeypatch.setenv("PANGEA_DATA_DIR", str(tmp_path))
    store = Auth(tmp_path / "auth.json")
    return TestClient(create_app(store)), store


# -- the password file ----------------------------------------------------

def test_a_fresh_install_has_no_password(auth):
    assert auth.configured is False
    with pytest.raises(AuthError, match="no password set"):
        auth.verify_password(PASSWORD)


def test_setting_a_password_writes_an_owner_only_file(auth):
    auth.set_password(PASSWORD)
    assert auth.configured
    assert oct(auth.path.stat().st_mode & 0o777) == "0o600"


def test_the_password_itself_is_never_stored(auth):
    auth.set_password(PASSWORD)
    stored = auth.path.read_text()
    assert PASSWORD not in stored
    record = json.loads(stored)
    assert record["algorithm"] == "pbkdf2_sha256" and record["rounds"] >= 600_000


def test_a_short_password_is_refused(auth):
    with pytest.raises(AuthError, match="at least 8"):
        auth.set_password("short")


def test_verification_accepts_only_the_right_password(auth):
    auth.set_password(PASSWORD)
    assert auth.verify_password(PASSWORD) is True
    assert auth.verify_password(PASSWORD.upper()) is False


def test_changing_the_password_invalidates_existing_sessions(auth):
    auth.set_password(PASSWORD)
    token = auth.issue_token()
    assert auth.check_token(token)
    auth.set_password("a-different-password")
    # The session secret rotates with the password, which is what someone
    # changing a password after a leak expects to happen.
    assert auth.check_token(token) is False


# -- tokens ---------------------------------------------------------------

def test_a_token_round_trips(auth):
    auth.set_password(PASSWORD)
    assert auth.check_token(auth.issue_token()) is True


def test_a_tampered_token_is_rejected(auth):
    auth.set_password(PASSWORD)
    token = auth.issue_token()
    payload, signature = token.split(".")
    assert auth.check_token(f"{payload}.{signature[:-2]}xy") is False
    assert auth.check_token(f"{payload}xx.{signature}") is False


def test_an_expired_token_is_rejected(auth):
    auth.set_password(PASSWORD)
    assert auth.check_token(auth.issue_token(ttl_seconds=-1)) is False


def test_rubbish_is_rejected_without_raising(auth):
    auth.set_password(PASSWORD)
    for rubbish in ("", "no-dot", "a.b", "...", None):
        assert auth.check_token(rubbish) is False


# -- lockout ---------------------------------------------------------------

def test_repeated_failures_lock_the_client_out(auth):
    auth.set_password(PASSWORD)
    for _ in range(5):
        auth.verify_password("wrong", client="10.0.0.9")
    assert auth.locked_for("10.0.0.9") > 0
    with pytest.raises(AuthError, match="too many attempts"):
        auth.verify_password(PASSWORD, client="10.0.0.9")


def test_a_lockout_is_per_client(auth):
    auth.set_password(PASSWORD)
    for _ in range(5):
        auth.verify_password("wrong", client="10.0.0.9")
    assert auth.locked_for("10.0.0.10") == 0
    assert auth.verify_password(PASSWORD, client="10.0.0.10") is True


def test_a_success_clears_the_failure_count(auth):
    auth.set_password(PASSWORD)
    auth.verify_password("wrong", client="c")
    auth.verify_password(PASSWORD, client="c")
    for _ in range(4):
        auth.verify_password("wrong", client="c")
    assert auth.locked_for("c") == 0  # the counter restarted


# -- the endpoints ---------------------------------------------------------

def test_without_a_password_the_server_serves_no_data(client):
    api, _ = client
    response = api.get("/api/overview")
    assert response.status_code == 503
    assert response.json()["configured"] is False
    assert "set-password" in response.json()["detail"]


def test_the_page_itself_stays_public(client):
    api, _ = client
    # It is an empty shell that fetches everything through the gated API,
    # so serving it unauthenticated gives nothing away.
    assert api.get("/").status_code == 200
    assert api.get("/healthz").status_code == 200


@pytest.mark.parametrize(
    "path", ["/api/overview", "/api/claims", "/api/sources", "/api/panel", "/api/export/claims.csv"]
)
def test_every_data_endpoint_needs_a_session(client, path):
    api, store = client
    store.set_password(PASSWORD)
    assert api.get(path).status_code == 401


def test_signing_in_opens_the_data_endpoints(client):
    api, store = client
    store.set_password(PASSWORD)
    assert api.post("/api/login", json={"password": "wrong"}).status_code == 401
    assert api.get("/api/overview").status_code == 401

    assert api.post("/api/login", json={"password": PASSWORD}).status_code == 200
    assert api.cookies.get(COOKIE_NAME)
    assert api.get("/api/overview").status_code == 200
    assert api.get("/api/sources").status_code == 200


def test_the_session_cookie_is_http_only(client):
    api, store = client
    store.set_password(PASSWORD)
    response = api.post("/api/login", json={"password": PASSWORD})
    assert "httponly" in response.headers["set-cookie"].lower()


def test_signing_out_closes_them_again(client):
    api, store = client
    store.set_password(PASSWORD)
    api.post("/api/login", json={"password": PASSWORD})
    api.post("/api/logout")
    assert api.get("/api/overview").status_code == 401


def test_the_lockout_is_reported_as_429(client):
    api, store = client
    store.set_password(PASSWORD)
    for _ in range(5):
        api.post("/api/login", json={"password": "wrong"})
    assert api.post("/api/login", json={"password": PASSWORD}).status_code == 429


def test_the_session_endpoint_describes_the_state(client):
    api, store = client
    assert api.get("/api/session").json() == {"configured": False, "authenticated": False}
    store.set_password(PASSWORD)
    assert api.get("/api/session").json() == {"configured": True, "authenticated": False}
    api.post("/api/login", json={"password": PASSWORD})
    assert api.get("/api/session").json() == {"configured": True, "authenticated": True}


def test_generated_passphrases_differ(auth):
    assert generate_passphrase() != generate_passphrase()
    assert len(generate_passphrase().split("-")) == 4
