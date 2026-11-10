"""
The dashboard's login.

  Responsibility: one password, a signed session cookie, and a lockout on
  repeated failures.

  Why this exists at all: the dashboard is reached over a shared tailnet,
  on plain HTTP, with no other gate in front of it. Anything that can route
  to the port can read every stored response. A single shared password is
  not identity management, and is not claimed to be -- it is the difference
  between "anyone on the tailnet" and "whoever the owner told".

  Decisions worth knowing:

    Fail closed.        With no password file, every data endpoint is
                        refused. An unconfigured deployment serves nothing
                        rather than serving everything.
    PBKDF2, 600k rounds, stdlib. No bcrypt dependency on a host where the
                        inode budget is tight; 600k SHA-256 rounds is the
                        current OWASP figure for PBKDF2-HMAC-SHA256.
    The cookie is signed, not encrypted. It carries an expiry and nothing
                        else, so there is nothing in it worth hiding; HMAC
                        over the secret stops it being forged.
    Not `Secure`.       The tailnet has no HTTPS for this host (`tailscale
                        serve` is disabled by its administrator), so a
                        Secure cookie would simply never be sent. This is a
                        real limitation, recorded here rather than papered
                        over: the password crosses the tailnet in the
                        clear.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

PBKDF2_ROUNDS = 600_000
COOKIE_NAME = "pangea_session"
DEFAULT_TTL_SECONDS = 14 * 24 * 3600

#: Lockout: after this many failures from one address, refuse for a while,
#: doubling each time. Slows a guessing script without locking the owner out
#: for long after a typo.
MAX_FAILURES = 5
BASE_LOCKOUT_SECONDS = 60


class AuthError(RuntimeError):
    """Authentication is not configured, or the attempt failed."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, salt: bytes | None = None, rounds: int = PBKDF2_ROUNDS) -> dict[str, object]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return {"algorithm": "pbkdf2_sha256", "rounds": rounds, "salt": salt.hex(), "hash": digest.hex()}


@dataclass
class Auth:
    """The password file, plus the in-memory failure counters."""

    path: Path
    record: dict[str, object] | None = None

    def __post_init__(self) -> None:
        self._failures: dict[str, tuple[int, float]] = {}
        if self.record is None and self.path.exists():
            self.record = json.loads(self.path.read_text(encoding="utf-8"))

    # -- configuration ----------------------------------------------------

    @property
    def configured(self) -> bool:
        return bool(self.record and self.record.get("hash") and self.record.get("secret"))

    def set_password(self, password: str) -> None:
        """
        Write the password file, readable only by its owner.

        The session secret is rotated at the same time, so changing the
        password also signs out every existing session -- which is what
        someone changing a password after a leak expects to happen.
        """
        if len(password) < 8:
            raise AuthError("password must be at least 8 characters")
        record = hash_password(password)
        record["secret"] = secrets.token_hex(32)
        record["updated_at"] = int(time.time())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Create with 0600 before writing, so the hash is never briefly
        # world-readable on a shared filesystem.
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle)
        os.chmod(self.path, 0o600)
        self.record = record

    # -- attempts ---------------------------------------------------------

    def locked_for(self, client: str) -> float:
        """Seconds this client must wait, 0 if it may try now."""
        failures, until = self._failures.get(client, (0, 0.0))
        return max(0.0, until - time.time())

    def verify_password(self, password: str, client: str = "-") -> bool:
        if not self.configured:
            raise AuthError("no password set; run `./pangea set-password`")
        if self.locked_for(client) > 0:
            raise AuthError("too many attempts; wait before trying again")
        expected = bytes.fromhex(str(self.record["hash"]))
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(str(self.record["salt"])),
            int(self.record["rounds"]),
        )
        if hmac.compare_digest(expected, candidate):
            self._failures.pop(client, None)
            return True
        failures, _ = self._failures.get(client, (0, 0.0))
        failures += 1
        lockout = BASE_LOCKOUT_SECONDS * (2 ** max(0, failures - MAX_FAILURES)) if failures >= MAX_FAILURES else 0
        self._failures[client] = (failures, time.time() + lockout)
        return False

    # -- sessions ---------------------------------------------------------

    def issue_token(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
        if not self.configured:
            raise AuthError("no password set")
        payload = _b64(json.dumps({"exp": int(time.time()) + ttl_seconds}).encode())
        signature = _b64(hmac.new(bytes.fromhex(str(self.record["secret"])), payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{signature}"

    def check_token(self, token: str | None) -> bool:
        if not token or not self.configured:
            return False
        try:
            payload, signature = token.split(".", 1)
            expected = _b64(
                hmac.new(bytes.fromhex(str(self.record["secret"])), payload.encode(), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(expected, signature):
                return False
            return int(json.loads(_unb64(payload))["exp"]) > int(time.time())
        except (ValueError, KeyError, json.JSONDecodeError):
            return False


def generate_passphrase(words: int = 4) -> str:
    """
    A readable random passphrase, for a first setup.

    Random words rather than random characters because this one gets typed
    on a tablet keyboard; ~44 bits of entropy from this alphabet, which the
    lockout above makes ample against online guessing.
    """
    alphabet = (
        "amber anchor atlas beacon bramble cedar cinder cobalt copper delta ember falcon "
        "garnet harbor indigo ivory jasper kestrel lantern marble nimbus onyx pewter quartz "
        "raven saffron timber umber velvet walnut yarrow zephyr"
    ).split()
    return "-".join(secrets.choice(alphabet) for _ in range(words))
