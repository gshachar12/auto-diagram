"""Hashing must be stable across processes, orderings and runs."""
from __future__ import annotations

import hashlib

from Dataset.ids import canonical_json, content_hash, content_id, file_sha256


def test_canonical_json_ignores_key_order():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_canonical_json_keeps_unicode_readable():
    assert "é" in canonical_json({"x": "é"})


def test_content_hash_is_stable_and_sensitive():
    payload = {"filter": "tcp.port == 80", "limit": 50}
    assert content_hash(payload) == content_hash(dict(reversed(list(payload.items()))))
    assert content_hash(payload) != content_hash({**payload, "limit": 51})


def test_content_id_has_a_readable_prefix():
    identifier = content_id("clm", {"text": "a claim"})
    prefix, digest = identifier.split("_")
    assert prefix == "clm" and len(digest) == 12


def test_file_sha256_matches_hashlib(tmp_path):
    path = tmp_path / "blob.bin"
    payload = b"x" * (3 << 20)  # larger than one read chunk
    path.write_bytes(payload)
    assert file_sha256(path) == hashlib.sha256(payload).hexdigest()
