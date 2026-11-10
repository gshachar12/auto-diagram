"""
Content hashing and identifiers.

  Responsibility: one canonical way to hash a payload and one way to derive
  an id from it. Everything that must be traceable later -- a config, a
  rendered prompt, a PCAP file, a run manifest -- is hashed here, so two
  components never disagree about what "the hash" of something is.

  Ids are content-derived (`clm_9f2a...`) rather than sequential: the same
  claim built twice yields the same id, which is what makes a seeded demo
  dataset reproducible and makes idempotent run keys possible. The prefix is
  cosmetic -- it makes a stray id in a log self-describing.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

#: Length of the hex digest kept in an id. 12 hex chars = 48 bits; with the
#: dataset's expected size (<1e5 objects per kind) a collision is ~1e-9.
ID_DIGEST_LEN = 12

_HASH_READ_CHUNK = 1 << 20


def canonical_json(payload: Any) -> str:
    """
    Serialize a payload so that equal payloads always produce equal bytes.

    Sorted keys, no insignificant whitespace, UTF-8 preserved rather than
    escaped. Used for every hash so a dict's construction order can never
    change a hash.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def content_hash(payload: Any) -> str:
    """Full sha256 of a payload's canonical JSON."""
    return sha256_hex(canonical_json(payload))


def content_id(prefix: str, payload: Any) -> str:
    """A short, stable, content-derived id, e.g. `pair_3f91c0a28b17`."""
    return f"{prefix}_{content_hash(payload)[:ID_DIGEST_LEN]}"


def event_id(prefix: str) -> str:
    """
    A unique id for a log entry.

    Deliberately NOT content-derived. Events repeat: two mutations of the
    same claim can be discarded for the same reason in the same second, and
    hashing (kind, ref, reason, timestamp) then produces the same id twice
    and the second insert fails. That happened on the first real pair
    build. An event is an occurrence, not a value, so it gets an identity
    of its own.
    """
    return f"{prefix}_{uuid.uuid4().hex[:ID_DIGEST_LEN]}"


def file_sha256(path: str | Path) -> str:
    """
    Hash a file's bytes, streamed.

    PCAPs can be tens of megabytes, and a capture's hash goes into every run
    manifest, so this is read in chunks rather than loaded whole.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_HASH_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
