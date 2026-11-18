"""
The PCAP service.

  Responsibility: the single place that runs tshark. The extraction agent,
  the pair validator, the solver models' tool and the analysis all go
  through here, so a capture is read one way and the safety rules are
  written once.

  Threat model. The display filter is attacker-controlled in the one case
  that matters: it is whatever a solver model decided to write. So:

    No shell, ever.      tshark is invoked with an argument list. There is
                         no string to escape, so there is nothing for `;`,
                         backticks or `$( )` to break out of.
    Filters are compiled, not inspected. Instead of guessing which
                         characters are dangerous with a denylist, the
                         filter is handed to tshark to compile; if tshark
                         rejects it, so do we. A filter is also refused if
                         it looks like an option (`-r`, `--version`), since
                         an argument starting with `-` would be read as a
                         flag rather than a filter.
    Captures live in a jail. A path is resolved (symlinks included) and must
                         land inside one of the configured roots. Opening
                         /etc/passwd, or a symlink pointing at it, fails.
    Everything is bounded. Wall-clock timeout, a cap on bytes read from
                         tshark and a cap on packets returned. A query over
                         a million-packet capture returns a truncated result
                         that says it is truncated; it does not return a
                         gigabyte or hang.

  Determinism and caching: tshark emits packets in file order, so a query is
  reproducible, and results are cached by (capture sha256, filter, limit) --
  by content, not by path, so two names for the same bytes share a cache
  entry and an edited file never hits a stale one.
"""
from __future__ import annotations

import atexit
import os
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..ids import content_hash, file_sha256
from ..storage.db import Database
from ..storage.repository import utc_now

#: Fields returned for each matching packet, in this order. `frame.len` is
#: here because a packet table without a length is hard to read: a 1514-byte
#: frame and a bare ACK look the same otherwise.
PACKET_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "_ws.col.Source",
    "_ws.col.Destination",
    "_ws.col.Protocol",
    "frame.len",
    "_ws.col.Info",
)

MAX_FILTER_LENGTH = 2048

#: A 24-byte libpcap file header with no packets: a capture tshark will
#: happily open and find nothing in. Filters are compiled against this, so a
#: valid filter exits 0 and an invalid one exits non-zero -- which makes the
#: exit status the verdict, instead of us pattern-matching tshark's prose.
_EMPTY_PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
_empty_capture_path: str | None = None


def _empty_capture() -> str:
    """Path to a shared empty capture, created once per process."""
    global _empty_capture_path
    if _empty_capture_path and Path(_empty_capture_path).exists():
        return _empty_capture_path
    handle = tempfile.NamedTemporaryFile(prefix="pangea-empty-", suffix=".pcap", delete=False)
    handle.write(_EMPTY_PCAP_HEADER)
    handle.close()
    _empty_capture_path = handle.name
    atexit.register(lambda: Path(handle.name).unlink(missing_ok=True))
    return _empty_capture_path


class PcapServiceError(RuntimeError):
    """Base for everything this service refuses or fails to do."""


class PathNotAllowed(PcapServiceError):
    """A capture outside the read-only roots, or not a regular file."""


class FilterError(PcapServiceError):
    """A display filter tshark will not compile, or one shaped like a flag."""


class PcapTimeout(PcapServiceError):
    """tshark exceeded the configured wall-clock limit and was killed."""


@dataclass(frozen=True)
class Packet:
    number: int
    time_epoch: float | None
    source: str
    destination: str
    protocol: str
    length: int | None
    info: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "time_epoch": self.time_epoch,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
        }


@dataclass(frozen=True)
class QueryResult:
    """
    The answer to one filter.

    `match_count` is the number of matching packets actually seen. When
    `truncated` is true the scan hit an output cap, so the true count is at
    least `match_count` -- stated rather than silently rounded off.
    """

    filter: str
    match_count: int
    packets: list[dict[str, Any]]
    truncated: bool = False
    limit: int = 0
    pcap_sha256: str = ""
    cached: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "filter": self.filter,
            "match_count": self.match_count,
            "packets": self.packets,
            "truncated": self.truncated,
            "limit": self.limit,
            "pcap_sha256": self.pcap_sha256,
            "cached": self.cached,
        }


@dataclass(frozen=True)
class Summary:
    """What a model is told about a capture before it asks anything."""

    path: str
    sha256: str
    size_bytes: int
    packet_count: int
    first_packet_epoch: float | None
    last_packet_epoch: float | None
    duration_seconds: float | None
    link_type: str = ""
    protocol_hierarchy: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "packet_count": self.packet_count,
            "first_packet_epoch": self.first_packet_epoch,
            "last_packet_epoch": self.last_packet_epoch,
            "duration_seconds": self.duration_seconds,
            "link_type": self.link_type,
            "protocol_hierarchy": self.protocol_hierarchy,
            "endpoints": self.endpoints,
        }


def _subprocess_env(tshark_path: str) -> dict[str, str]:
    """
    The environment tshark is run with.

    A relocated Wireshark -- here, one extracted from .deb packages into a
    home directory because the host has no root -- cannot find its own
    libwireshark unless LD_LIBRARY_PATH points beside it. Doing that here
    rather than in the launcher means `pytest` works the same as `./pangea`,
    instead of failing in a way that looks like a code bug.
    """
    env = dict(os.environ)
    lib_dir = Path(tshark_path).resolve().parent.parent / "lib" / "x86_64-linux-gnu"
    if (lib_dir / "libwireshark.so.17").exists() or list(lib_dir.glob("libwireshark.so*")):
        existing = env.get("LD_LIBRARY_PATH")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{existing}" if existing else str(lib_dir)
    return env


def resolve_capinfos(tshark_path: str) -> str | None:
    """
    capinfos, if it sits beside tshark.

    It reads a capture's header rather than dissecting every packet, so the
    count and the time window of a 324 MB file come back in milliseconds
    instead of a minute. Optional: without it, summary() falls back to
    tshark and is merely slow.
    """
    sibling = Path(tshark_path).parent / "capinfos"
    if sibling.exists():
        return str(sibling)
    return shutil.which("capinfos")


def resolve_tshark(configured: str | None = None) -> str:
    """
    Find tshark: PANGEA_TSHARK, then the config, then PATH.

    The environment variable comes first because on this host tshark is a
    user-space build outside PATH, and a wrapper that sets it is how the
    launcher makes the whole thing work.
    """
    for candidate in (os.environ.get("PANGEA_TSHARK"), configured):
        if candidate and Path(candidate).exists():
            return str(candidate)
    found = shutil.which("tshark")
    if not found:
        # Last resort: the user-space Wireshark this project installs when
        # the host has no root (see src/Dataset/README.md). Checked last so
        # a system tshark always wins.
        fallback = Path.home() / ".pangea-tools" / "tshark" / "usr" / "bin" / "tshark"
        if fallback.exists():
            return str(fallback)
    if not found:
        raise PcapServiceError(
            "tshark not found. Set PANGEA_TSHARK, put it on PATH, or run through ./pangea."
        )
    return found


class PcapService:
    """Runs tshark, under the limits above, and caches what it learns."""

    def __init__(
        self,
        *,
        allowed_roots: Iterable[str | Path],
        tshark_path: str | None = None,
        timeout_seconds: float = 30.0,
        max_packets_returned: int = 50,
        max_output_bytes: int = 1 << 20,
        db: Database | None = None,
    ) -> None:
        self.tshark = resolve_tshark(tshark_path)
        self.capinfos = resolve_capinfos(self.tshark)
        self.env = _subprocess_env(self.tshark)
        self.allowed_roots = [Path(root).resolve() for root in allowed_roots]
        self.timeout_seconds = float(timeout_seconds)
        self.max_packets_returned = int(max_packets_returned)
        self.max_output_bytes = int(max_output_bytes)
        self.db = db

    @classmethod
    def from_config(cls, config, db: Database | None = None, repo_root: Path | None = None) -> "PcapService":
        from ..manifest import REPO_ROOT

        root = repo_root or REPO_ROOT
        return cls(
            allowed_roots=[root / r for r in config.get("pcap_tool.allowed_roots", ["pcaps"])],
            tshark_path=config.get("pcap_tool.tshark_path"),
            timeout_seconds=config.get("pcap_tool.timeout_seconds", 30),
            max_packets_returned=config.get("pcap_tool.max_packets_returned", 50),
            max_output_bytes=config.get("pcap_tool.max_output_bytes", 1 << 20),
            db=db,
        )

    # -- the jail ---------------------------------------------------------

    def resolve_capture(self, path: str | Path) -> Path:
        """
        Resolve a capture path and refuse anything outside the roots.

        `Path.resolve()` follows symlinks before the check, so a link inside
        a root that points at /etc/passwd is rejected on where it lands, not
        on where it sits.
        """
        resolved = Path(path).expanduser().resolve()
        if not any(resolved == root or resolved.is_relative_to(root) for root in self.allowed_roots):
            raise PathNotAllowed(
                f"{resolved} is outside the readable capture roots "
                f"({', '.join(str(r) for r in self.allowed_roots)})"
            )
        if not resolved.is_file():
            raise PathNotAllowed(f"{resolved} is not a regular file")
        return resolved

    # -- running tshark ---------------------------------------------------

    def _run(self, args: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess:
        """
        One invocation. A list, never a string: `shell=False` is the whole
        defence against injection, so it is not optional anywhere here.
        """
        try:
            return subprocess.run(
                [self.tshark, *args],
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout_seconds,
                check=False,
                shell=False,
                env=self.env,
            )
        except subprocess.TimeoutExpired as exc:
            raise PcapTimeout(f"tshark exceeded {timeout or self.timeout_seconds}s") from exc

    def validate_filter(self, display_filter: str) -> None:
        """
        Let tshark decide whether a filter is a filter.

        A denylist of dangerous characters would be both leaky and wrong --
        `;` and `"` are legal in display filters. The only authority on the
        syntax is the program that will run it.
        """
        if not isinstance(display_filter, str) or not display_filter.strip():
            raise FilterError("empty display filter")
        if "\x00" in display_filter:
            raise FilterError("display filter contains a NUL byte")
        if len(display_filter) > MAX_FILTER_LENGTH:
            raise FilterError(f"display filter longer than {MAX_FILTER_LENGTH} characters")
        if display_filter.lstrip().startswith("-"):
            # Would be taken as an option by any argv-based caller.
            raise FilterError("a display filter may not start with '-'")

        # Compile it against an empty capture. Anything tshark will not
        # accept exits non-zero, whatever wording it chooses for the
        # complaint -- an unknown field, an unbalanced bracket, a dangling
        # operator and a shell metacharacter all land here the same way.
        result = self._run(
            ["-Y", display_filter, "-r", _empty_capture()], timeout=min(self.timeout_seconds, 15)
        )
        if result.returncode != 0:
            first_line = (result.stderr or "").strip().splitlines()
            raise FilterError(first_line[0] if first_line else f"tshark rejected the filter (exit {result.returncode})")

    # -- the two operations ----------------------------------------------

    def summary(self, path: str | Path) -> Summary:
        """Protocol hierarchy, endpoints, time window and packet count."""
        capture = self.resolve_capture(path)
        digest = file_sha256(capture)

        packet_count, first, last = self._header_stats(capture)
        if packet_count is None:
            # No capinfos: count frame numbers. Slower, same answer.
            numbered = self._run(["-r", str(capture), "-T", "fields", "-e", "frame.number"])
            lines = [line for line in numbered.stdout.splitlines() if line.strip()]
            packet_count = len(lines)
            epochs = self._run(["-r", str(capture), "-T", "fields", "-e", "frame.time_epoch"]).stdout.split()
            if epochs:
                first, last = float(epochs[0]), float(epochs[-1])

        hierarchy = _parse_protocol_hierarchy(self._run(["-r", str(capture), "-q", "-z", "io,phs"]).stdout)
        endpoints = _parse_endpoints(self._run(["-r", str(capture), "-q", "-z", "endpoints,ip"]).stdout)
        link_type = self._link_type(capture)

        return Summary(
            path=str(capture),
            sha256=digest,
            size_bytes=capture.stat().st_size,
            packet_count=packet_count or 0,
            first_packet_epoch=first,
            last_packet_epoch=last,
            duration_seconds=(last - first) if (first is not None and last is not None) else None,
            link_type=link_type,
            protocol_hierarchy=hierarchy,
            endpoints=endpoints,
        )

    def _header_stats(self, capture: Path) -> tuple[int | None, float | None, float | None]:
        """Packet count and time window from the capture header, via capinfos."""
        if not self.capinfos:
            return None, None, None
        try:
            result = subprocess.run(
                [self.capinfos, "-c", "-a", "-e", "-S", "-M", "-T", "-r", str(capture)],
                capture_output=True, text=True, timeout=self.timeout_seconds, check=False, shell=False,
                env=self.env,
            )
        except subprocess.TimeoutExpired as exc:
            raise PcapTimeout(f"capinfos exceeded {self.timeout_seconds}s") from exc
        for line in result.stdout.splitlines():
            cells = line.rstrip("\n").split("\t")
            if len(cells) >= 4:
                try:
                    return int(cells[1]), float(cells[2]), float(cells[3])
                except ValueError:
                    continue
        return None, None, None

    def head(self, path: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
        """
        The first N packets, with no filter and no count.

        `-c N` makes tshark stop after reading N packets, so this is cheap
        even on a 324 MB capture. query() cannot use it: counting matches
        requires reading the whole file, and a `-c` there would silently
        turn "29 matches" into "29 matches in the first N packets".
        """
        capture = self.resolve_capture(path)
        limit = self.max_packets_returned if limit is None else min(int(limit), self.max_packets_returned)
        result = self._run(
            ["-r", str(capture), "-c", str(limit), "-T", "fields",
             *sum((["-e", name] for name in PACKET_FIELDS), []),
             "-E", "separator=\t", "-E", "occurrence=f"]
        )
        return [_parse_packet_line(line).as_dict() for line in result.stdout.splitlines() if line.strip()]

    def query(self, path: str | Path, display_filter: str, limit: int | None = None) -> QueryResult:
        """
        Run a display filter: how many packets match, and the first few.

        Streamed rather than buffered, because the capture may be larger
        than memory and a filter may match everything in it. The stream is
        cut at `max_output_bytes`, and the result says so.
        """
        capture = self.resolve_capture(path)
        limit = self.max_packets_returned if limit is None else min(int(limit), self.max_packets_returned)
        self.validate_filter(display_filter)

        digest = file_sha256(capture)
        cache_key = content_hash({"sha256": digest, "filter": display_filter, "limit": limit})
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        args = [
            self.tshark, "-r", str(capture), "-Y", display_filter, "-T", "fields",
            *sum((["-e", field_name] for field_name in PACKET_FIELDS), []),
            "-E", "separator=\t", "-E", "occurrence=f",
        ]
        match_count = 0
        packets: list[dict[str, Any]] = []
        truncated = False
        bytes_read = 0

        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, env=self.env
        )
        try:
            assert process.stdout is not None
            for line in process.stdout:
                bytes_read += len(line)
                if bytes_read > self.max_output_bytes:
                    truncated = True
                    break
                line = line.rstrip("\n")
                if not line:
                    continue
                match_count += 1
                if len(packets) < limit:
                    packets.append(_parse_packet_line(line).as_dict())
            if truncated:
                process.kill()
            stderr = ""
            try:
                _, stderr = process.communicate(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                raise PcapTimeout(f"tshark exceeded {self.timeout_seconds}s")
            if process.returncode not in (0, None) and not truncated:
                message = (stderr or "").strip().splitlines()
                raise PcapServiceError(message[0] if message else f"tshark exited {process.returncode}")
        finally:
            if process.poll() is None:
                process.kill()

        result = QueryResult(
            filter=display_filter,
            match_count=match_count,
            packets=packets,
            truncated=truncated,
            limit=limit,
            pcap_sha256=digest,
        )
        self._cache_put(cache_key, digest, display_filter, limit, result)
        return result

    # -- cache -------------------------------------------------------------

    def _cache_get(self, cache_key: str) -> QueryResult | None:
        if self.db is None:
            return None
        row = self.db.one("SELECT result FROM pcap_query_cache WHERE cache_key = ?", (cache_key,))
        if row is None:
            return None
        import json

        payload = json.loads(row["result"])
        return QueryResult(**{**payload, "cached": True})

    def _cache_put(self, cache_key: str, digest: str, display_filter: str, limit: int, result: QueryResult) -> None:
        if self.db is None:
            return
        import json

        self.db.insert(
            "pcap_query_cache",
            dict(
                cache_key=cache_key,
                pcap_sha256=digest,
                filter=display_filter,
                limit_n=limit,
                result=json.dumps(result.as_dict()),
                created_at=utc_now(),
            ),
        )


    def _link_type(self, capture: Path) -> str:
        if not self.capinfos:
            return ""
        result = subprocess.run(
            [self.capinfos, "-E", "-M", "-T", "-r", str(capture)],
            capture_output=True, text=True, timeout=self.timeout_seconds, check=False, shell=False,
            env=self.env,
        )
        for line in result.stdout.splitlines():
            cells = line.rstrip("\n").split("\t")
            if len(cells) >= 2:
                return cells[1]
        return ""


# -- output parsing ------------------------------------------------------

def _parse_packet_line(line: str) -> Packet:
    parts = (line.split("\t") + [""] * len(PACKET_FIELDS))[: len(PACKET_FIELDS)]
    try:
        number = int(parts[0])
    except ValueError:
        number = 0
    try:
        epoch = float(parts[1])
    except ValueError:
        epoch = None
    try:
        length: int | None = int(parts[5])
    except ValueError:
        length = None
    return Packet(number, epoch, parts[2], parts[3], parts[4], length, parts[6])


def _parse_io_stat(text: str) -> tuple[int | None, float | None, float | None]:
    """
    Read packet count and time window out of `-z io,stat,0`.

    The table's one interval covers the whole file, so its frame count is
    the capture's, and the interval bounds are the first and last packet
    times relative to the capture start.
    """
    count: int | None = None
    duration: float | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and "<>" in stripped:
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if len(cells) >= 2:
                try:
                    count = int(cells[1])
                except ValueError:
                    pass
                bounds = cells[0].split("<>")
                if len(bounds) == 2:
                    try:
                        duration = float(bounds[1])
                    except ValueError:
                        pass
    if count is None:
        return None, None, None
    return count, 0.0, duration


def _parse_protocol_hierarchy(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("=") or "frames:" not in line:
            continue
        depth = (len(line) - len(line.lstrip(" "))) // 2
        name = line.strip().split(" ")[0]
        frames = bytes_ = 0
        for token in line.split():
            if token.startswith("frames:"):
                frames = int(token.split(":")[1])
            elif token.startswith("bytes:"):
                bytes_ = int(token.split(":")[1])
        rows.append({"protocol": name, "depth": depth, "frames": frames, "bytes": bytes_})
    return rows


def _parse_endpoints(text: str, limit: int = 20) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    started = False
    for line in text.splitlines():
        if set(line.strip()) == {"="}:
            started = not started or started
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[0].count(".") == 3 or (len(parts) >= 5 and ":" in parts[0]):
            try:
                rows.append({"address": parts[0], "packets": int(parts[1]), "bytes": int(parts[2])})
            except ValueError:
                continue
        if len(rows) >= limit:
            break
    return rows


def _parse_link_type(stderr: str) -> str:
    for line in stderr.splitlines():
        if "link-layer" in line.lower() or "encapsulation" in line.lower():
            return line.strip()
    return ""
