"""Bounded SHA-256 preservation checks; no cryptographic/protocol implementation.

Linux cache advice bounds avoidable file-cache retention inside the SAME cgroup.
File bytes and lexical manifest identities remain the source of comparison.
"""

import codecs
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

HASH_CHUNK = 256 * 1024
MANIFEST_CHUNK = 8192
MAX_TOKEN = 32768
MAX_ENTRIES = 10000
MAX_PATH = 4096


class AuditError(Exception):
    """An incomplete comparison/report MUST NOT become a success result."""


def _identity(name):
    if (
        type(name) is not str
        or not name
        or len(name) > MAX_PATH
        or "\x00" in name
        or PurePosixPath(name).is_absolute()
        or str(PurePosixPath(name)) != name
        or ".." in PurePosixPath(name).parts
    ):
        raise AuditError("invalid lexical relative manifest path")
    return name


def digest_file(path: Path, *, prefix_bytes=None, progress=None) -> str:
    """Follow file symlinks, hash all bytes with SHA-256; never hash link text.

    Prefix hashing is only for an explicitly authorised append-only report. It is
    not used to replace complete-file hashing of ordinary protected files.
    """
    if prefix_bytes is not None and (type(prefix_bytes) is not int or prefix_bytes < 0):
        raise AuditError("invalid prefix bound")
    if not path.is_file():
        raise AuditError("protected path is not a regular file or a file symlink")
    buffer = bytearray(HASH_CHUNK)
    view = memoryview(buffer)
    hasher = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_RANDOM)
        offset = 0
        while prefix_bytes is None or offset < prefix_bytes:
            wanted = HASH_CHUNK if prefix_bytes is None else min(HASH_CHUNK, prefix_bytes - offset)
            count = stream.readinto(view[:wanted])
            if count is None:
                raise AuditError("incomplete read")
            if count == 0:
                break
            hasher.update(view[:count])
            # HASH_CHUNK is page aligned; final partial EOF pages are released below.
            os.posix_fadvise(stream.fileno(), offset, count, os.POSIX_FADV_DONTNEED)
            offset += count
            if progress is not None:
                progress(offset)
        if prefix_bytes is not None and offset != prefix_bytes:
            raise AuditError("truncated append-only prefix")
        os.posix_fadvise(stream.fileno(), 0, offset, os.POSIX_FADV_DONTNEED)
        after = os.fstat(stream.fileno())
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise AuditError("file changed during content comparison")
    return hasher.hexdigest()


class _Tokens:
    """Incremental strict UTF-8 JSON string/punctuation reader; no whole-file read."""

    def __init__(self, stream):
        self.stream, self.text, self.eof = stream, "", False
        self.utf8 = codecs.getincrementaldecoder("utf-8")()
        self.decoder = json.JSONDecoder()

    def fill(self):
        if self.eof:
            return
        block = self.stream.read(MANIFEST_CHUNK)
        if not block:
            self.eof = True
        self.text += self.utf8.decode(block, final=self.eof)
        if len(self.text) > MAX_TOKEN + 2 * MANIFEST_CHUNK:
            raise AuditError("manifest token exceeds bounded admission")

    def space(self):
        while True:
            self.text = self.text.lstrip(" \t\r\n")
            if self.text or self.eof:
                return
            self.fill()

    def peek(self):
        self.space()
        return self.text[:1]

    def take(self, expected):
        if self.peek() != expected:
            raise AuditError("malformed or truncated manifest punctuation")
        self.text = self.text[1:]

    def string(self):
        if self.peek() != '"':
            raise AuditError("manifest keys and digests must be strings")
        while True:
            try:
                value, end = self.decoder.raw_decode(self.text)
            except json.JSONDecodeError as error:
                if self.eof or len(self.text) >= MAX_TOKEN:
                    raise AuditError("malformed or truncated manifest string") from error
                self.fill()
                continue
            self.text = self.text[end:]
            return value

    def finish(self):
        self.space()
        if self.text or not self.eof:
            raise AuditError("trailing manifest data")


def iter_manifest(path: Path):
    """Strict flat JSON path->SHA256, preserving unordered-object semantics.

    Duplicate names are errors instead of JSON's silent last-value replacement.
    Seen lexical names are retained for duplicate detection, not a second digest map.
    """
    seen = set()
    try:
        with path.open("rb", buffering=0) as stream:
            tokens = _Tokens(stream)
            tokens.take("{")
            if tokens.peek() != "}":
                while True:
                    name = _identity(tokens.string())
                    tokens.take(":")
                    digest = tokens.string()
                    if not re.fullmatch("[0-9a-f]{64}", digest):
                        raise AuditError("invalid SHA-256 digest")
                    if name in seen or len(seen) >= MAX_ENTRIES:
                        raise AuditError("duplicate path or manifest entry limit")
                    seen.add(name)
                    yield name, digest
                    if tokens.peek() == "}":
                        break
                    tokens.take(",")
            tokens.take("}")
            tokens.finish()
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AuditError("malformed UTF-8/JSON manifest") from error


@dataclass
class Comparison:
    names: set[str] = field(default_factory=set, repr=False)
    changed: list[str] = field(default_factory=list)
    allowed_changed: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unchanged: int = 0
    bytes_hashed: int = 0
    coverage_sha256: str = ""

    @property
    def passed(self):
        return not self.changed and not self.missing

    def report(self):
        return {
            "protected_files": len(self.names),
            "unchanged_protected_files": self.unchanged,
            "allowed_changed_files": self.allowed_changed,
            "changed_files": self.changed,
            "missing_files": self.missing,
            "bytes_hashed": self.bytes_hashed,
            "coverage_sha256": self.coverage_sha256,
        }


def compare(root, entries, *, expected_count, permitted=frozenset(), progress=None):
    """Complete the iterator, including its EOF validation, before returning a result."""
    if type(expected_count) is not int or not 0 <= expected_count <= MAX_ENTRIES:
        raise AuditError("unsupported expected inventory size")
    result = Comparison()
    coverage = hashlib.sha256()
    for name, expected in entries:
        _identity(name)
        if name in result.names or len(result.names) >= MAX_ENTRIES:
            raise AuditError("duplicate path or comparison admission limit")
        if not re.fullmatch("[0-9a-f]{64}", expected):
            raise AuditError("invalid expected digest")
        result.names.add(name)
        coverage.update(name.encode("utf-8") + b"\x00" + bytes.fromhex(expected))
        path = root / name
        if not path.is_file():
            result.missing.append(name)
        else:
            actual = digest_file(path, progress=progress)
            result.bytes_hashed += path.stat().st_size
            if actual == expected:
                result.unchanged += 1
            elif name in permitted:
                result.allowed_changed.append(name)
            else:
                result.changed.append(name)
    if len(result.names) != expected_count:
        raise AuditError("incomplete inventory comparison")
    result.coverage_sha256 = coverage.hexdigest()
    return result


def inventory_names(root, directories):
    """Enumerate every non-directory entry; do not follow symlink directories."""

    def walk(directory):
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    yield from walk(path)
                else:
                    yield path.relative_to(root).as_posix()

    for name in directories:
        _identity(name)
        yield from walk(root / name)


def inventory_check(root, directories, expected_names, *, optional_names=frozenset()):
    """Exact name membership, with no suffix or directory-wide exclusions."""
    actual = set()
    for name in inventory_names(root, directories):
        if name in actual or len(actual) >= MAX_ENTRIES:
            raise AuditError("duplicate/oversized inventory traversal")
        actual.add(name)
    unexpected = actual - expected_names - optional_names
    missing = expected_names - actual
    return {
        "passed": not unexpected and not missing,
        "count": len(actual),
        "unexpected": sorted(unexpected),
        "missing": sorted(missing),
    }


def write_report(path, value):
    """Stream an atomic new report; a write/flush/rename failure propagates."""
    if path.exists():
        raise AuditError("refusing to overwrite an existing report")
    pending = path.with_name(path.name + ".pending")
    try:
        with pending.open("x") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    except BaseException:
        pending.unlink(missing_ok=True)
        raise


def guarded_pass(content, run, *, memory_bytes, command_seconds):
    """A content pass is insufficient: require the completed outer guard record.

    Legacy content-report fields retain their meaning. Missing/torn guard records,
    non-zero memory events, timeout and reporting failures cannot authorise success.
    """
    try:
        service = run["service"]
        events = dict(line.split() for line in service["after"]["memory.events"].splitlines())
        return (
            content["passed"] is True
            and content["comparison_complete"] is True
            and run["status"] == "pass"
            and run["exit_code"] == 0
            and run["stop"] is None
            and run["seconds"] < command_seconds
            and run["sampled_tree_RSS_peak"] <= memory_bytes
            and service["exit_code"] == 0
            and service["resource_guard_passed"] is True
            and service["resource_guard_exit_code"] == 0
            and service["before"]["memory.max"] == str(memory_bytes)
            and service["before"]["memory.swap.max"] == "0"
            and int(service["after"]["memory.peak"]) < memory_bytes
            and int(service["after"]["memory.swap.peak"]) == 0
            and all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
        )
    except KeyError, TypeError, ValueError:
        return False
