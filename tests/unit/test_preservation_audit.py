"""Isolated audit fixtures only; never mutate protected project files."""

import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from scripts import preservation_audit as audit


@pytest.fixture
def workspace():
    with TemporaryDirectory(prefix="preservation-fixture-") as name:
        yield Path(name)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def baseline(root, entries):
    path = root / "baseline.json"
    path.write_text(json.dumps(entries))
    return path


def check(root, path, count, **kwargs):
    return audit.compare(root, audit.iter_manifest(path), expected_count=count, **kwargs)


def test_unchanged_permitted_and_protected_changes(workspace):
    (workspace / "a").write_bytes(b"first")
    (workspace / "b").write_bytes(b"other")
    path = baseline(workspace, {"a": sha(b"first"), "b": sha(b"other")})
    result = check(workspace, path, 2)
    assert result.passed and result.unchanged == 2 and len(result.names) == 2
    (workspace / "b").write_bytes(b"ALTER")  # Same length, but explicitly permitted.
    permitted = check(workspace, path, 2, permitted={"b"})
    assert permitted.passed and permitted.allowed_changed == ["b"]
    (workspace / "a").write_bytes(b"FIRST")  # Same-size protected edit must fail.
    protected = check(workspace, path, 2, permitted={"b"})
    assert not protected.passed and protected.changed == ["a"]
    (workspace / "b").unlink()  # Permission to change content is not permission to delete.
    removed = check(workspace, path, 2, permitted={"b"})
    assert not removed.passed and removed.missing == ["b"]


@pytest.mark.parametrize(
    "position",
    [0, audit.HASH_CHUNK - 1, audit.HASH_CHUNK, audit.HASH_CHUNK + 1, 2 * audit.HASH_CHUNK],
)
def test_cross_chunk_changes_detected(workspace, position):
    data = bytearray(b"A" * (2 * audit.HASH_CHUNK + 17))
    path = baseline(workspace, {"payload": sha(data)})
    (workspace / "payload").write_bytes(data)
    assert check(workspace, path, 1).passed
    data[position] ^= 1
    (workspace / "payload").write_bytes(data)
    assert not check(workspace, path, 1).passed


@pytest.mark.parametrize("operation", ["add", "remove", "symlink-directory"])
def test_required_inventory_additions_and_removals(workspace, operation):
    directory = workspace / "tree"
    directory.mkdir()
    (directory / "a").write_bytes(b"A")
    expected = {"tree/a"}
    assert audit.inventory_check(workspace, ("tree",), expected)["passed"]
    if operation == "add":
        (directory / "b").write_bytes(b"B")
    elif operation == "remove":
        (directory / "a").unlink()
    else:
        (directory / "link").symlink_to(directory, target_is_directory=True)
    outcome = audit.inventory_check(workspace, ("tree",), expected)
    assert not outcome["passed"]
    assert outcome["missing"] if operation == "remove" else outcome["unexpected"]


def test_only_exact_optional_additions_allowed(workspace):
    directory = workspace / "tree"
    directory.mkdir()
    (directory / "allowed").write_bytes(b"A")
    assert audit.inventory_check(workspace, ("tree",), set(), optional_names={"tree/allowed"})[
        "passed"
    ]
    (directory / "other").write_bytes(b"B")
    assert not audit.inventory_check(workspace, ("tree",), set(), optional_names={"tree/allowed"})[
        "passed"
    ]


@pytest.mark.parametrize(
    "malformed",
    [
        b"",
        b"{",
        b'{"a":',
        b'{"a":"' + b"0" * 64 + b'"',
        b'{"a":"short"}',
        b'{"a":0}',
        b'{"a":"' + b"0" * 64 + b'","a":"' + b"0" * 64 + b'"}',
        b'{"../a":"' + b"0" * 64 + b'"}',
        b'{"/a":"' + b"0" * 64 + b'"}',
        b'{"a/./b":"' + b"0" * 64 + b'"}',
        b"[]",
        b"{} trailing",
        b'{"\xff":"' + b"0" * 64 + b'"}',
    ],
)
def test_malformed_or_truncated_manifest_is_explicit_failure(workspace, malformed):
    path = workspace / "bad.json"
    path.write_bytes(malformed)
    with pytest.raises(audit.AuditError):
        list(audit.iter_manifest(path))


def test_streamed_utf8_unordered_manifest_and_trailing_validation(workspace, monkeypatch):
    monkeypatch.setattr(audit, "MANIFEST_CHUNK", 3)
    entries = {"z-é": sha(b"Z"), "a": sha(b"A")}
    for name, data in [("z-é", b"Z"), ("a", b"A")]:
        (workspace / name).write_bytes(data)
    path = workspace / "baseline.json"
    path.write_text(json.dumps(entries, ensure_ascii=False))
    assert check(workspace, path, 2).passed
    path.write_text(path.read_text() + " invalid")
    with pytest.raises(audit.AuditError):
        check(workspace, path, 2)  # All entries yielded but final EOF check still required.


def test_incomplete_duplicate_or_failing_iterator_cannot_succeed(workspace):
    (workspace / "a").write_bytes(b"A")
    entry = ("a", sha(b"A"))
    with pytest.raises(audit.AuditError):
        audit.compare(workspace, [entry], expected_count=2)
    with pytest.raises(audit.AuditError):
        audit.compare(workspace, [entry, entry], expected_count=2)

    def interrupted():
        yield entry
        raise OSError("controlled iterator I/O failure")

    with pytest.raises(OSError):
        audit.compare(workspace, interrupted(), expected_count=2)


@pytest.mark.parametrize("fault", ["hash-io", "cache-advice-io", "memory", "inventory-io"])
def test_io_resource_and_traversal_failure_never_return_success(workspace, monkeypatch, fault):
    (workspace / "a").write_bytes(b"A")
    path = baseline(workspace, {"a": sha(b"A")})

    def fail(*args, **kwargs):
        raise MemoryError("controlled") if fault == "memory" else OSError("controlled")

    if fault == "hash-io":
        monkeypatch.setattr(audit, "digest_file", fail)
    elif fault == "cache-advice-io":
        monkeypatch.setattr(os, "posix_fadvise", fail)
    elif fault == "inventory-io":
        monkeypatch.setattr(os, "scandir", fail)
        with pytest.raises(OSError):
            audit.inventory_check(workspace, ("dir",), set())
        return
    with pytest.raises((MemoryError, OSError)):
        check(workspace, path, 1, progress=fail if fault == "memory" else None)


@pytest.mark.parametrize("phase", ["write", "fsync", "rename"])
def test_report_failure_has_no_published_success(workspace, monkeypatch, phase):
    destination = workspace / "result.json"

    def fail(*args, **kwargs):
        if phase == "write":
            args[1].write('{"passed":')
        raise OSError("controlled report failure")

    owner, name = {"write": (json, "dump"), "fsync": (os, "fsync"), "rename": (os, "replace")}[
        phase
    ]
    monkeypatch.setattr(owner, name, fail)
    with pytest.raises(OSError):
        audit.write_report(destination, {"passed": True})
    assert not destination.exists()
    assert not destination.with_name("result.json.pending").exists()


def test_report_compatibility_and_no_overwrite(workspace):
    (workspace / "a").write_bytes(b"A")
    result = audit.compare(workspace, [("a", sha(b"A"))], expected_count=1)
    output = {"passed": result.passed, **result.report()}
    path = workspace / "result.json"
    audit.write_report(path, output)
    parsed = json.loads(path.read_text())
    assert (
        parsed["passed"] and parsed["protected_files"] == parsed["unchanged_protected_files"] == 1
    )
    assert parsed["allowed_changed_files"] == parsed["missing_files"] == []
    with pytest.raises(audit.AuditError):
        audit.write_report(path, {"passed": False})
    assert json.loads(path.read_text()) == output


def test_file_symlink_lexical_identity_and_existing_metadata_semantics(workspace):
    (workspace / "target").write_bytes(b"DATA")
    (workspace / "alias").symlink_to("target")
    path = baseline(workspace, {"alias": sha(b"DATA"), "target": sha(b"DATA")})
    result = check(workspace, path, 2)
    assert result.passed and result.names == {"alias", "target"}
    os.utime(workspace / "target", (100, 100))
    (workspace / "target").chmod(0o600)
    assert check(workspace, path, 2).passed  # No new baseline mtime/mode semantics.
    (workspace / "target").unlink()
    assert check(workspace, path, 2).missing == ["alias", "target"]


def test_advice_changes_no_digest_or_chunk_coverage(workspace, monkeypatch):
    data = b"X" * (2 * audit.HASH_CHUNK + 17)
    path = workspace / "large"
    path.write_bytes(data)
    real = os.posix_fadvise
    calls = []

    def record(fd, offset, length, advice):
        calls.append((offset, length, advice))
        return real(fd, offset, length, advice)

    monkeypatch.setattr(os, "posix_fadvise", record)
    assert audit.digest_file(path) == sha(data)
    chunks = [(offset, length) for offset, length, advice in calls[1:-1]]
    assert chunks == [
        (0, audit.HASH_CHUNK),
        (audit.HASH_CHUNK, audit.HASH_CHUNK),
        (2 * audit.HASH_CHUNK, 17),
    ]


def test_append_prefix_does_not_replace_complete_file_check(workspace):
    path = workspace / "report"
    path.write_bytes(b"original")
    expected = sha(b"original")
    with path.open("ab") as stream:
        stream.write(b"\nnew result")
    assert audit.digest_file(path, prefix_bytes=8) == expected
    assert audit.digest_file(path) != expected
    path.write_bytes(b"ORIGINAL\nnew result")
    assert audit.digest_file(path, prefix_bytes=8) != expected
    with pytest.raises(audit.AuditError):
        audit.digest_file(path, prefix_bytes=100)


def test_mid_read_mutation_and_token_or_entry_limits(workspace, monkeypatch):
    path = workspace / "a"
    path.write_bytes(b"A" * 32)
    mutated = False

    def mutate(offset):
        nonlocal mutated
        if not mutated:
            with path.open("ab") as stream:
                stream.write(b"B")
            mutated = True

    with pytest.raises(audit.AuditError, match="file changed during"):
        audit.digest_file(path, progress=mutate)
    manifest = baseline(workspace, {"a": sha(b"A")})
    monkeypatch.setattr(audit, "MAX_ENTRIES", 0)
    with pytest.raises(audit.AuditError):
        list(audit.iter_manifest(manifest))


@pytest.mark.parametrize(
    "fault", ["none", "missing", "resource", "timeout", "report", "incomplete", "swap"]
)
def test_content_success_needs_complete_clean_guard(fault):
    content = {"passed": True, "comparison_complete": True}
    run = {
        "status": "pass",
        "exit_code": 0,
        "stop": None,
        "seconds": 1,
        "sampled_tree_RSS_peak": 10,
        "service": {
            "exit_code": 0,
            "resource_guard_passed": True,
            "resource_guard_exit_code": 0,
            "before": {"memory.max": "100", "memory.swap.max": "0"},
            "after": {
                "memory.peak": "30",
                "memory.swap.peak": "0",
                "memory.events": "max 0\noom 0\noom_kill 0",
            },
        },
    }
    run = deepcopy(run)
    if fault == "missing":
        del run["service"]["after"]
    elif fault == "resource":
        run["service"]["after"]["memory.events"] = "max 1\noom 0\noom_kill 0"
    elif fault == "timeout":
        run["stop"] = "wall deadline"
    elif fault == "report":
        run["service"]["exit_code"] = 1
    elif fault == "incomplete":
        content["comparison_complete"] = False
    elif fault == "swap":
        run["service"]["after"]["memory.swap.peak"] = "1"
    assert audit.guarded_pass(content, run, memory_bytes=100, command_seconds=60) == (
        fault == "none"
    )
