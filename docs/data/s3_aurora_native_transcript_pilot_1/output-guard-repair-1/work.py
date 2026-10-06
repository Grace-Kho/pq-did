"""Repair validation and retained native-case sequence; no build command."""

import gzip
import json
import subprocess
import time
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
H = R.parent / "header-correction-1"
C = P / "docs/data/s3_aurora_compiler_compatibility_contract_1"
NEXT = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/guarded-build-v2"


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


native = load(H / "work.py")
prior, sha, read = native.prior, native.sha, native.read


def save(name, value):
    (R / name).write_text(json.dumps(value, indent=2) + "\n")


def tooling():
    checks = load(R / "checks.py")
    files = [str(R / name) for name in checks.PYTHON]
    for options in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *options, "--no-cache", *files], check=True, timeout=1
        )
    save(
        "static-inputs.json",
        {"sha256": {str((R / n).relative_to(P)): sha(R / n) for n in checks.PYTHON}},
    )
    seals = load(R / "seal_policy.py")
    snapshot = seals.snapshot(P)
    assert seals.verify_repository(P, snapshot)
    save("report-snapshot.json", snapshot)
    guard = load(R / "run.py")
    assert guard.artifact_limits() is None
    for name, entry in guard.policy.retained_inventory(R).items():
        if entry["kind"] != "symlink":
            assert sha(P / name) == entry["sha256"]
    with gzip.open(H / "artifact-inventory.json.gz", "rt") as stream:
        assets = json.load(stream)
    for entry in assets["files"]:
        path = P / entry["path"]
        assert path.stat().st_size == entry["bytes"] and path.lstat().st_mode == entry["mode"]
        assert sha(path) == entry["sha256"]
    registration = read(R / "registration.json")
    assert {str(p.relative_to(P)) for p in guard.EXACT} == set(registration["exact_new_slots"])
    assert sha(P / registration["ninja_path"]) == registration["ninja_sha256"]
    assert sha(P / registration["build_log"]) == registration["build_log_sha256"]
    ninja = (P / registration["ninja_path"]).read_text().splitlines()
    assert len(registration["all_compiler_linker_outputs"]) == 22
    for row in registration["all_compiler_linker_outputs"]:
        assert row["ninja_rule"] in ninja and sha(P / row["path"]) == row["sha256"]
        assert (P / row["path"]).resolve() == P / row["path"]
    built = read(H / "build-attempt.json")
    assert built["status"] == "pass" and built["attempt"] == 5
    for name, digest in built["binary_sha256"].items():
        assert sha(NEXT / "build" / name) == digest
    for row in read(R.parent / "case-plan.json")["cases"]:
        assert sha(P / row["retained_expectation"]) == row["retained_sha256"]
    save(
        "binary-admission.json",
        {
            "passed": True,
            "compiler_body_exit": 0,
            "historical_outer_guard_passed": False,
            "binary_sha256": built["binary_sha256"],
            "retained_manifest": registration["prior_manifest_sha256"],
            "verified_outputs": 22,
            "verified_current_tree_files": len(assets["files"]),
            "builds_this_package": 0,
            "pins_and_overlays_verified": True,
            "no_binary_executed_during_admission": True,
        },
    )
    load(R / "fixtures.py").run(guard)


def cases():
    assert read(R / "pre-native/result.json")["passed"]
    assert read(R / "binary-admission.json")["passed"]
    result = read(H / "build-attempt.json")
    assert result["status"] == "pass"
    for name, expected in result["binary_sha256"].items():
        assert sha(NEXT / "build" / name) == expected
    assert not (R / "native-case-ledger.json").exists()
    expected = read(R.parent / "case-plan.json")["cases"]
    rows = []
    started = time.monotonic()
    for index in range(24):
        assert time.monotonic() - started + 2 < 49, "case command admission reserve"
        semantic = index < 8
        n = index + 1 if semantic else index - 7
        case_id = ("SEM-" if semantic else "TR-") + f"{n:02d}"
        command = [str(NEXT / "build" / ("exp2_semantics" if semantic else "exp2_native")), str(n)]
        if not semantic:
            row = expected[n - 1]
            assert row["id"] == case_id
            assert sha(P / row["retained_expectation"]) == row["retained_sha256"]
            command += [
                str(NEXT / "overlay" / ("nonce-mutated.bin" if n == 3 else "canonical.bin"))
            ]
        item = {
            "id": case_id,
            "invocation": 420 + len(read(R / "fixture-ledger.json")) + index,
            "status": "admitted",
            "command": command,
        }
        rows.append(item)
        save("native-case-ledger.json", rows)
        start = time.monotonic()
        try:
            output = subprocess.run(command, capture_output=True, timeout=2)
            assert len(output.stdout) + len(output.stderr) < 61440
            (R / (case_id + ".native.txt")).write_bytes(output.stdout + output.stderr)
            assert output.returncode == 0, "native exit " + str(output.returncode)
            if semantic:
                assert output.stdout == f"SEM-{n} pass\n".encode() and not output.stderr
                outcome = {"literal_independent_expected_assertions_passed": True}
                provenance = str((C / "semantic_cases.cpp").relative_to(P))
            else:
                outcome = prior.compare(
                    output.stdout.decode("ascii"), read(P / row["retained_expectation"])
                )
                provenance = row["retained_expectation"]
            save(
                case_id + ".json",
                {
                    "command": command,
                    "exit_code": output.returncode,
                    "expected_provenance": provenance,
                    "expected_sha256": sha(P / provenance),
                    "outcome": outcome,
                },
            )
            item.update(status="pass", seconds=time.monotonic() - start)
        except Exception as error:
            item.update(status="failed", seconds=time.monotonic() - start, error=str(error))
            save("native-case-ledger.json", rows)
            raise
        save("native-case-ledger.json", rows)


def run(name):
    if name in {"tooling", "tooling-corrected"}:
        tooling()
    elif name == "cases":
        cases()
    else:
        load(R / "checks.py").run(name)
