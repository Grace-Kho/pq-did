"""One authorised native build and individually admitted public-input cases."""

import json
import os
import subprocess
import time
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
C = P / "docs/data/s3_aurora_compiler_compatibility_contract_1"
OLD = R.parent / "reconciliation-1"
A = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
NEXT = A / "guarded-build-v1"


def load(path):
    m = types.ModuleType(path.stem)
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    return m


prior = load(OLD / "native_work.py")
sha, read = prior.sha, prior.read


def save(name, value):
    (R / name).write_text(json.dumps(value, indent=2) + "\n")


def preflight():
    started = time.monotonic()
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [
                str(P / ".venv/bin/ruff"),
                *args,
                "--no-cache",
                *[str(R / n) for n in ("run.py", "work.py", "checks.py")],
            ],
            check=True,
            timeout=0.5,
        )
    guard = load(R / "run.py")
    old = R.parent / "build-4-admission-1"
    opening = read(R / "opening-ledger.json")
    assert sha(old / "manifest.json") == opening["prior_manifest_sha256"]
    for manifest in ("manifest.json", "checked-inputs.json"):
        for name, expected in read(old / manifest)["sha256"].items():
            assert sha(P / name) == expected, name
    sealed = read(R.parent / "resource-guard-repair-1/next-build-request.json")
    proposal = read(C / "proposal.json")
    assert sealed["commands"] == [
        [a.replace("compatibility-v1", "guarded-build-v1") for a in proposal[k]]
        for k in ("configure_argv", "build_argv")
    ]
    assert guard.artifact_limits() is None
    assert opening["budget"]["sum"] <= 2097152
    assert 12222999 + 2097152 <= 16777216
    assert 1606632 + 2097152 <= 4194304
    assert NEXT.is_dir() and not any(NEXT.iterdir())
    actions = []
    for name in ("work", "overlay"):
        argv = ["cp", "-a", str(A / "compatibility-v1" / name), str(NEXT / name)]
        subprocess.run(argv, check=True, timeout=1)
        actions.append(argv)
    (NEXT / "scratch").mkdir()
    for name in ("work", "overlay"):
        source = A / "compatibility-v1" / name
        paths = [p for p in source.rglob("*") if p.is_file()]
        assert {str(p.relative_to(source)) for p in paths} == {
            str(p.relative_to(NEXT / name)) for p in (NEXT / name).rglob("*") if p.is_file()
        }
        for p in paths:
            assert sha(p) == sha(NEXT / name / p.relative_to(source))
    assert (
        sha(NEXT / "work/libiop/libiop/relations/variable.tcc")
        == "74ae2e8f6c7caed735be225dc63f25a84bb5b790579f0afe124aafcb0d7bc3bd"
    )
    assert sha(NEXT / "overlay/semantic_cases.cpp") == sha(C / "semantic_cases.cpp")
    for row in read(R.parent / "case-plan.json")["cases"]:
        assert sha(P / row["retained_expectation"]) == row["retained_sha256"]
    save(
        "preflight-result.json",
        {
            "passed": True,
            "seconds": time.monotonic() - started,
            "commands": actions,
            "byte_identical_copy": True,
            "budget": opening["budget"],
            "retained_metadata_addition": 784736,
            "previous_failures_unchanged": True,
            "new_builds": 0,
            "new_cases": 0,
        },
    )


def build():
    assert read(R / "preflight.json")["status"] == "pass"
    assert read(R / "preflight-result.json")["passed"]
    assert not (R / "build-attempt.json").exists()
    proposal = read(R.parent / "resource-guard-repair-1/next-build-request.json")
    commands = proposal["commands"]
    save(
        "build-commands.json",
        {"commands": commands, "environment": proposal["environment"]},
    )
    save("build-attempt.json", {"attempt": 4, "ceiling": 4, "status": "admitted"})
    env = dict(os.environ, **load(R / "run.py").compiler_environment())
    for name in proposal["environment"]["unset"]:
        env.pop(name, None)
    start = time.monotonic()
    try:
        for command in commands:
            subprocess.run(
                command, check=True, env=env, timeout=max(0.1, 53 - (time.monotonic() - start))
            )
        binaries = {name: sha(NEXT / "build" / name) for name in ("exp2_native", "exp2_semantics")}
    except Exception as error:
        save(
            "build-attempt.json",
            {
                "attempt": 4,
                "status": "failed",
                "seconds": time.monotonic() - start,
                "error": str(error),
            },
        )
        raise
    save(
        "build-attempt.json",
        {
            "attempt": 4,
            "status": "pass",
            "seconds": time.monotonic() - start,
            "binary_sha256": binaries,
        },
    )


def cases():
    assert read(R / "build-4.json")["status"] == "pass"
    result = read(R / "build-attempt.json")
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
        item = {"id": case_id, "invocation": 412 + index, "status": "admitted", "command": command}
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
    {"preflight": preflight, "build-4": build, "cases": cases}[name]()
