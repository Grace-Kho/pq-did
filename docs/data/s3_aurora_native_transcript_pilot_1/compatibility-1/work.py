"""One authorised native build and individually admitted public-input cases."""

import json
import os
import shutil
import subprocess
import time
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
C = P / "docs/data/s3_aurora_compiler_compatibility_contract_1"
OLD = R.parent / "reconciliation-1"
A = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
NEXT = A / "compatibility-v1"


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
    opening = read(R / "opening-ledger.json")
    assert sha(C / "manifest.json") == opening["contract_seal_sha256"]
    for name, expected in read(C / "manifest.json")["sha256"].items():
        assert sha(P / name) == expected, name
    for name, expected in read(C / "reviewed-inputs.json")["sha256"].items():
        assert sha(P / name) == expected, name
    proposal = read(C / "proposal.json")
    for name, expected in proposal["review_artifacts_sha256"].items():
        assert sha(C / name) == expected, name
    for name, expected in read(OLD / "native-inputs-v2.json")["sha256"].items():
        assert sha(P / name) == expected, name
    for row in read(R.parent / "case-plan.json")["cases"]:
        assert sha(P / row["retained_expectation"]) == row["retained_sha256"]
    guard = load(R / "run.py")
    assert guard.artifact_limits() is None
    assert guard.package_size() + 131072 < 393216
    assert 11654809 + 393216 < 12386485
    assert 1038442 + 393216 < 2097152
    assert guard.g.size(A) == 11228057
    assert not NEXT.exists()
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
    actions = []

    def run(argv):
        subprocess.run(argv, check=True, env=env, timeout=2)
        actions.append(argv)

    NEXT.mkdir()
    for name in ("work", "overlay"):
        run(["cp", "-a", str(A / name), str(NEXT / name)])
    for directory, patch in (
        (NEXT / "work/libiop", "variable-members.patch"),
        (NEXT / "overlay", "semantic-target.patch"),
    ):
        base = ["git", "--no-replace-objects", "-C", str(directory), "apply"]
        run([*base, "--check", str(C / patch)])
        run([*base, str(C / patch)])
    shutil.copyfile(C / "semantic_cases.cpp", NEXT / "overlay/semantic_cases.cpp")
    changed = "libiop/libiop/relations/variable.tcc"
    assert (
        sha(NEXT / "work" / changed) == read(C / "reviewed-inputs.json")["proposed_target_sha256"]
    )
    for path in (A / "work").rglob("*"):
        if path.is_file() and str(path.relative_to(A / "work")) != changed:
            assert sha(path) == sha(NEXT / "work" / path.relative_to(A / "work"))
    assert {
        str(p.relative_to(NEXT / "work")) for p in (NEXT / "work").rglob("*") if p.is_file()
    } == {str(p.relative_to(A / "work")) for p in (A / "work").rglob("*") if p.is_file()}
    for name in ("exp2_native.cpp", "canonical.bin", "nonce-mutated.bin"):
        assert sha(NEXT / "overlay" / name) == sha(A / "overlay" / name)
    assert (
        sha(NEXT / "overlay/semantic_cases.cpp")
        == proposal["review_artifacts_sha256"]["semantic_cases.cpp"]
    )
    save(
        "preflight-result.json",
        {
            "passed": True,
            "seconds": time.monotonic() - started,
            "commands": actions,
            "contract_sha256": opening["contract_seal_sha256"],
            "patch_sha256": sha(C / "variable-members.patch"),
            "postimage_sha256": sha(NEXT / "work" / changed),
            "native_sources_original_and_prior_work_preserved": True,
            "libff_workaround": "Unchanged binary/common target; no libff source correction",
            "latent_defects_review": {
                "free_field_times_term": "Not called: SEM uses term * field member",
                "merge_sort_coalesce": "Not called: C(term) copies one term via add_term",
                "empty_is_valid": "Not called by SEM or public Driver",
                "evaluation": "SEM index 3 has three assignments; index 0 needs none",
                "native_driver": "BCS rounds/hashchain; no R1CS construction or validation",
            },
            "expectations": "Literal GF(2^192) polynomial arithmetic; sealed TR golden JSON",
            "new_builds": 0,
            "new_cases": 0,
        },
    )


def build():
    assert read(R / "preflight.json")["status"] == "pass"
    assert read(R / "preflight-result.json")["passed"]
    assert not (R / "build-attempt.json").exists()
    proposal = read(C / "proposal.json")
    commands = [proposal["configure_argv"], proposal["build_argv"]]
    save(
        "build-commands.json",
        {"commands": commands, "environment": proposal["command_environment"]},
    )
    save("build-attempt.json", {"attempt": 3, "ceiling": 3, "status": "admitted"})
    env = dict(os.environ, CCACHE_DISABLE="1")
    for name in proposal["command_environment"]["unset"]:
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
                "attempt": 3,
                "status": "failed",
                "seconds": time.monotonic() - start,
                "error": str(error),
            },
        )
        raise
    save(
        "build-attempt.json",
        {
            "attempt": 3,
            "status": "pass",
            "seconds": time.monotonic() - start,
            "binary_sha256": binaries,
        },
    )


def cases():
    assert read(R / "build-3.json")["status"] == "pass"
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
        item = {"id": case_id, "invocation": 403 + index, "status": "admitted", "command": command}
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
    {"preflight": preflight, "build-3": build, "cases": cases}[name]()
