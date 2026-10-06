"""Eight individually admitted synthetic tooling cases; no native execution."""

import copy
import json
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
OLD = R.parent / "compatibility-1"
policy = types.ModuleType("policy")
exec(compile((R / "policy.py").read_text(), str(R / "policy.py"), "exec"), policy.__dict__)
MIB = policy.MIB


def record(name):
    return copy.deepcopy(json.loads((OLD / (name + ".json")).read_text()))


def rejects(call, text):
    try:
        call()
    except ValueError as error:
        assert text in str(error), (text, str(error))
        return str(error)
    raise AssertionError("unexpected admission: " + text)


def case(n):
    # Every case executes inside the real 256 MiB tooling cgroup.
    location = next(
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    assert (
        Path("/sys/fs/cgroup") / location.lstrip("/") / "memory.max"
    ).read_text().strip() == str(256 * MIB)
    evidence, root = R / "tmp/synthetic-evidence", R / "tmp/synthetic-artifacts"
    if n == 1:
        row = record("preflight")
        row["service"]["after"]["memory.peak"] = str(500 * MIB)
        return policy.validate_record(row, "compatibility/preflight")
    if n == 2:
        row = record("preflight")
        row["service"]["after"]["memory.peak"] = str(1024 * MIB + 1)
        return rejects(
            lambda: policy.validate_record(row, "compatibility/preflight"), "cgroup memory excess"
        )
    if n == 3:
        row = record("quality")
        row["service"]["after"]["memory.peak"] = str(256 * MIB + 1)
        return rejects(
            lambda: policy.validate_record(row, "compatibility/quality"), "cgroup memory excess"
        )
    if n == 4:
        row = record("preflight")
        row["service"]["before"]["memory.max"] = str(2 * 1024 * MIB)
        results = [
            rejects(lambda: policy.validate_record(row, "unknown/preflight"), "unknown phase")
        ]
        results.append(
            rejects(
                lambda: policy.validate_record(row, "compatibility/preflight"),
                "unauthorised memory ceiling",
            )
        )
        row = record("preflight")
        row["stop"] = "synthetic recorded breach"
        results.append(
            rejects(
                lambda: policy.validate_record(row, "compatibility/preflight"),
                "recorded resource breach",
            )
        )
        return {"related_policy_assertions": results, "separate_parameterised_invocations": 0}
    if n == 5:
        with tempfile.TemporaryDirectory(prefix="roles-", dir=R / "tmp") as temp:
            base = Path(temp)
            evidence, root = base / "evidence", base / "artifacts"
            object_path = root / "build/exp2_native"
            data = {
                evidence / "renamed.o": b"log",
                root / "scratch/ccABC123.s": b"assembly",
                object_path: b"\x7fELFsynthetic",
                root / "build/renamed-diagnostic.o": b"diagnostic",
                root / "work/renamed.a": b"source",
            }
            for path, value in data.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
            rows = policy.walk_outputs(evidence) + policy.walk_outputs(root)
            measured = policy.account(rows, evidence, root, compiler_active=True)
            assert measured["evidence"] == len(b"logdiagnostic")
            assert measured["artifacts"] == sum(
                len(v) for k, v in data.items() if k.is_relative_to(root)
            )
            assert measured["scratch"] == 8
            assert measured["roles"][str(root / "work/renamed.a")] == "ordinary-source"
            assert policy.compiler_environment(root)["TMPDIR"] == str(root / "scratch")
            policy.enforce(measured)
            return {
                "bytes": measured,
                "actual_fixture_bytes": sum(map(len, data.values())),
                "cleanup": "TemporaryDirectory removes only these new synthetic files",
            }
    if n == 6:
        return rejects(
            lambda: policy.account(
                [(str(root / "build/exp2_native"), 32 * MIB + 1)],
                evidence,
                root,
                compiler_active=True,
            ),
            "artifact per-file limit",
        )
    if n == 7:
        slots = sorted(policy.output_slots(root))[:5]
        rows = [(str(path), 32 * MIB if i < 4 else 1) for i, path in enumerate(slots)]
        totals = policy.account(rows, evidence, root, compiler_active=True)
        return rejects(
            lambda: policy.enforce(totals, retained_artifacts=0), "aggregate artifact limit"
        )
    if n == 8:
        totals = policy.account([(str(evidence / "log-renamed.o"), 240001)], evidence, root)
        return rejects(lambda: policy.enforce(totals), "repair evidence reservation")
    raise ValueError("unlisted tooling case")


def run(name):
    if name == "tooling-rerun-1":
        target = R / "tooling-rerun-ledger.json"
        assert not target.exists()
        row = {"id": "RG-08", "invocation": 411, "status": "admitted", "rerun": True}
        target.write_text(json.dumps([row]) + "\n")
        command = [str(P / ".venv/bin/python"), "-I", "-B", str(R / "fixtures.py"), "8"]
        start = time.monotonic()
        out = subprocess.run(command, capture_output=True, timeout=1)
        (R / "RG-08-rerun-1.txt").write_bytes(out.stdout + out.stderr)
        row.update(
            status="pass" if out.returncode == 0 else "failed",
            seconds=time.monotonic() - start,
            command=command,
        )
        target.write_text(json.dumps([row], indent=2) + "\n")
        assert out.returncode == 0 and json.loads(out.stdout)["passed"]
        return
    assert name == "tooling"
    ledger = R / "tooling-ledger.json"
    assert not ledger.exists(), "no implicit retry"
    rows = []
    started = time.monotonic()
    for n in range(1, 9):
        assert time.monotonic() - started + 1 < 9, "tooling deadline reserve"
        row = {"id": f"RG-{n:02d}", "invocation": 402 + n, "status": "admitted", "rerun": False}
        rows.append(row)
        ledger.write_text(json.dumps(rows, indent=2) + "\n")
        command = [str(P / ".venv/bin/python"), "-I", "-B", str(R / "fixtures.py"), str(n)]
        before = time.monotonic()
        try:
            output = subprocess.run(command, capture_output=True, timeout=1)
            (R / f"RG-{n:02d}.txt").write_bytes(output.stdout + output.stderr)
            assert output.returncode == 0, output.stderr.decode(errors="replace")
            value = json.loads(output.stdout)
            assert value["id"] == row["id"] and value["passed"] is True
            row.update(status="pass", seconds=time.monotonic() - before, command=command)
        except Exception as error:
            row.update(status="failed", seconds=time.monotonic() - before, error=str(error))
            ledger.write_text(json.dumps(rows, indent=2) + "\n")
            raise
        ledger.write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    number = int(sys.argv[1])
    outcome = case(number)
    print(
        json.dumps(
            {"id": f"RG-{number:02d}", "passed": True, "synthetic": True, "outcome": outcome}
        )
    )
