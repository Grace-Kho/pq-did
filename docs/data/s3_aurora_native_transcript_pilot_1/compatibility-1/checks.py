"""Finalise the stopped third build using the existing preservation workflow."""

import gzip
import hashlib
import json
import os
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
C = P / "docs/data/s3_aurora_compiler_compatibility_contract_1"
PREVIOUS = R.parent / "reconciliation-1"
A = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/compatibility-v1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
sys.dont_write_bytecode = True


def load(path):
    m = types.ModuleType(path.stem)
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    return m


prior = load(C / "checks.py")
guard = load(R / "run.py")
audit, read, digest = prior.audit, prior.read, prior.digest
PYTHON = ("run.py", "work.py", "checks.py")
NAMES = {
    *PYTHON,
    "executed-run.py",
    "executed-work.py",
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "source-preparation-diagnostic.json",
    "run-ledger.json",
    "run.lock",
    "STOP.json",
    "STOP-quality.json",
    "STOP-prepare.json",
    "STOP-full-audit.json",
    "preflight-result.json",
    "build-attempt.json",
    "build-commands.json",
    "build-outcome.json",
    "native-case-outcomes.json",
    "termination.json",
    "artifact-inventory.json.gz",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "finalisation.py",
    *{
        n + s
        for n in ("preflight", "build-3", "quality", "prepare", "full-audit")
        for s in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = C / "manifest.json"
    assert digest(seal) == "4c2c86e74ed7e5614861c002684257b48deffbe3247a413726e8042669ee2173"
    required = set(value["required_names"]) | set(read(seal)["sha256"])
    required.add(str(seal.relative_to(P)))
    for name, expected in read(seal)["sha256"].items():
        if name not in DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str(seal.relative_to(P))] = digest(seal)
    for name, prefix in read(R / "prefixes.json").items():
        if name in value["frozen_package_inputs"]:
            assert value["frozen_package_inputs"].pop(name) == prefix["sha256"]
        value["append_only_documentation"][name] = prefix
    checked = read(R / "checked-inputs.json")["sha256"]
    for name, expected in checked.items():
        assert value["frozen_package_inputs"].get(name, expected) == expected
        value["frozen_package_inputs"][name] = expected
    required.update(checked)
    with gzip.open(R / "artifact-inventory.json.gz", "rt") as stream:
        artifacts = json.load(stream)
    for row in artifacts["files"]:
        path = P / row["path"]
        required.add(row["path"])
        assert path.lstat().st_mode == row["mode"] and path.lstat().st_size == row["bytes"]
        if row["kind"] == "regular":
            assert not path.is_symlink()
            value["frozen_package_inputs"][row["path"]] = row["sha256"]
        else:
            assert path.is_symlink() and os.readlink(path) == row["target"]
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / name).relative_to(P)) for name in NAMES}
    )
    value["new_python_files"] += [str((R / name).relative_to(P)) for name in PYTHON]
    return value


def quality():
    files = [str(R / name) for name in PYTHON]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.5
        )
    inputs = read(C / "reviewed-inputs.json")
    assert (
        digest(A / "work/libiop/libiop/relations/variable.tcc") == inputs["proposed_target_sha256"]
    )
    for row in read(R.parent / "case-plan.json")["cases"]:
        assert digest(P / row["retained_expectation"]) == row["retained_sha256"]
    assert read(R / "native-case-outcomes.json")["admitted_native_invocations"] == 0
    assert read(R / "termination.json")["temporary_directory_empty"]
    rows = []
    for base, dirs, names in os.walk(A):
        for name in list(dirs):
            if (Path(base) / name).is_symlink():
                names.append(name)
                dirs.remove(name)
        for name in names:
            path = Path(base) / name
            stat = path.lstat()
            row = {"path": str(path.relative_to(P)), "bytes": stat.st_size, "mode": stat.st_mode}
            if path.is_symlink():
                row.update(kind="symlink", target=os.readlink(path))
            else:
                assert path.is_file()
                row.update(kind="regular", sha256=digest(path))
            rows.append(row)
    (R / "artifact-inventory.json.gz").write_bytes(
        gzip.compress(
            json.dumps(
                {
                    "purpose": "Partial third build retained; no linking or native case success",
                    "files": sorted(rows, key=lambda row: row["path"]),
                    "total_bytes": sum(row["bytes"] for row in rows),
                }
            ).encode(),
            mtime=0,
        )
    )
    assert guard.artifact_limits() is None
    present = {path.name for path in R.iterdir() if path.is_file()}
    assert present <= NAMES, sorted(present - NAMES)
    frozen = present - {
        "run-ledger.json",
        "run.lock",
        "quality.json",
        "quality.log",
        "quality.service.json",
    }
    audit.write_report(
        R / "checked-inputs.json",
        {
            "sha256": {str((R / name).relative_to(P)): digest(R / name) for name in sorted(frozen)},
            "native_invocations": 0,
            "build_attempts_used": 3,
        },
    )


def prepare():
    value = scope()
    result = audit.inventory_check(
        P,
        value["additional_name_inventory_roots"],
        set(value["required_names"]),
        optional_names=set(value["optional_names"]),
    )
    assert result["passed"], result
    audit.write_report(
        R / "preparation.json",
        {
            "inventory": result,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
            "historical_repairs_build_failures_and_original_baselines_retained": True,
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [row["name"] for row in rows] == [
        "preflight",
        "build-3",
        "quality",
        "prepare",
        "full-audit",
    ]
    original.prior.check_runs(R, {"preflight", "quality", "prepare"})
    assert rows[1]["status"] == "failed" and rows[1]["stop"] == "diagnostic/package output stop"
    assert all(row["status"] in {"pass", "launched"} for row in [rows[0], *rows[2:]])
    charge = 5 + sum(row.get("seconds", row["limit_seconds"]) for row in rows)
    assert charge <= 150 and charge <= 264.3718736843439
    assert 405.07074665662367 + charge <= 674
    assert read(R / "native-case-outcomes.json")["admitted_native_invocations"] == 0
    assert read(R / "build-attempt.json")["attempt"] == 3
    assert read(R / "termination.json")["passed"]
    assert not (A / "build/exp2_native").exists() and not (A / "build/exp2_semantics").exists()
    return 405.07074665662367 + charge


def full_audit():
    expected = read(R / "preparation.json")["scope_sha256"]
    assert hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest() == expected
    path = PREVIOUS / "checks.py"
    text = path.read_text()
    begin, end = text.index("def full_audit():"), text.index("\ndef run(")
    function = text[begin:end].replace(
        "Reconciled trees/provisioned pins; two failed native builds; zero native cases",
        "Third build guard-stopped; zero semantic/transcript invocations; preservation only",
    )
    m = types.ModuleType("audit_wrapper")
    m.__dict__.update(globals())
    exec(compile(function, str(path), "exec"), m.__dict__)
    m.full_audit()


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
