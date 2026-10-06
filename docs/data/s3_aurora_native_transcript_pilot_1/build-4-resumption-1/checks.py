"""Read-only fourth-build admission and one preservation finalisation."""

import gzip
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
OLD = R.parent / "build-4-admission-1"
PREVIOUS = R.parent / "reconciliation-1"
A = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
sys.dont_write_bytecode = True


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(OLD / "checks.py")
guard = load(R / "run.py")
policy = load(R.parent / "resource-guard-repair-1/policy.py")
policy.PHASES.update(
    {
        "resumption/preflight": (268435456, 3),
        "resumption/build-4": (1073741824, 55),
        "resumption/cases": (1073741824, 50),
        "resumption/quality": (268435456, 3),
        "resumption/prepare": (268435456, 3),
        "resumption/full-audit": (268435456, 7),
    }
)
audit, read, digest = prior.audit, prior.read, prior.digest
PYTHON = ("run.py", "work.py", "checks.py")
NAMES = {
    *PYTHON,
    "preflight-inputs.json.gz",
    "preflight-result.json",
    "build-attempt.json",
    "build-commands.json",
    "native-case-ledger.json",
    "artifact-inventory.json.gz",
    "termination.json",
    *{(f"SEM-{n:02d}" + s) for n in range(1, 9) for s in (".json", ".native.txt")},
    *{(f"TR-{n:02d}" + s) for n in range(1, 17) for s in (".json", ".native.txt")},
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "run-ledger.json",
    "run.lock",
    "STOP.json",
    "STOP-prepare.json",
    "STOP-full-audit.json",
    "admission-result.json",
    "native-case-outcomes.json",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    *{
        n + suffix
        for n in ("preflight", "build-4", "cases", "quality", "prepare", "full-audit")
        for suffix in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = OLD / "manifest.json"
    assert digest(seal) == "3dc73504668e70fc011e3ddd97d02fabdf930fc780ac17005730fbd015cb26cf"
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
        assert path.lstat().st_mode == row["mode"] and path.stat().st_size == row["bytes"]
        required.add(row["path"])
        value["frozen_package_inputs"][row["path"]] = row["sha256"]
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / name).relative_to(P)) for name in NAMES}
    )
    value["new_python_files"] += [str((R / name).relative_to(P)) for name in PYTHON]
    return value


def quality():
    files = [str(R / n) for n in PYTHON]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.5
        )
    rows = []
    root = A / "guarded-build-v1"
    for path in sorted(root.rglob("*")):
        if path.is_file():
            st = path.lstat()
            assert not path.is_symlink()
            rows.append(
                {
                    "path": str(path.relative_to(P)),
                    "bytes": st.st_size,
                    "mode": st.st_mode,
                    "kind": "regular",
                    "sha256": digest(path),
                }
            )
    (R / "artifact-inventory.json.gz").write_bytes(
        gzip.compress(
            json.dumps({"files": rows, "total_bytes": sum(r["bytes"] for r in rows)}).encode(),
            mtime=0,
        )
    )
    cases = read(R / "native-case-ledger.json") if (R / "native-case-ledger.json").exists() else []
    names = [f"SEM-{n:02d}" for n in range(1, 9)] + [f"TR-{n:02d}" for n in range(1, 17)]
    assert [r["id"] for r in cases] == names[: len(cases)]
    indexed = {r["id"]: r for r in cases}
    audit.write_report(
        R / "native-case-outcomes.json",
        {
            "cases": [indexed.get(n, {"id": n, "status": "not-run"}) for n in names],
            "new_invocations": len(cases),
            "cumulative_invocations": 411 + len(cases),
            "ceiling": 438,
        },
    )
    audit.write_report(
        R / "termination.json",
        {
            "temporary_directory_empty": not any((R / "tmp").iterdir()),
            "compiler_scratch_retained_bytes": guard.g.size(root / "scratch"),
            "new_workload_launched": False,
            "build_record": "build-4.json",
        },
    )
    assert guard.artifact_limits() is None


def prepare():
    assert read(R / "quality.json")["status"] == "pass"
    present = {path.name for path in R.iterdir() if path.is_file()}
    assert present <= NAMES, sorted(present - NAMES)
    frozen = present - {
        "run-ledger.json",
        "run.lock",
        "prepare.json",
        "prepare.log",
        "prepare.service.json",
    }
    audit.write_report(
        R / "checked-inputs.json",
        {
            "sha256": {str((R / n).relative_to(P)): digest(R / n) for n in sorted(frozen)},
            "new_builds": int((R / "build-attempt.json").exists()),
            "new_native_invocations": read(R / "native-case-outcomes.json")["new_invocations"],
        },
    )
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
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert rows[-1]["name"] == "full-audit" and rows[-1]["status"] == "launched"
    for row in rows[:-1]:
        if row["name"] in {"preflight", "build-4", "cases"} and row["status"] == "failed":
            assert (R / "STOP.json").exists()
        else:
            policy.validate_record(row, "resumption/" + row["name"])
    charge = 5 + sum(r.get("seconds", r["limit_seconds"]) for r in rows)
    assert charge <= read(R / "config.json")["package_seconds"]
    cases = read(R / "native-case-outcomes.json")
    assert cases["new_invocations"] <= 24 and cases["cumulative_invocations"] <= 435
    return read(R / "config.json")["prior_implementation_charged_seconds"] + charge


def full_audit():
    assert (
        hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest()
        == read(R / "preparation.json")["scope_sha256"]
    )
    path = PREVIOUS / "checks.py"
    text = path.read_text()
    function = text[text.index("def full_audit():") : text.index("\ndef run(")]
    function = function.replace(
        "Reconciled trees/provisioned pins; two failed native builds; zero native cases",
        "Fourth native build continuation; individual outcomes retained without retries",
    ).replace('including_prior_package": 402', 'including_prior_package": 411')
    function = function.replace('"output_bytes":12386485', '"output_bytes":16777216')
    count = read(R / "native-case-outcomes.json")["cumulative_invocations"]
    function = function.replace(
        'including_prior_package": 411', 'including_prior_package": ' + str(count)
    )
    module = types.ModuleType("audit_wrapper")
    module.__dict__.update(globals())
    exec(compile(function, str(path), "exec"), module.__dict__)
    module.full_audit()


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
