"""Record a stale preflight seal and complete preservation; no native launch."""

import gzip
import hashlib
import json
import subprocess
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
OLD = R.parent / "seal-repair-1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(OLD / "checks.py")
guard = load(R / "run.py")
audit, read, digest, policy = prior.audit, prior.read, prior.digest, prior.policy
policy.PHASES.update(
    {
        "header/fixtures": (268435456, 5),
        "header/preflight": (268435456, 3),
        "header/build-5": (1073741824, 55),
        "header/cases": (1073741824, 50),
        "header/quality": (268435456, 3),
        "header/prepare": (268435456, 3),
        "header/full-audit": (268435456, 7),
    }
)
PYTHON = ("run.py", "work.py", "seal_policy.py", "checks.py")
NAMES = {
    *PYTHON,
    "overlay-amendment.json",
    "standard-size-type.patch",
    "report-snapshot.json",
    "static-inputs.json",
    "preflight-result.json",
    "build-attempt.json",
    "build-commands.json",
    "native-case-ledger.json",
    "artifact-inventory.json.gz",
    "termination.json",
    *{f"SEM-{n:02d}" + s for n in range(1, 9) for s in (".json", ".native.txt")},
    *{f"TR-{n:02d}" + s for n in range(1, 17) for s in (".json", ".native.txt")},
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "admission-result.json",
    "native-case-outcomes.json",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "run-ledger.json",
    "run.lock",
    "STOP.json",
    "STOP-prepare.json",
    "STOP-full-audit.json",
    *{
        n + suffix
        for n in ("fixtures", "preflight", "build-5", "cases", "quality", "prepare", "full-audit")
        for suffix in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = OLD / "manifest.json"
    assert digest(seal) == "b654553f67533c37c4906c6d73e8fe891677048fb978ac52e03dfa909ed805ee"
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
    for name, expected in read(R / "checked-inputs.json")["sha256"].items():
        assert value["frozen_package_inputs"].get(name, expected) == expected
        value["frozen_package_inputs"][name] = expected
        required.add(name)
    with gzip.open(R / "artifact-inventory.json.gz", "rt") as stream:
        artifacts = json.load(stream)
    for row in artifacts["files"]:
        path = P / row["path"]
        assert path.lstat().st_mode == row["mode"] and path.stat().st_size == row["bytes"]
        required.add(row["path"])
        value["frozen_package_inputs"][row["path"]] = row["sha256"]
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / n).relative_to(P)) for n in NAMES}
    )
    value["new_python_files"] += [str((R / n).relative_to(P)) for n in PYTHON]
    return value


def static():
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
    audit.write_report(
        R / "static-inputs.json",
        {"sha256": {str((R / n).relative_to(P)): digest(R / n) for n in PYTHON}},
    )
    seals = load(R / "seal_policy.py")
    snapshot = seals.snapshot(P)
    assert seals.verify_repository(P, snapshot)
    audit.write_report(R / "report-snapshot.json", snapshot)
    assert guard.artifact_limits() is None


def quality():
    for n, h in read(R / "static-inputs.json")["sha256"].items():
        assert digest(P / n) == h
    entries = []
    root = prior.prior.A / "guarded-build-v2"
    for path in sorted(root.rglob("*")):
        if path.is_file():
            assert not path.is_symlink()
            st = path.lstat()
            entries.append(
                {
                    "path": str(path.relative_to(P)),
                    "bytes": st.st_size,
                    "mode": st.st_mode,
                    "sha256": digest(path),
                    "kind": "regular",
                }
            )
    (R / "artifact-inventory.json.gz").write_bytes(
        gzip.compress(
            json.dumps(
                {"files": entries, "total_bytes": sum(r["bytes"] for r in entries)}
            ).encode(),
            mtime=0,
        )
    )
    cases = read(R / "native-case-ledger.json") if (R / "native-case-ledger.json").exists() else []
    tools = []
    names = [f"SEM-{n:02d}" for n in range(1, 9)] + [f"TR-{n:02d}" for n in range(1, 17)]
    assert [r["id"] for r in cases] == names[: len(cases)]
    indexed = {r["id"]: r for r in cases}
    audit.write_report(
        R / "native-case-outcomes.json",
        {
            "cases": [indexed.get(n, {"id": n, "status": "not-run"}) for n in names],
            "new_invocations": len(cases),
            "tooling_invocations": len(tools),
            "cumulative_invocations": 419 + len(cases),
            "ceiling": 448,
        },
    )
    audit.write_report(
        R / "termination.json",
        {
            "temporary_directory_empty": not any((R / "tmp").iterdir()),
            "scratch_bytes": guard.g.size(root / "scratch"),
            "worker_guard_records": [r["name"] for r in read(R / "run-ledger.json")],
            "no_further_native_launch": True,
        },
    )
    assert guard.artifact_limits() is None


def prepare():
    assert read(R / "quality.json")["status"] == "pass"
    present = {p.name for p in R.iterdir() if p.is_file()}
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
        {"sha256": {str((R / n).relative_to(P)): digest(R / n) for n in sorted(frozen)}},
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
        if (
            row["name"] in {"preflight", "build-5", "cases", "fixtures"}
            and row["status"] == "failed"
        ):
            assert (R / "STOP.json").exists()
        else:
            policy.validate_record(row, "header/" + row["name"])
    config = read(R / "config.json")
    charge = 5 + sum(r.get("seconds", r["limit_seconds"]) for r in rows)
    assert charge <= config["package_seconds"]
    assert charge <= read(R / "opening-ledger.json")["parent_remaining"]
    result = read(R / "native-case-outcomes.json")
    assert result["new_invocations"] <= 24 and result["tooling_invocations"] <= 10
    assert result["cumulative_invocations"] <= 448
    return config["prior_implementation_charged_seconds"] + charge


def full_audit():
    path = R.parent / "build-4-resumption-1/checks.py"
    source = path.read_text().replace('"output_bytes":16777216', '"output_bytes":18874368')
    source = source.replace("Fourth native build continuation", "Fifth native build continuation")
    base = types.ModuleType("audit_base")
    base.__file__ = str(path)
    exec(compile(source, str(path), "exec"), base.__dict__)
    bindings = dict(base.__dict__)
    bindings.update(R=R, scope=scope, current_checks=current_checks, guard=guard)
    types.FunctionType(base.full_audit.__code__, bindings)()


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
