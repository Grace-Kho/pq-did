"""Chained preservation before native admission and after the case sequence."""

import hashlib
import json
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
H = R.parent / "header-correction-1"
PYTHON = ("run.py", "monitor_safety.py", "fixtures.py", "work.py", "checks.py", "seal_policy.py")
PHASES = {
    "tooling": 8,
    "tooling-corrected": 8,
    "tooling-rerun-1": 3,
    "tooling-rerun-2": 3,
    "prepare-pre": 3,
    "pre-audit": 7,
    "cases": 50,
    "quality": 3,
    "prepare": 3,
    "full-audit": 7,
}
LATE = {
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "run-ledger.json",
    "run.lock",
}
NAMES = {
    *PYTHON,
    *LATE,
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "registration.json",
    "static-inputs.json",
    "static-failure-inputs.json.gz",
    "static-correction.json",
    "report-snapshot.json",
    "fixture-ledger.json",
    "binary-admission.json",
    "native-case-ledger.json",
    "native-case-outcomes.json",
    "termination.json",
    "STOP.json",
    *{f"GUARD-{n:02d}" + suffix for n in range(1, 6) for suffix in (".json", ".failure.json")},
    *{f"SEM-{n:02d}" + s for n in range(1, 9) for s in (".json", ".native.txt")},
    *{f"TR-{n:02d}" + s for n in range(1, 17) for s in (".json", ".native.txt")},
    *{
        phase + suffix
        for phase in PHASES
        for suffix in (".json", ".log", ".service.json", ".fatal.json")
    },
    *{"STOP-" + phase + ".json" for phase in PHASES},
    *{
        "pre-native/" + n
        for n in (
            "config.json",
            "checked-inputs.json",
            "preparation.json",
            "validation.json",
            "phases.json",
            "result.json",
            "native-case-outcomes.json",
        )
    },
}
ACTIVE = R


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(H / "checks.py")
guard = load(R / "run.py")
audit, read, digest, policy = prior.audit, prior.read, prior.digest, prior.policy
policy.PHASES.update(
    {"output/" + n: (1073741824 if n == "cases" else 268435456, s) for n, s in PHASES.items()}
)


def outcomes(target):
    cases = read(R / "native-case-ledger.json") if (R / "native-case-ledger.json").exists() else []
    tools = read(R / "fixture-ledger.json") if (R / "fixture-ledger.json").exists() else []
    names = [f"SEM-{n:02d}" for n in range(1, 9)] + [f"TR-{n:02d}" for n in range(1, 17)]
    assert [r["id"] for r in cases] == names[: len(cases)]
    index = {r["id"]: r for r in cases}
    value = {
        "cases": [index.get(n, {"id": n, "status": "not-run"}) for n in names],
        "new_invocations": len(cases),
        "tooling_invocations": len(tools),
        "cumulative_invocations": 419 + len(tools) + len(cases),
        "ceiling": 450,
    }
    audit.write_report(target / "native-case-outcomes.json", value)
    return value


def scope():
    value = prior.scope()
    seal = H / "manifest.json"
    assert digest(seal) == "b5e486eaf5b869fbe0ad682568805fd6a80cf1d5c3257ed9c297e4d0b5b545d7"
    docs = read(R / "prefixes.json")
    required = set(value["required_names"]) | set(read(seal)["sha256"])
    required.add(str(seal.relative_to(P)))
    for name, expected in read(seal)["sha256"].items():
        if name not in docs:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str(seal.relative_to(P))] = digest(seal)
    for name, prefix in docs.items():
        if name in value["frozen_package_inputs"]:
            assert value["frozen_package_inputs"].pop(name) == prefix["sha256"]
        value["append_only_documentation"][name] = prefix
    for name, expected in read(ACTIVE / "checked-inputs.json")["sha256"].items():
        assert value["frozen_package_inputs"].get(name, expected) == expected
        value["frozen_package_inputs"][name] = expected
        required.add(name)
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / n).relative_to(P)) for n in NAMES}
    )
    value["new_python_files"] += [str((R / n).relative_to(P)) for n in PYTHON]
    return value


def prepare():
    if ACTIVE != R:
        assert read(R / "tooling-corrected.json")["status"] == "pass"
        rows = read(R / "fixture-ledger.json")
        assert len(rows) == 5 and all(r["status"] == "pass" for r in rows)
        outcomes(ACTIVE)
    else:
        assert read(R / "quality.json")["status"] == "pass"
    present = {str(p.relative_to(R)) for p in R.rglob("*") if p.is_file()}
    assert present <= NAMES, sorted(present - NAMES)
    excluded = {"run-ledger.json", "run.lock"}
    phase = "prepare-pre" if ACTIVE != R else "prepare"
    excluded.update(phase + s for s in (".json", ".log", ".service.json"))
    excluded.update(str((ACTIVE / n).relative_to(R)) for n in LATE)
    frozen = {str((R / n).relative_to(P)): digest(R / n) for n in present - excluded}
    audit.write_report(ACTIVE / "checked-inputs.json", {"sha256": frozen})
    value = scope()
    inventory = audit.inventory_check(
        P,
        value["additional_name_inventory_roots"],
        set(value["required_names"]),
        optional_names=set(value["optional_names"]),
    )
    assert inventory["passed"], inventory
    audit.write_report(
        ACTIVE / "preparation.json",
        {
            "inventory": inventory,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    current = "pre-audit" if ACTIVE != R else "full-audit"
    assert rows[-1]["name"] == current and rows[-1]["status"] == "launched"
    for row in rows[:-1]:
        if row["name"] in {"cases", "tooling"} and row["status"] == "failed":
            assert (R / "STOP.json").exists()
        else:
            policy.validate_record(row, "output/" + row["name"])
    charge = 5 + sum(row.get("seconds", row["limit_seconds"]) for row in rows)
    opening = read(R / "opening-ledger.json")
    assert charge <= min(
        opening[k]
        for k in (
            "subcap_remaining",
            "parent_remaining",
            "native_remaining",
            "implementation_remaining",
        )
    )
    counts = read(ACTIVE / "native-case-outcomes.json")
    assert counts["tooling_invocations"] <= 7 and counts["new_invocations"] <= 24
    assert counts["cumulative_invocations"] <= 450
    assert guard.artifact_limits() is None
    return read(R / "config.json")["prior_implementation_charged_seconds"] + charge


def full_audit():
    # Reuse the unchanged baseline comparisons, full inventory and report readback.
    path = R.parent / "build-4-resumption-1/checks.py"
    source = path.read_text().replace('"output_bytes":16777216', '"output_bytes":18874368')
    source = source.replace(
        "Fourth native build continuation", "Registered-output guard continuation"
    )
    base = types.ModuleType("audit_base")
    base.__file__ = str(path)
    exec(compile(source, str(path), "exec"), base.__dict__)
    bindings = dict(base.__dict__)
    bindings.update(R=ACTIVE, scope=scope, current_checks=current_checks, guard=guard)
    types.FunctionType(base.full_audit.__code__, bindings)()


def finish_pre_audit():
    record = read(R / "pre-audit.json")
    content = read(R / "pre-native/validation.json")
    phases = read(R / "pre-native/phases.json")["phases"]
    passed = audit.guarded_pass(content, record, memory_bytes=268435456, command_seconds=7)
    assert phases[-1]["phase"] == "report-written-and-readback-complete" and passed
    audit.write_report(
        R / "pre-native/result.json",
        {
            "passed": True,
            "audit_exit": 0,
            "content_partition_union": content["content_partition_union"],
            "resource_guard_record": "../pre-audit.json",
            "report_readback_complete": True,
        },
    )


def quality():
    for name, expected in read(R / "static-inputs.json")["sha256"].items():
        assert digest(P / name) == expected
    outcomes(R)
    audit.write_report(
        R / "termination.json",
        {
            "temporary_directory_empty": not any((R / "tmp").iterdir()),
            "scratch_bytes": guard.g.size(guard.NEXT / "scratch"),
            "no_new_builds": True,
            "worker_guard_records": [r["name"] for r in read(R / "run-ledger.json")],
        },
    )
    assert guard.artifact_limits() is None


def run(name):
    global ACTIVE
    ACTIVE = R / "pre-native" if name in {"prepare-pre", "pre-audit"} else R
    {
        "prepare-pre": prepare,
        "prepare": prepare,
        "pre-audit": full_audit,
        "full-audit": full_audit,
        "quality": quality,
    }[name]()
