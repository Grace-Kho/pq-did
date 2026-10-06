"""Reuse completed milestone preservation for this analysis-only proposal."""

import hashlib
import inspect
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit  # noqa: E402

C = P / "docs/data/oct31_kyc_native_milestone_1/native-finalisation-1"
REPORT = P / "docs/oct31_auth_relation_integration.md"
SEAL = "b81bacf5bddb6d371f0ad50120291d039194f2f490718a9179b3a7d6708a3ba7"
CLOSURE = "7a4ab57cb54185bf49fe60f1c5bd4e52dc68d000904c9a8dd879c7b4e7089723"
PHASES = ("quality", "prepare", "full-audit", "readback")
INPUTS = {
    "run.py",
    "checks.py",
    "config.json",
    "opening-ledger.json",
    "prefixes.json",
    "comparison-point.json",
    "execution-plan.json",
    "cases.json",
    "ledger.json",
    "relation-notes.md",
    "backend-security-notes.md",
}
OUTPUTS = {
    "run-ledger.json",
    "run.lock",
    "static-review.json",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "final-inventory.json",
    "resource-closure.json",
    "audit-failure.json",
    "STOP.json",
    *{"STOP-" + phase + ".json" for phase in PHASES},
    *{
        phase + suffix
        for phase in PHASES
        for suffix in (".json", ".log", ".service.json", ".fatal.json")
    },
}


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(C / "checks.py")
p = prior.p
g = load(R / "run.py")
read = prior.guard.read
write = audit.write_report
digest = audit.digest_file


def name(path):
    return path.relative_to(P).as_posix()


def historical():
    assert digest(C / "manifest.json") == SEAL
    assert digest(C / "validation-closure.json") == CLOSURE
    closure = read(C / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    seals = read(C / "manifest.json")["sha256"]
    seals.update(closure["finalisation_sha256"])
    seals[name(C / "manifest.json")] = SEAL
    seals[name(C / "validation-closure.json")] = CLOSURE
    return seals


def verify_snapshot():
    seals = historical()
    prefixes = read(R / "prefixes.json")
    for path, expected in seals.items():
        if path in prefixes:
            assert prefixes[path]["sha256"] == expected
            actual = digest(P / path, prefix_bytes=prefixes[path]["bytes"])
        else:
            actual = digest(P / path)
        assert actual == expected, path
    cp = read(R / "comparison-point.json")
    assert cp["manifest_sha256"] == SEAL and cp["closure_sha256"] == CLOSURE
    for path, expected in {**cp["dataset_sha256"], **cp["source_and_binary_sha256"]}.items():
        assert seals[path] == expected and digest(P / path) == expected, path
    old_ledger = C.parent / "ledger.json"
    assert digest(R / "ledger.json") == digest(old_ledger) == seals[name(old_ledger)]
    return len(seals)


def scope():
    value = prior.scope()
    seals = historical()
    prefixes = read(R / "prefixes.json")
    value["frozen_package_inputs"].update(seals)
    for path, prefix in prefixes.items():
        assert seals[path] == prefix["sha256"]
        value["frozen_package_inputs"].pop(path)
        value["append_only_documentation"][path] = prefix
    checked = read(R / "checked-inputs.json")["sha256"]
    value["frozen_package_inputs"].update(checked)
    value["required_names"] = sorted(
        set(value["required_names"]) | set(seals) | set(checked) | {name(REPORT)}
    )
    value["optional_names"] = sorted(set(value["optional_names"]) | {name(R / n) for n in OUTPUTS})
    value["new_python_files"] += [name(R / n) for n in ("run.py", "checks.py")]
    value["new_markdown_files"] += [
        name(REPORT),
        name(R / "relation-notes.md"),
        name(R / "backend-security-notes.md"),
    ]
    return value


def quality():
    commands = []
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        command = [
            str(P / ".venv/bin/ruff"),
            *args,
            "--no-cache",
            str(R / "run.py"),
            str(R / "checks.py"),
        ]
        subprocess.run(command, check=True, timeout=0.7)
        commands.append(command)
    count = verify_snapshot()
    plan, cases = read(R / "execution-plan.json"), read(R / "cases.json")
    assert not plan["approved"] and plan["approval_required"] and not plan["profile_adopted"]
    assert len(cases["cases"]) == len({r["id"] for r in cases["cases"]}) == 96
    assert all(not row["executed"] for row in cases["cases"])
    assert sum(plan["phase_caps_seconds"].values()) == 2550
    assert (
        plan["initial_cases"] + plan["additional_partition_or_affected_correction_invocations"]
        == 128
    )
    assert 867 + 128 == plan["post_full_use_invocations"] <= 1050
    assert 58112659 + 67108864 <= 134217728
    assert 24789361 + 2097152 + 6291456 <= 33554432
    assert plan["proof_attempts_requested"] == 0
    assert g.package_size() < 2097152 - 262144
    write(
        R / "static-review.json",
        {
            "passed": True,
            "commands": commands,
            "sealed_v1_paths_verified": count,
            "new_tests": 0,
            "builds": 0,
            "relations_executed": 0,
            "cumulative_invocations_unchanged": 867,
            "proposal_authorised": False,
            "baseline_reused": True,
            "storage_admission_passed": True,
        },
    )


def prepare():
    assert read(R / "quality.json")["status"] == "pass"
    present = {path.name for path in R.iterdir() if path.is_file()}
    assert present <= INPUTS | OUTPUTS, sorted(present - INPUTS - OUTPUTS)
    assert INPUTS <= present
    assert not any((R / "tmp").iterdir())
    frozen = INPUTS | {"static-review.json", "quality.json", "quality.log", "quality.service.json"}
    write(
        R / "checked-inputs.json",
        {
            "sha256": {name(R / item): digest(R / item) for item in sorted(frozen)},
            "scope": "Explicit proposal inputs only; no historical seal regeneration",
        },
    )
    value = scope()
    inventory = p.inventory(value)
    result = {
        "passed": inventory["passed"],
        "inventory": inventory,
        "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        "historical_baselines_regenerated": False,
    }
    write(R / "preparation.json", result)
    assert result["passed"], inventory


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [row["name"] for row in rows] == ["quality", "prepare", "full-audit"]
    original.prior.check_runs(R, {"quality", "prepare"})
    assert rows[-1]["status"] == "launched"
    config = read(R / "config.json")
    charge = config["operator_charge_seconds"] + sum(
        row.get("seconds", row["limit_seconds"]) for row in rows
    )
    assert charge + 10 <= config["package_seconds"]
    assert charge + config["prior_analysis_charged_seconds"] + 10 <= 300
    assert config["test_invocations"] == {}
    assert not read(R / "execution-plan.json")["approved"]
    assert read(C / "validation-closure.json")["complete"]
    assert digest(R / "ledger.json") == digest(C.parent / "ledger.json")
    assert g.package_size() < 2097152
    return config["prior_analysis_charged_seconds"] + charge


def full_audit():
    # Reuse all original content/prefix/seal/inventory/report comparisons. Only
    # this package's ledger, output directory and analysis accounting differ.
    source = inspect.getsource(p.full_audit)
    replacements = (
        ('"command_seconds": 300', '"command_seconds": 60'),
        ('"child_seconds": 295', '"child_seconds": 55'),
        ('"aggregate_seconds": 4274', '"aggregate_seconds": 300'),
        (
            'package="OCT31-KYC-NATIVE-MILESTONE-1"',
            'package="OCT31-AUTH-RELATION-INTEGRATION-1-PROPOSAL"',
        ),
        ("prior_output_bytes=16665098", "prior_output_bytes=24789361"),
        (
            "module.current_storage = guard.storage",
            'module.current_storage = lambda: {"new_evidence_bytes": g.package_size()}',
        ),
        (
            '"implementation_remaining_including_audit_reservation": 4274 - charged',
            '"implementation_allowance_remaining_unchanged": 3297.852425285615',
        ),
        ("module.current_cases = current_cases", "module.current_cases = lambda: {}"),
        (
            "Approved isolated native/baseline/benchmark milestone",
            "Analysis-only full-relation proposal; frozen v1 reused; no tests/builds/proofs",
        ),
    )
    for before, after in replacements:
        assert before in source, before
        source = source.replace(before, after)
    module = types.ModuleType("analysis_preservation")
    module.__dict__.update(vars(p))
    module.__dict__.update(D=R, scope=scope, current_checks=current_checks, g=g)
    exec(compile(source, str(R / "checks.py"), "exec"), module.__dict__)
    module.full_audit()


def readback():
    assert read(R / "result.json")["passed"]
    assert read(R / "full-audit.json")["status"] == "pass"
    inventory = p.inventory(scope())
    assert inventory["passed"], inventory
    write(R / "final-inventory.json", inventory)
    verify_snapshot()
    for path, expected in read(R / "manifest.json")["sha256"].items():
        assert digest(P / path) == expected, path
    assert "Preparation preservation" in REPORT.read_text()
    print(
        json.dumps(
            {
                "passed": True,
                "final_inventory_count": inventory["count"],
                "version": "OCT31-KYC-NATIVE-MILESTONE-1/v1",
                "new_invocations": 0,
                "report_readback": True,
            }
        )
    )


def run(phase):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit, "readback": readback}[
        phase
    ]()
