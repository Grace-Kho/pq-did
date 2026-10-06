"""Extend the established auditor with this approved isolated package only."""

import hashlib
import inspect
import json
import sys
import types
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.implementation_consolidation_1 import run as guard  # noqa: E402
from scripts import preservation_audit as audit  # noqa: E402

D, N = guard.D, guard.N
A = P / "docs/data/oct31_joint_hash_masking_decision_1"
REPORT = "docs/implementation_consolidation.md"


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(P / "experiments/joint_hash_masking_decision_1/preservation.py")
p = prior.p


def name(path):
    return path.relative_to(P).as_posix()


def historical():
    approval = guard.read(D / "opening.json")
    assert audit.digest_file(A / "manifest.json") == approval["prior_manifest_sha256"]
    assert audit.digest_file(A / "validation-closure.json") == approval["prior_closure_sha256"]
    closure = guard.read(A / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    seals = guard.read(A / "manifest.json")["sha256"]
    seals.update(closure["finalisation_sha256"])
    seals[name(A / "manifest.json")] = approval["prior_manifest_sha256"]
    seals[name(A / "validation-closure.json")] = approval["prior_closure_sha256"]
    return seals


def scope():
    value = prior.scope()
    seals = historical()
    value["frozen_package_inputs"].update(seals)
    for path, prefix in guard.read(D / "prefixes.json").items():
        assert seals[path] == prefix["sha256"]
        value["frozen_package_inputs"].pop(path)
        value["append_only_documentation"][path] = prefix
    current = guard.read(D / "new-inventory.json")
    value["frozen_package_inputs"].update(current["sha256"])
    value["required_names"] = sorted(
        set(value["required_names"]) | set(seals) | set(current["required_names"])
    )
    value["optional_names"] = sorted(set(value["optional_names"]) | set(current["optional_names"]))
    for root in guard.ROOTS:
        path = name(root)
        if not any(
            path == old or path.startswith(old + "/")
            for old in value["additional_name_inventory_roots"]
        ):
            value["additional_name_inventory_roots"].append(path)
    value["new_python_files"] += current["python_files"]
    value["new_markdown_files"] += [REPORT, name(D / "handover.md"), name(D / "reproduction.md")]
    return value


def prepare():
    mutable = {
        "ledger.json",
        "ledger.lock",
        "execution.lock",
        "new-inventory.json",
        "preparation.json",
        "validation.json",
        "phases.json",
        "result.json",
        "validation-closure.json",
        "manifest.json",
        "final-inventory.json",
        "resource-closure.json",
        "audit-failure.json",
        "shutdown.json",
    }
    optional = {name(D / item) for item in mutable}
    for phase in ("prepare", "full-audit", "final-readback"):
        optional.update(
            name(D / "jobs" / (phase + suffix))
            for suffix in (".json", ".input.json", ".worker.json", ".log")
        )
    required, hashes, python = [], {}, []
    for root in guard.ROOTS:
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            assert not path.is_symlink(), name(path)
            path_name = name(path)
            required.append(path_name)
            if path_name not in optional:
                hashes[path_name] = audit.digest_file(path)
            if path.suffix == ".py":
                python.append(path_name)
    required.append(REPORT)
    assert (P / REPORT).is_file()
    guard.write(
        D / "new-inventory.json",
        {
            "required_names": required,
            "optional_names": sorted(optional),
            "sha256": hashes,
            "python_files": python,
            "scope": "New approved roots only; retained proposal/v1/baselines inherited strictly",
        },
    )
    value = scope()
    inventory = p.inventory(value)
    guard.write(
        D / "preparation.json",
        {
            "passed": inventory["passed"],
            "inventory": inventory,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
            "historical_baselines_regenerated": False,
        },
    )
    assert inventory["passed"], inventory


def current_checks(_):
    policy, ledger = guard.POLICY, guard.read(D / "ledger.json")
    assert sum(row["name"] == "full-audit" for row in ledger["jobs"]) == 1
    assert not ledger["invocations"] and not ledger["builds"]
    assert ledger["work_events_reserved"] == 0
    assert ledger["work_events"] <= policy["work_event_ceiling"]
    for ordinal, case in enumerate(ledger["invocations"], 1):
        assert case["ordinal"] == ordinal and case["cumulative_invocations"] == 974 + ordinal
        assert case["status"] in {"pass", "failed", "incomplete"}
        record = guard.read(D / "cases" / (case["invocation_id"] + ".json"))
        assert record["case_id"] == case["case_id"] and record["status"] == case["status"]
    for row in ledger["jobs"]:
        authorised = policy["phase_memory"][row["phase"]]
        assert row["memory_limit_bytes"] == authorised
        if row["status"] == "launched":
            assert row["name"] == "full-audit"
            continue
        assert row["stop"] is None, row["name"]
        measured = row["worker"]
        assert measured["before"]["memory.max"] == str(authorised)
        assert measured["before"]["memory.swap.max"] == "0"
        assert int(measured["after"]["memory.peak"]) <= authorised
        assert not measured["resource_breach"]
    charged = guard.consumed(ledger)
    assert charged <= policy["implementation_ceiling_seconds"]
    assert charged - policy["historical_seconds"] <= policy["milestone_seconds"]
    assert guard.read(D / "preparation.json")["passed"]
    assert guard.read(D / "preflight.json")["programme_complete"] is False
    assert ledger["work_events"] == 77593603 + sum(
        row["work_events"] for row in ledger["invocations"]
    )
    return charged


def full_audit():
    # Keep every historical comparison and reporting check. Substitute only the
    # approved package scope, accounting, phase policy and invocation opening.
    source = inspect.getsource(p.full_audit)
    for before, after in (
        ('package="OCT31-KYC-NATIVE-MILESTONE-1"', 'package="IMPLEMENTATION-CONSOLIDATION-1"'),
        ("prior_output_bytes=16665098", "prior_output_bytes=26774908"),
        ("lambda: 448 + len(", "lambda: 974 + len("),
        (
            "Approved isolated native/baseline/benchmark milestone",
            "Evidence consolidation; full original scope retained; no reruns",
        ),
    ):
        assert before in source, before
        source = source.replace(before, after)
    module = types.ModuleType("auth_relation_preservation")
    module.__dict__.update(vars(p))
    module.__dict__.update(D=D, guard=guard, scope=scope, current_checks=current_checks)
    exec(compile(source, str(Path(__file__)), "exec"), module.__dict__)
    module.full_audit()


def readback():
    assert guard.read(D / "validation.json")["passed"]
    assert guard.read(D / "jobs/full-audit.json")["status"] == "pass"
    inventory = p.inventory(scope())
    assert inventory["passed"], inventory
    guard.write(D / "final-inventory.json", inventory)
    for path, expected in guard.read(D / "manifest.json")["sha256"].items():
        assert audit.digest_file(P / path) == expected, path
    text = (P / REPORT).read_text()
    assert "Preservation" in text and "not complete private authentication" in text
    assert "Scope unchanged" in text and "Stages 2–3" in text
    print(
        json.dumps(
            {
                "passed": True,
                "final_inventory_count": inventory["count"],
                "report_readback": True,
                "full_relation_admitted": False,
            }
        )
    )


if __name__ == "__main__":
    {"prepare": prepare, "full-audit": full_audit, "readback": readback}[sys.argv[1]]()
