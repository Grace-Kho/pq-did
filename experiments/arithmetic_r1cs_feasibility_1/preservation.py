"""Extend the established auditor with this approved isolated package only."""

import hashlib
import inspect
import json
import sys
import types
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.arithmetic_r1cs_feasibility_1 import run as guard  # noqa: E402
from scripts import preservation_audit as audit  # noqa: E402

D, N = guard.D, guard.N
A = P / "docs/data/oct31_compact_auth_representation_1"
REPORT = "docs/oct31_arithmetic_r1cs_feasibility.md"


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(P / "experiments/compact_auth_representation_1/preservation.py")
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
    value["new_markdown_files"] += [REPORT, name(D / "contract.md")]
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
    assert len(ledger["invocations"]) <= 79 and len(ledger["builds"]) <= 3
    assert ledger["work_events_reserved"] == 0
    assert ledger["work_events"] <= policy["work_event_ceiling"]
    for ordinal, case in enumerate(ledger["invocations"], 1):
        assert case["ordinal"] == ordinal and case["cumulative_invocations"] == 971 + ordinal
        assert case["status"] in {"pass", "failed", "incomplete"}
        if case["invocation_id"] == "ARF1-0001":
            assert case["status"] == "incomplete"
            assert case["work_events_charged_upper_bound"] == 50000000
            assert not (D / "cases/ARF1-0001.json").exists()
            failure = guard.read(D / "reporting-correction.json")
            for path, expected in failure["preserved_sha256"].items():
                assert audit.digest_file(P / path) == expected
            assert "FileNotFoundError" in (D / "jobs/workload-decision.log").read_text()
        else:
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
        if row["name"] == "source-quality-final":
            assert row["status"] == "failed" and row["exit_code"] == 1
            assert measured == {} and row["argv"][0] == "--completion"
            retained = guard.read(D / "static-launch-failure.json")["properties"]
            assert retained["ActiveState"] == "failed" and retained["MainPID"] == "0"
            assert retained["ControlGroup"] == "" and retained["ExecMainStatus"] == "1"
            assert retained["MemoryMax"] == str(authorised)
            assert retained["MemorySwapMax"] == "0"
            assert 0 < int(retained["MemoryPeak"]) <= authorised
            # Preserve the missing worker record as a failed launch. This is
            # termination/resource evidence, never a successful static check.
            continue
        assert measured["before"]["memory.max"] == str(authorised)
        assert measured["before"]["memory.swap.max"] == "0"
        assert int(measured["after"]["memory.peak"]) <= authorised
        assert not measured["resource_breach"]
    charged = guard.consumed(ledger)
    assert charged <= policy["implementation_ceiling_seconds"]
    assert charged - policy["historical_seconds"] <= policy["milestone_seconds"]
    assert guard.read(D / "preparation.json")["passed"]
    assert guard.read(D / "whole-workload-model.json")["codewords_allocated"] == 0
    assert ledger["work_events"] == 27593603 + sum(
        row.get("work_events", row.get("work_events_charged_upper_bound", 0))
        for row in ledger["invocations"]
    )
    assert guard.read(D / "whole-workload-model.json") == guard.read(
        D / "whole-workload-model-r1.json"
    )
    return charged


def full_audit():
    # Keep every historical comparison and reporting check. Substitute only the
    # approved package scope, accounting, phase policy and invocation opening.
    source = inspect.getsource(p.full_audit)
    for before, after in (
        ('package="OCT31-KYC-NATIVE-MILESTONE-1"', 'package="OCT31-ARITHMETIC-R1CS-FEASIBILITY-1"'),
        ("prior_output_bytes=16665098", "prior_output_bytes=26326576"),
        ("lambda: 448 + len(", "lambda: 971 + len("),
        (
            "Approved isolated native/baseline/benchmark milestone",
            "Arithmetic prime-field contract; unchanged-hash and masking no-go; no proofs",
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
    assert "2 GiB" in text and "Stages 2–3" in text
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
