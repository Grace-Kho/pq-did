"""Inherited complete audit; explicit new roots and protected historical prefixes."""

import hashlib
import inspect
import json
import sys
import types
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_domain_mask_correction_1 import run as guard  # noqa: E402
from scripts import preservation_audit as audit  # noqa: E402

D, N = guard.D, guard.N
A = P / "docs/data/ligetron_correction_admission_1"
REPORTS = ("docs/ligetron_domain_mask_correction.md",)


def load(path):
    m = types.ModuleType(path.stem)
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    return m


prior = load(P / "experiments/ligetron_correction_admission_1/preservation.py")
p = prior.p


def name(path):
    return path.relative_to(P).as_posix()


def historical():
    opening = guard.read(D / "opening.json")
    assert audit.digest_file(A / "manifest.json") == opening["prior_manifest_sha256"]
    assert audit.digest_file(A / "validation-closure.json") == opening["prior_closure_sha256"]
    closure = guard.read(A / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    result = guard.read(A / "manifest.json")["sha256"]
    result.update(closure["finalisation_sha256"])
    result[name(A / "manifest.json")] = opening["prior_manifest_sha256"]
    result[name(A / "validation-closure.json")] = opening["prior_closure_sha256"]
    return result


def historical_scope():
    value = prior.scope()
    value["frozen_package_inputs"].update(historical())
    return value


def scope():
    value = historical_scope()
    value["frozen_package_inputs"]["PQ_DID_Ligetron_Domain_Mask_Followup.zip"] = guard.read(
        D / "opening.json"
    )["input_sha256"]
    for path, prefix in guard.read(D / "prefixes.json").items():
        expected = value["frozen_package_inputs"].get(path)
        assert expected == prefix["sha256"], path
        value["frozen_package_inputs"].pop(path)
        value["append_only_documentation"][path] = prefix
    # Exact approved documentation appendix; its sealed historical prefix remains checked.
    value["original_permitted_documentation"] = sorted(
        set(value["original_permitted_documentation"]) | {"benchmarks/README.md"}
    )
    current = guard.read(D / "new-inventory.json")
    value["frozen_package_inputs"].update(current["sha256"])
    value["required_names"] = sorted(
        set(value["required_names"])
        | set(historical())
        | set(current["required_names"])
        | {"PQ_DID_Ligetron_Domain_Mask_Followup.zip"}
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
    value["new_markdown_files"] += list(REPORTS)
    return value


def partitioned_inventory(root, directories, expected_names, *, optional_names=frozenset()):
    files = {
        "PQ_DID_Ligetron_Correction_Handover.zip",
        "PQ_DID_Ligetron_Domain_Mask_Followup.zip",
    } & set(expected_names)
    result = p.partitioned_inventory(
        root, directories, set(expected_names) - files, optional_names=optional_names
    )
    if files:
        frozen = historical_scope()["frozen_package_inputs"]
        frozen["PQ_DID_Ligetron_Domain_Mask_Followup.zip"] = guard.read(D / "opening.json")[
            "input_sha256"
        ]
        for path in sorted(files):
            assert audit.digest_file(root / path) == frozen[path], path
            result["partitions"].append(
                {
                    "root": path,
                    "kind": "sealed root file",
                    "passed": True,
                    "count": 1,
                    "expected_count": 1,
                    "unexpected": [],
                    "missing": [],
                }
            )
        result["count"] += len(files)
        result["expected_union_count"] += len(files)
        result["expected_total_count"] += len(files)
    return result


def inventory(value):
    return partitioned_inventory(
        P,
        value["additional_name_inventory_roots"],
        set(value["required_names"]),
        optional_names=set(value["optional_names"]),
    )


def prepare():
    mutable = {
        "ledger.json",
        "ledger.lock",
        "execution.lock",
        "new-inventory.json",
        "preparation.json",
        "preparation-corrected.json",
        "preparation-corrected-v2.json",
        "preparation-corrected-v3.json",
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
    optional = {name(D / x) for x in mutable}
    for phase in (
        "prepare",
        "prepare-2",
        "prepare-3",
        "prepare-4",
        "full-audit",
        "full-audit-2",
        "readback",
    ):
        optional.update(
            name(D / "jobs" / (phase + s)) for s in (".json", ".input.json", ".worker.json", ".log")
        )
    required = []
    hashes = {}
    python = []
    for root in guard.ROOTS:
        for f in sorted(root.rglob("*")):
            if f.is_dir():
                continue
            assert not f.is_symlink()
            path = name(f)
            required.append(path)
            if path not in optional:
                hashes[path] = audit.digest_file(f)
            if f.suffix == ".py":
                python.append(path)
    required += list(REPORTS)
    guard.write(
        D / "new-inventory.json",
        {
            "required_names": required,
            "optional_names": sorted(optional),
            "sha256": hashes,
            "python_files": python,
            "historical_baselines_regenerated": False,
        },
    )
    value = scope()
    inv = inventory(value)
    guard.write(
        D / "preparation-corrected-v3.json",
        {
            "passed": inv["passed"],
            "inventory": inv,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        },
    )
    assert inv["passed"], inv


def current_checks(_):
    rows = guard.read(D / "ledger.json")
    assert len(rows["invocations"]) == 32 and len(rows["builds"]) == 2
    assert rows["work_events"] == 144593603 and rows["work_events_reserved"] == 0
    assert [r["name"] for r in rows["jobs"] if r["name"].startswith("full-audit")] == [
        "full-audit",
        "full-audit-2",
    ]
    for i, row in enumerate(rows["invocations"], 1):
        assert row["status"] == "pass" and row["cumulative_invocations"] == 1218 + i
        result = guard.read(D / "cases" / (row["invocation_id"] + ".json"))
        assert result["status"] == "pass" and result["exit_code"] == 0
    assert {r["case_id"] for r in rows["invocations"]} == set(
        guard.read(D / "execution-plan.json")["cases"]
    )
    failures = {"source-admission", "static", "preflight", "build-1", "prepare", "full-audit"}
    for row in rows["jobs"]:
        limit = guard.POLICY["phase_memory"][row["phase"]]
        assert row["memory_limit_bytes"] == limit
        if row["status"] == "launched":
            assert row["name"] == "full-audit-2"
            continue
        assert row["stop"] is None and not row["worker"]["resource_breach"]
        assert int(row["worker"]["after"]["memory.peak"]) <= limit
        assert row["status"] == ("failed" if row["name"] in failures else "pass")
    assert guard.read(D / "preflight.json")["passed"]
    assert guard.read(D / "build-2-result.json")["passed"]
    original = guard.read(D / "build-input-seal.json")["sha256"]
    amendment = guard.read(D / "case-driver-amendment.json")
    assert original[amendment["path"]] == amendment["prior_sha256"]
    original[amendment["path"]] = amendment["current_sha256"]
    for path, expected in original.items():
        assert audit.digest_file(P / path) == expected, path
    opening = guard.read(D / "opening.json")
    assert (
        guard.POLICY["historical_seconds"]
        == opening["prior_resources"]["implementation_aggregate_charged_seconds"]
    )
    assert (
        guard.POLICY["KYC_unchanged"]
        == opening["prior_resources"]["KYC_remaining_seconds_unchanged"]
    )
    charge = guard.consumed(rows)
    assert charge - guard.POLICY["historical_seconds"] <= 360
    return charge


def full_audit():
    source = inspect.getsource(p.full_audit)
    source = source.replace('D / "preparation.json"', 'D / "preparation-corrected-v3.json"')
    for before, after in (
        ('package="OCT31-KYC-NATIVE-MILESTONE-1"', 'package="LIGETRON-DOMAIN-MASK-CORRECTION-1"'),
        ("prior_output_bytes=16665098", "prior_output_bytes=37617783"),
        ("lambda: 448 + len(", "lambda: 1218 + len("),
        ('"aggregate_seconds": 4274', '"aggregate_seconds": 6674'),
        ('"output_bytes": 33554432', '"output_bytes": 41943040'),
        ("4274 - charged", "6674 - charged"),
        (
            "Approved isolated native/baseline/benchmark milestone",
            "Approved isolated domain/mask component; no private proofs",
        ),
    ):
        assert before in source, before
        source = source.replace(before, after)
    m = types.ModuleType("delivery_audit")
    m.__dict__.update(vars(p))
    m.__dict__.update(
        D=D, guard=guard, scope=scope, current_checks=current_checks, inventory=inventory
    )
    m.__dict__["partitioned_inventory"] = partitioned_inventory
    exec(compile(source, str(Path(__file__)), "exec"), m.__dict__)
    m.full_audit()


def readback():
    assert guard.read(D / "result.json")["passed"]
    inv = inventory(scope())
    assert inv["passed"], inv
    guard.write(D / "final-inventory.json", inv)
    for path, h in guard.read(D / "manifest.json")["sha256"].items():
        assert audit.digest_file(P / path) == h, path
    print(json.dumps({"passed": True, "inventory_count": inv["count"], "report_readback": True}))


if __name__ == "__main__":
    {"prepare": prepare, "full-audit": full_audit, "readback": readback}[sys.argv[1]]()
