"""Retained complete preservation workflow extended for this blocked package."""

import hashlib
import inspect
import json
import sys
import types
import zipfile
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_domain_mask_correction_1 import preservation as prior  # noqa: E402
from experiments.ligetron_full_path_engineering_1 import run as guard  # noqa: E402
from scripts import preservation_audit as audit  # noqa: E402

D, N = guard.D, guard.N
A = P / "docs/data/ligetron_domain_mask_correction_1"
PRE = P / "docs/data/ligetron_dependency_hardware_preflight_1"
REPORT = "docs/ligetron_full_path_engineering.md"


def name(path):
    return path.relative_to(P).as_posix()


def historical():
    admission = guard.read(D / "source-preparation.json")
    assert audit.digest_file(A / "manifest.json") == admission["prior_manifest_sha256"]
    assert audit.digest_file(A / "validation-closure.json") == admission["prior_closure_sha256"]
    closure = guard.read(A / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    result = guard.read(A / "manifest.json")["sha256"]
    result.update(closure["finalisation_sha256"])
    result[name(A / "manifest.json")] = admission["prior_manifest_sha256"]
    result[name(A / "validation-closure.json")] = admission["prior_closure_sha256"]
    with zipfile.ZipFile(P / "handover/ligetron_full_path_preflight_v1.zip") as z:
        for row in json.loads(z.read("MANIFEST.json"))["files"]:
            path = row["original_path"]
            if path.startswith(str(P)) and "!" not in path:
                rel = Path(path).relative_to(P).as_posix()
                expected = result.get(rel)
                if expected is not None:
                    assert expected == row["sha256"], rel
                result[rel] = row["sha256"]
    result.update(guard.read(D / "additional-retained-seals.json"))
    return result


def scope():
    value = prior.scope()
    retained = historical()
    value["frozen_package_inputs"].update(retained)
    for path, prefix in guard.read(D / "prefixes.json").items():
        expected = value["frozen_package_inputs"].pop(path, None)
        if expected is not None:
            assert expected == prefix["sha256"], path
        value["append_only_documentation"][path] = prefix
    current = guard.read(D / "new-inventory.json")
    value["frozen_package_inputs"].update(current["sha256"])
    value["required_names"] = sorted(
        set(value["required_names"]) | set(retained) | set(current["required_names"])
    )
    value["optional_names"] = sorted(set(value["optional_names"]) | set(current["optional_names"]))
    for root in (D, N, PRE, P / "handover"):
        path = name(root)
        if not any(
            path == old or path.startswith(old + "/")
            for old in value["additional_name_inventory_roots"]
        ):
            value["additional_name_inventory_roots"].append(path)
    value["new_python_files"] += current["python_files"]
    value["new_markdown_files"] += [REPORT]
    return value


def partitioned_inventory(root, directories, expected_names, *, optional_names=frozenset()):
    extra = {"AGENTS.md", "PQ_DID_Ligetron_Review_and_Next_Task_v1.zip"} & set(expected_names)
    result = prior.partitioned_inventory(
        root, directories, set(expected_names) - extra, optional_names=optional_names
    )
    for path in extra:
        assert audit.digest_file(root / path) == historical()[path]
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
    for key in ("count", "expected_union_count", "expected_total_count"):
        result[key] += len(extra)
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
        "preparation-corrected-v2.json",
        "validation.json",
        "phases.json",
        "result.json",
        "validation-closure.json",
        "manifest.json",
        "final-inventory.json",
        "resource-closure.json",
        "audit-failure.json",
        "shutdown.json",
        "archive-result.json",
        "finalisation.json",
        "report-readback.json",
    }
    optional = {name(D / x) for x in mutable}
    optional.add("handover/ligetron_full_path_engineering_review_v1.zip")
    for job in (
        "prepare",
        "prepare-2",
        "prepare-3",
        "full-audit",
        "full-audit-2",
        "readback",
        "package",
    ):
        optional.update(
            name(D / "jobs" / (job + ext))
            for ext in (".json", ".input.json", ".worker.json", ".log")
        )
    required, hashes, python = [], {}, []
    for root in guard.ROOTS:
        for f in sorted(root.rglob("*")):
            if not f.is_file():
                continue
            assert not f.is_symlink()
            path = name(f)
            required.append(path)
            if path not in optional:
                hashes[path] = audit.digest_file(f)
            if f.suffix == ".py":
                python.append(path)
    required.append(REPORT)
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
        D / "preparation-corrected-v2.json",
        {
            "passed": inv["passed"],
            "inventory": inv,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        },
    )
    assert inv["passed"], inv


def current_checks(_):
    value = guard.read(D / "ledger.json")
    assert not value["invocations"] and not value["builds"] and not value["proofs"]
    assert value["work_events"] == 144593603
    memory = guard.read(D / "memory-admission.json")
    assert not memory["passed"] and memory["required_each_bytes"] == 4294967296
    rows = guard.read(D / "outcomes.json")["fixed_cases"]
    assert [r["case_id"] for r in rows] == [f"E{i:02d}" for i in range(1, 41)]
    assert all(r["status"] == "unrun" and not r["invocation_consumed"] for r in rows)
    for row in value["jobs"]:
        if row.get("worker"):
            assert row["stop"] is None and not row["worker"]["resource_breach"]
            assert (
                int(row["worker"]["after"]["memory.peak"])
                <= guard.POLICY["phase_memory"][row["phase"]]
            )
        elif "worker" in row:
            # Retain the one diagnosed launcher failure, before audit child start.
            assert row["name"] == "full-audit" and row["exit_code"] == 1
            assert row["argv"][:2] == ["--completion", "--"]
            assert row["status"] == "failed" and row["stop"] is None
            log = (D / "jobs/full-audit.log").read_text()
            assert "No such file or directory: '--completion'" in log
    for path, expected in guard.read(D / "prepared-overlay-seal.json")["sha256"].items():
        assert audit.digest_file(P / path) == expected, path
    charged = guard.consumed(value)
    assert charged - guard.POLICY["historical_seconds"] <= 7200
    return charged


def full_audit():
    source = inspect.getsource(prior.p.full_audit)
    changes = (
        ('D / "preparation.json"', 'D / "preparation-corrected-v2.json"'),
        ("4274 - charged", "13874 - charged"),
        ('"aggregate_seconds": 4274', '"aggregate_seconds": 13874'),
        ('"output_bytes": 33554432', '"output_bytes": 46137344'),
        ("prior_output_bytes=16665098", "prior_output_bytes=39039552"),
        ("lambda: 448 + len(", "lambda: 1250 + len("),
        ('package="OCT31-KYC-NATIVE-MILESTONE-1"', 'package="LIGETRON-FULL-PATH-ENGINEERING-1"'),
        (
            "Approved isolated native/baseline/benchmark milestone",
            "Approved engineering package: memory-gated, source-only progress; "
            "all native cases unrun",
        ),
    )
    for before, after in changes:
        assert before in source
        source = source.replace(before, after)
    m = types.ModuleType("full_path_preservation")
    m.__dict__.update(vars(prior.p))
    m.__dict__.update(
        D=D,
        guard=guard,
        scope=scope,
        current_checks=current_checks,
        inventory=inventory,
        partitioned_inventory=partitioned_inventory,
    )
    exec(compile(source, str(Path(__file__)), "exec"), m.__dict__)
    m.full_audit()


def readback():
    assert guard.read(D / "result.json")["passed"]
    inv = inventory(scope())
    assert inv["passed"]
    guard.write(D / "final-inventory.json", inv)
    for path, expected in guard.read(D / "manifest.json")["sha256"].items():
        assert audit.digest_file(P / path) == expected, path
    guard.write(D / "report-readback.json", {"passed": True, "inventory_count": inv["count"]})


if __name__ == "__main__":
    {"prepare": prepare, "full-audit": full_audit, "readback": readback}[sys.argv[1]]()
