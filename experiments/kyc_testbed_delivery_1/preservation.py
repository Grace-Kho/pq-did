"""Inherited complete audit; explicit new roots and protected historical prefixes."""

import hashlib
import inspect
import json
import sys
import types
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_testbed_delivery_1 import run as guard  # noqa: E402
from scripts import preservation_audit as audit  # noqa: E402

D, N = guard.D, guard.N
A = P / "docs/data/s3_binius_committed_view_correspondence_1"
REPORTS = ("docs/kyc_testbed_delivery.md", "docs/kyc_testbed_interoperability_limits.md")


def load(path):
    m = types.ModuleType(path.stem)
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    return m


prior = load(A / "checks.py")
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
        set(value["required_names"]) | set(historical()) | set(current["required_names"])
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
    value["new_markdown_files"] += list(REPORTS) + [name(guard.B / "README.md")]
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
    optional = {name(D / x) for x in mutable}
    for phase in (
        "prepare",
        "full-audit",
        "static-audit-fix",
        "prepare-2",
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
    inv = p.inventory(value)
    guard.write(
        D / "preparation.json",
        {
            "passed": inv["passed"],
            "inventory": inv,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        },
    )
    assert inv["passed"], inv


def current_checks(_):
    rows = guard.read(D / "ledger.json")
    audits = [r for r in rows["jobs"] if r["name"].startswith("full-audit")]
    assert [r["name"] for r in audits] == ["full-audit", "full-audit-2"]
    assert audits[0]["status"] == "failed" and audits[0]["exit_code"] == 1
    assert audits[0]["stop"] is None and not audits[0]["worker"]["resource_breach"]
    assert len(rows["invocations"]) <= 22 and not rows["builds"]
    assert rows["work_events"] == 77593603 and rows["work_events_reserved"] == 0
    expected = {x["id"] for x in guard.read(D / "execution-plan.json")["cases"]}
    latest = {}
    for i, r in enumerate(rows["invocations"], 1):
        assert r["ordinal"] == i and r["cumulative_invocations"] == 1165 + i
        assert r["case_id"] in expected and r["status"] in {"pass", "failed", "incomplete"}
        result = guard.read(D / "cases" / (r["invocation_id"] + ".json"))
        assert result["status"] == r["status"]
        latest[r["case_id"]] = r["status"]
    assert set(latest) == expected and all(v == "pass" for v in latest.values())
    for r in rows["jobs"]:
        limit = guard.POLICY["phase_memory"][r["phase"]]
        assert r["memory_limit_bytes"] == limit
        if r["status"] == "launched":
            assert r["name"] == "full-audit-2"
            continue
        assert r["stop"] is None and not r["worker"]["resource_breach"]
        assert int(r["worker"]["after"]["memory.peak"]) <= limit
    charge = guard.consumed(rows)
    assert charge - guard.POLICY["historical_seconds"] <= 220
    assert guard.POLICY["KYC_after_transfer"] - (charge - guard.POLICY["historical_seconds"]) >= 300
    assert guard.read(D / "preflight.json")["passed"]
    return charge


def full_audit():
    source = inspect.getsource(p.full_audit)
    for before, after in (
        ('package="OCT31-KYC-NATIVE-MILESTONE-1"', 'package="KYC-TESTBED-DELIVERY-1"'),
        ("prior_output_bytes=16665098", "prior_output_bytes=35553865"),
        ("lambda: 448 + len(", "lambda: 1165 + len("),
        ('"aggregate_seconds": 4274', '"aggregate_seconds": 6074'),
        ('"output_bytes": 33554432', '"output_bytes": 41943040'),
        ("4274 - charged", "6074 - charged"),
        (
            "Approved isolated native/baseline/benchmark milestone",
            "Approved genuine disclosed-baseline delivery; no private proofs",
        ),
    ):
        assert before in source, before
        source = source.replace(before, after)
    m = types.ModuleType("delivery_audit")
    m.__dict__.update(vars(p))
    m.__dict__.update(D=D, guard=guard, scope=scope, current_checks=current_checks)
    exec(compile(source, str(Path(__file__)), "exec"), m.__dict__)
    m.full_audit()


def readback():
    assert guard.read(D / "result.json")["passed"]
    inv = p.inventory(scope())
    assert inv["passed"], inv
    guard.write(D / "final-inventory.json", inv)
    for path, h in guard.read(D / "manifest.json")["sha256"].items():
        assert audit.digest_file(P / path) == h, path
    print(json.dumps({"passed": True, "inventory_count": inv["count"], "report_readback": True}))


if __name__ == "__main__":
    {"prepare": prepare, "full-audit": full_audit, "readback": readback}[sys.argv[1]]()
