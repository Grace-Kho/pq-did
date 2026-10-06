"""Reuse the complete historical auditor with the explicit milestone amendment.

Original baselines and comparison partitions are never regenerated. Newly created
milestone outputs receive their own inventory; retained inputs remain immutable.
"""

import hashlib
import json
import sys
import types
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_milestone_1 import run as guard  # noqa: E402
from scripts import preservation_audit as audit  # noqa: E402

D = guard.D
OLD = P / "docs/data/october_implementation_milestone_1"
REPORTS = (
    "docs/stage3_aurora_masking_native.md",
    "docs/stage2_mldsa_reference_baseline.md",
    "docs/kyc_milestone_benchmarks.md",
    "docs/oct31_kyc_native_milestone.md",
)


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


def scope():
    prior = load(OLD / "checks.py")
    value = prior.scope()
    seal = OLD / "manifest.json"
    expected = "158539d9c54fd5a33ae49b794b9f9716f620911a61e78bd973536e0aa3a28d8e"
    assert audit.digest_file(seal) == expected
    manifest = guard.read(seal)["sha256"]
    prefixes = guard.read(D / "prefixes.json")
    for name, digest in manifest.items():
        if name in prefixes:
            assert digest == prefixes[name]["sha256"]
            value["frozen_package_inputs"].pop(name, None)
            value["append_only_documentation"][name] = prefixes[name]
        else:
            value["frozen_package_inputs"][name] = digest
    value["frozen_package_inputs"][str(seal.relative_to(P))] = expected
    # benchmarks/README stays byte-identical unless an explicit reviewed append is made.
    for name, prefix in prefixes.items():
        assert audit.digest_file(P / name, prefix_bytes=prefix["bytes"]) == prefix["sha256"]
    required = set(value["required_names"]) | set(manifest) | {str(seal.relative_to(P))}
    current = guard.read(D / "new-inventory.json")
    required.update(current["required_names"])
    value["frozen_package_inputs"].update(current["sha256"])
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(set(value["optional_names"]) | set(current["optional_names"]))
    for root in guard.ROOTS:
        name = root.relative_to(P).as_posix()
        if not any(
            name == old or name.startswith(old + "/")
            for old in value["additional_name_inventory_roots"]
        ):
            value["additional_name_inventory_roots"].append(name)
    value["new_python_files"] += current["python_files"]
    value["new_markdown_files"] += list(REPORTS)
    return value


def partitioned_inventory(root, directories, expected_names, *, optional_names=frozenset()):
    """Retain the auditor's 10,000-entry ceiling for each disjoint original root."""
    for index, name in enumerate(directories):
        for other in directories[index + 1 :]:
            assert not (
                name == other or name.startswith(other + "/") or other.startswith(name + "/")
            )
    covered, unexpected, missing, partitions = set(), [], [], []
    for name in directories:
        expected = {path for path in expected_names if path.startswith(name + "/")}
        optional = {path for path in optional_names if path.startswith(name + "/")}
        assert not covered & expected
        result = audit.inventory_check(root, [name], expected, optional_names=optional)
        covered.update(expected)
        unexpected.extend(result["unexpected"])
        missing.extend(result["missing"])
        partitions.append({"root": name, **result, "expected_count": len(expected)})
    missing.extend(expected_names - covered)
    return {
        "passed": not unexpected and not missing,
        "count": sum(row["count"] for row in partitions),
        "unexpected": sorted(unexpected),
        "missing": sorted(missing),
        "partitions": partitions,
        "expected_union_count": len(covered),
        "expected_total_count": len(expected_names),
        "partition_overlap": 0,
        "entry_ceiling_per_partition_unchanged": audit.MAX_ENTRIES,
    }


def inventory(value):
    return partitioned_inventory(
        P,
        value["additional_name_inventory_roots"],
        set(value["required_names"]),
        optional_names=set(value["optional_names"]),
    )


def prepare():
    assert guard.read(D / "approval.json")["approved"] is True
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
    }
    optional = {str((D / n).relative_to(P)) for n in mutable}
    for phase in ("prepare", "prepare-2", "full-audit", "final-readback"):
        optional.update(
            str((D / "jobs" / (phase + suffix)).relative_to(P))
            for suffix in (".json", ".input.json", ".worker.json", ".log")
        )
    hashes, required, python = {}, [], []
    for root in guard.ROOTS:
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            name = path.relative_to(P).as_posix()
            required.append(name)
            if name not in optional:
                hashes[name] = audit.digest_file(path)
            if path.suffix == ".py" and not path.is_relative_to(guard.N / "work"):
                python.append(name)
    for name in REPORTS:
        assert (P / name).is_file(), name
        required.append(name)
    result = {
        "required_names": required,
        "optional_names": sorted(optional),
        "sha256": hashes,
        "python_files": python,
        "scope": "Only new approved milestone roots; historical entries inherited unchanged",
    }
    guard.write(D / "new-inventory.json", result)
    value = scope()
    checked = inventory(value)
    assert checked["passed"], checked
    guard.write(
        D / "preparation.json",
        {
            "passed": True,
            "inventory": checked,
            "historical_baselines_regenerated": False,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        },
    )


def current_checks(_):
    policy = guard.POLICY
    rows = guard.read(D / "ledger.json")
    assert sum(row["name"] == "full-audit" for row in rows["jobs"]) == 1
    assert len(rows["invocations"]) <= 600
    assert len(rows["builds"]) <= 8
    for ordinal, case in enumerate(rows["invocations"], 1):
        assert case["ordinal"] == ordinal and case["cumulative_invocations"] == 448 + ordinal
        assert case["status"] in {"pass", "failed", "incomplete"}
    for row in rows["jobs"]:
        assert row["phase"] in policy["phase_memory"]
        authorised = policy["phase_memory"][row["phase"]]
        assert row["memory_limit_bytes"] == authorised
        if row["status"] == "launched":
            assert row["name"] == "full-audit"
            continue
        assert row["stop"] is None, row["name"]
        assert row["seconds"] <= row["limit_seconds"] + 5
        measured = row["worker"]
        assert measured["before"]["memory.max"] == str(authorised)
        assert int(measured["after"]["memory.peak"]) <= authorised
        assert measured["before"]["memory.swap.max"] == "0"
        assert measured["resource_breach"] is False
    assert guard.consumed(rows) <= policy["implementation_ceiling_seconds"]
    assert guard.read(D / "preparation.json")["passed"]
    return guard.consumed(rows)


def full_audit():
    value = scope()
    expected = guard.read(D / "preparation.json")["scope_sha256"]
    assert hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() == expected
    source_path = P / "docs/data/s3_aurora_transcript_correction_contract_1/audit.py"
    source = source_path.read_text()
    start = source.index('    runs = small(D / "run-ledger.json")')
    end = source.index('    for name in scope["new_python_files"]:', start)
    source = source[:start] + "    charged = current_checks(SELF)\n" + source[end:]
    replacement = [
        (
            'scope, config = small(D / "scope.json"), small(D / "config.json")',
            "scope, config = load_scope(), current_config()",
        ),
        (
            'require(config[key] == old_config[key], "changed ceiling: " + key)',
            "require(config[key] == amendments.get(key, old_config[key]), "
            '"changed ceiling: " + key)',
        ),
        (
            'sum(path.stat().st_size for path in D.rglob("*") if path.is_file())',
            'current_storage()["new_evidence_bytes"]',
        ),
        (
            'path.stat().st_size <= config["per_file_bytes"]',
            "path.stat().st_size <= output_role(path)[1]",
        ),
        (
            '"total_test_invocations_including_prior_package": 386',
            '"total_test_invocations_including_prior_package": current_invocations()',
        ),
        ('"test_invocations": {}', '"test_invocations": current_cases()'),
        ('"unique_new_tests": 0', '"unique_new_tests": len(current_cases())'),
        (
            '"Pinned evidence reused; pseudocode and 16 inactive regression cases"',
            '"Approved isolated native/baseline/benchmark milestone"',
        ),
        (
            '"implementation_allowance_remaining_unchanged": 41.82321833795868',
            '"implementation_remaining_including_audit_reservation": 4274 - charged',
        ),
    ]
    for before, after in replacement:
        assert before in source, before
        source = source.replace(before, after)
    module = types.ModuleType("milestone_preservation")
    module.__file__ = str(source_path)
    exec(compile(source, str(source_path), "exec"), module.__dict__)
    module.D = module.prior.D = D
    module.audit = types.SimpleNamespace(**vars(audit))
    module.audit.inventory_check = partitioned_inventory
    module.SELF = module
    module.load_scope = lambda: value
    module.current_checks = current_checks
    module.amendments = {
        "command_seconds": 300,
        "child_seconds": 295,
        "aggregate_seconds": 4274,
        "output_bytes": 33554432,
    }
    config = guard.read(P / "docs/data/s2_authority_isolation_pilot_1/config.json")
    config.update(module.amendments)
    config.update(
        package="OCT31-KYC-NATIVE-MILESTONE-1", full_audit_attempts=1, prior_output_bytes=16665098
    )
    module.current_config = lambda: config
    module.current_storage = guard.storage
    module.output_role = guard.output_role
    module.current_invocations = lambda: 448 + len(guard.read(D / "ledger.json")["invocations"])

    def current_cases():
        counts = {}
        for row in guard.read(D / "ledger.json")["invocations"]:
            counts[row["case_id"]] = counts.get(row["case_id"], 0) + 1
        return counts

    module.current_cases = current_cases
    measure = module.prior.Measurements()
    try:
        module.main(measure)
    except Exception as error:
        measure.phase("incomplete-audit-failure")
        guard.write(D / "audit-failure.json", {"passed": False, "error": str(error)[:3000]})
        raise


def readback():
    assert guard.read(D / "validation.json")["passed"]
    assert guard.read(D / "jobs/full-audit.json")["status"] == "pass"
    result = inventory(scope())
    assert result["passed"], result
    guard.write(D / "final-inventory.json", result)
    for path in (D / "ledger.json", D / "policy.json", D / "validation.json"):
        guard.read(path)
    for name in REPORTS:
        assert (P / name).read_text().count("```") % 2 == 0
    print(json.dumps({"final_inventory": result, "readback": True}))


if __name__ == "__main__":
    {"prepare": prepare, "full-audit": full_audit, "readback": readback}[sys.argv[1]]()
