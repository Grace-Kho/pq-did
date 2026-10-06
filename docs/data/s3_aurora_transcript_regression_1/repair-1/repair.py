"""Narrow traversal repair; reuse comparison code and all recorded regressions."""

# ruff: noqa: E402

import gzip
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

R = Path(__file__).resolve().parent
B = R.parent
P = B.parents[2]
ROOT = "experiments/aurora_transcript_regression_1"
DOCS = (
    "docs/status.md",
    "docs/traceability.md",
    "docs/spec_issues.md",
    "docs/stage3_aurora_transcript_regression.md",
)
PIN = "a73e4e3e4e6f5cdbe1416d87757aebaf6c4ef26f0e2644d50d81fda3e306014e"
sys.path.insert(0, str(P))
sys.path.insert(0, str(B))
from scripts import preservation_audit as audit


def read(path):
    with path.open("rb") as stream:
        data = stream.read(1048577)
    assert len(data) <= 1048576
    return json.loads(data)


def module(name):
    spec = importlib.util.spec_from_file_location("sealed_" + name, B / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def package_bytes():
    return (
        sum(x.stat().st_size for root in (B, P / ROOT) for x in root.rglob("*") if x.is_file())
        + (P / DOCS[-1]).stat().st_size
    )


def hydrated_runs():
    rows = read(R / "run-ledger.json")
    for row in rows:
        path = R / row["service_record"]
        if path.exists():
            row["service"] = read(path)
    return rows


def sealed_inputs(prefixes=False):
    assert audit.digest_file(B / "manifest.json") == PIN
    pins = read(B / "manifest.json")["sha256"]
    for name, expected in pins.items():
        if prefixes and name in DOCS:
            prefix = read(R / "prefixes.json")[name]
            assert audit.digest_file(P / name, prefix_bytes=prefix["bytes"]) == expected
        else:
            assert audit.digest_file(P / name) == expected, name
    return pins


def checks():
    pins = sealed_inputs()
    exact = {
        ROOT + "/" + name
        for name in ("README.md", "cases.py", "reference_trace.py", "transcript.py")
    }
    assert {str(x.relative_to(P)) for x in (P / ROOT).iterdir()} == exact
    assert all(name in pins and (P / name).is_file() for name in exact)
    failure = read(B / "prepare.json")
    assert failure["status"] == "failed" and failure["exit_code"] == 1
    assert "scope name-only preflight" in (B / "prepare.log").read_text()
    closure = read(B / "validation-closure.json")
    assert closure["new_package_charged_seconds"] == 5.676312444964424
    assert closure["total_test_invocations"] == 402 and closure["full_audit_attempts"] == 0
    old_scope = read(P / "docs/data/s3_aurora_transcript_correction_contract_1/scope.json")
    assert ROOT not in old_scope["additional_name_inventory_roots"]
    files = [str(path) for path in sorted(R.glob("*.py"))]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.4
        )
    audit.write_report(
        R / "prefixes.json",
        {name: {"bytes": (P / name).stat().st_size, "sha256": pins[name]} for name in DOCS},
    )
    audit.write_report(
        R / "checked-inputs.json",
        {
            "previous_manifest_sha256": PIN,
            "four_authorised_files": sorted(exact),
            "only_added_traversal_root": ROOT,
            "sha256": {
                str(path.relative_to(P)): audit.digest_file(path)
                for path in [*R.glob("*.py"), R / "config.json"]
            },
        },
    )


def prepare():
    sealed_inputs(prefixes=True)
    original = module("prepare")
    inventory, writer = audit.inventory_check, audit.write_report
    future = {
        str((R / name).relative_to(P))
        for name in (
            "scope.json.gz",
            "validation.json",
            "phases.json",
            "result.json",
            "full-audit.json",
            "full-audit.log",
            "full-audit.service.json",
            "STOP.json",
            "manifest.json",
            "validation-closure.json",
        )
    }
    observed = {}

    def corrected_inventory(root, directories, expected_names, *, optional_names=frozenset()):
        assert ROOT not in directories
        corrected = [*directories, ROOT]  # The sole traversal correction.
        observed["before"] = list(directories)
        observed["after"] = corrected
        observed["expected"] = set(expected_names)
        return inventory(
            root, corrected, expected_names, optional_names=set(optional_names) | future
        )

    def save_scope(path, scope):
        assert path == B / "scope.json" and not path.exists()
        assert scope["additional_name_inventory_roots"] == observed["before"]
        scope["additional_name_inventory_roots"] = observed["after"]
        scope["optional_names"] = sorted(set(scope["optional_names"]) | future)
        # All original entries/hashes/allowlists remain. Add protection for the
        # failed attempt and new bookkeeping; no historical hash is regenerated.
        retained = read(B / "manifest.json")["sha256"]
        for name, value in retained.items():
            if name not in DOCS:
                assert scope["frozen_package_inputs"].get(name, value) == value
                scope["frozen_package_inputs"][name] = value
        scope["frozen_package_inputs"][str((B / "manifest.json").relative_to(P))] = PIN
        scope["frozen_package_inputs"].update(read(R / "checked-inputs.json")["sha256"])
        scope["repair_prefixes"] = read(R / "prefixes.json")
        scope["repair_delta"] = {
            "added_root": ROOT,
            "expected_entries_removed": [],
            "allowlist_changed": False,
            "baseline_regenerated": False,
        }
        assert not (R / "scope.json.gz").exists()
        # Storage-only compression; every decoded scope field is retained.
        data = json.dumps(scope, separators=(",", ":")).encode()
        assert len(data) < 1048576
        (R / "scope.json.gz").write_bytes(gzip.compress(data, mtime=0))
        assert load_scope(expand=False) == scope

    audit.inventory_check, audit.write_report = corrected_inventory, save_scope
    try:
        original.main()
    finally:
        audit.inventory_check, audit.write_report = inventory, writer


def load_scope(expand=True):
    with gzip.open(R / "scope.json.gz", "rb") as stream:
        data = stream.read(1048577)
    assert len(data) <= 1048576
    scope = json.loads(data)
    if expand:
        parent = read(P / scope["inherited_required_names_from"])
        before, delta = set(parent["required_names"]), set(scope["required_names"])
        assert not before & delta
        scope["required_names"] = sorted(before | delta)
    return scope


def full_audit():
    original = module("audit")
    original.D = original.prior.D = R
    original.load_scope = load_scope
    reader = original.small
    old_runs = read(B / "run-ledger.json")
    assert len(old_runs) == 4 and old_runs[-1]["name"] == "prepare"
    assert old_runs[-1]["status"] == "failed" and old_runs[-1]["exit_code"] == 1
    # Keep the failed record immutable and charged; it is not a passed prerequisite.
    view = [*old_runs[:-1], *hydrated_runs()]
    for row in view[3:]:
        if row["name"] == "checks":
            row["name"] = "repair-checks"
    config = read(B / "config.json")
    config["operator_charge_seconds"] += 5 + old_runs[-1]["seconds"]
    virtual = {"run-ledger.json": view, "config.json": config}
    reuse = {
        "case-ledger.json",
        "case-summary.json",
        "execution-inputs.json",
        "reviewed-inputs.json",
    }

    def routed(path):
        if path.parent == R:
            if path.name in virtual:
                return virtual[path.name]
            if path.name in reuse:
                return reader(B / path.name)
        return reader(path)

    original.small = original.prior.small_json = routed
    original.prior.check_runs(R, {"repair-checks", "prepare"})
    writer = audit.write_report

    def record(path, value):
        if path == R / "validation.json":
            value.update(
                historical_preparation_failure_preserved=True,
                historical_failure_seconds_charged=old_runs[-1]["seconds"],
                new_regression_invocations=0,
                reused_passed_regressions=16,
                traversal_root_added=ROOT,
                complete_aggregate_package_bytes=package_bytes(),
                completion_view="Passed original prerequisites plus authorised repair; "
                "failed preparation retained and separately charged",
            )
        writer(path, value)

    class Measurements(original.prior.Measurements):
        def phase(self, name):
            snapshot = self.snapshot()
            self.rows.append(
                {
                    "phase": name,
                    "seconds": time.monotonic() - self.started,
                    "current": snapshot["current"],
                    "peak": snapshot["peak"],
                    "events": snapshot["events"],
                }
            )
            (R / "phases.json").write_text(json.dumps({"phases": self.rows}, separators=(",", ":")))

    audit.write_report = record
    measure = Measurements()
    try:
        assert package_bytes() < 262144
        for name, prefix in load_scope()["repair_prefixes"].items():
            assert audit.digest_file(P / name, prefix_bytes=prefix["bytes"]) == prefix["sha256"]
        original.main(measure)
        assert package_bytes() < 262144
    except Exception as error:
        measure.phase("incomplete-audit-failure")
        if not (R / "validation.json").exists():
            writer(
                R / "validation.json",
                {"passed": False, "comparison_complete": False, "error": str(error)[:2000]},
            )
        raise
    finally:
        audit.write_report = writer


if __name__ == "__main__":
    {"checks": checks, "prepare": prepare, "full-audit": full_audit}[sys.argv[1]]()
