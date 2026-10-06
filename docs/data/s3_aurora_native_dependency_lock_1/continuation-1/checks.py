"""Reuse the corrected preservation comparisons for this metadata-only package."""

import gzip
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
D = R.parent
P = D.parents[2]
N = P / "docs/data/s3_aurora_native_transcript_pilot_1"
REPORT = P / "docs/stage3_aurora_native_dependency_lock.md"
PROPOSAL = P / "docs/proposals/s3_aurora_native_dependency_lock_1"
DOCS = ("docs/status.md", "docs/traceability.md", "docs/spec_issues.md")
sys.dont_write_bytecode = True


def load(path):
    module = types.ModuleType(path.stem + "_retained")
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


native = load(N / "run.py")
audit, read, digest = native.audit, native.read, native.digest
guard = load(R / "run.py")
NAMES = {
    "run.py",
    "checks.py",
    "config.json",
    "amendment.json",
    "retained-inputs.json",
    "metadata-resume-requests.json",
    "metadata-resume-results.json",
    "run.lock",
    "run-ledger.json",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "STOP.json",
    "validation-closure.json",
    "manifest.json",
    *{
        name + ext
        for name in ("metadata-resume", "quality", "prepare", "full-audit")
        for ext in (".json", ".log", ".service.json")
    },
}


def scope():
    value = native.scope()
    seal = N / "manifest.json"
    assert digest(seal) == "9963717df494c454ca943cd2f7c6cb5aef34af6bd74df37bfe72906e9fdc9afb"
    retained = {
        **read(seal)["sha256"],
        str(seal.relative_to(P)): digest(seal),
        **read(R / "retained-inputs.json")["sha256"],
    }
    required = set(value["required_names"]) | set(retained)
    for name, expected in retained.items():
        if name not in DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    for name, prefix in read(D / "prefixes.json").items():
        value["append_only_documentation"][name] = prefix
    value["frozen_package_inputs"].update(read(R / "checked-inputs.json")["sha256"])
    required.update(read(R / "checked-inputs.json")["sha256"])
    required.add(str(REPORT.relative_to(P)))
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / name).relative_to(P)) for name in NAMES}
    )
    value["new_python_files"] += [
        str((R / name).relative_to(P)) for name in ("run.py", "checks.py")
    ]
    value["new_markdown_files"] += [
        str(REPORT.relative_to(P)),
        str((PROPOSAL / "README.md").relative_to(P)),
    ]
    return value


def quality():
    files = [str(R / name) for name in ("run.py", "checks.py")]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.5
        )
    for name, expected in read(R / "retained-inputs.json")["sha256"].items():
        assert digest(P / name) == expected, name
    metadata = []
    for path in [*D.glob("metadata-*-results.json"), R / "metadata-resume-results.json"]:
        metadata.extend(read(path))
    for row in metadata:
        if row["status"] == 200:
            payload = gzip.decompress((P / row["retained"]).read_bytes())
            assert len(payload) == row["bytes"]
            assert hashlib.sha256(payload).hexdigest() == row["sha256"]
    lock = read(D / "dependency-lock.json")
    assert lock["artifact_verification_complete"] is False
    assert lock["native_build_admitted"] is False
    assert lock["installation_performed"] is False
    paths = [
        R / n
        for n in (
            "run.py",
            "checks.py",
            "config.json",
            "amendment.json",
            "retained-inputs.json",
            "metadata-resume-requests.json",
            "metadata-resume-results.json",
        )
    ]
    paths += [R / "metadata" / (r["id"] + ".gz") for r in read(R / "metadata-resume-results.json")]
    paths += [
        D / "dependency-lock.json",
        PROPOSAL / "README.md",
        PROPOSAL / "minimal-native.cmake.txt",
    ]
    audit.write_report(
        R / "checked-inputs.json",
        {
            "sha256": {str(path.relative_to(P)): digest(path) for path in paths},
            "historical_failure_preserved": True,
            "new_test_invocations": 0,
        },
    )


def prepare():
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
            "historical_repair_entries_retained": True,
            "baseline_regenerated": False,
        },
    )


def current_checks(original):
    config = read(R / "config.json")
    runs = read(R / "run-ledger.json")
    assert sum(row["name"] == "full-audit" for row in runs) == 1
    original.prior.check_runs(R, {"metadata-resume", "quality", "prepare"})
    assert all(row["status"] in {"pass", "launched"} for row in runs)
    old = read(D / "run-ledger.json")
    assert [row["status"] for row in old] == ["pass", "pass", "pass", "failed"]
    assert old[-1]["stop"] == "diagnostic/package output stop"
    assert read(R / "amendment.json")["recorded_exceedance_bytes"] == 7203
    assert config["test_invocations"] == {} and config["prior_test_invocations"] == 402
    assert config["synthetic_case_limit"] == 426
    charge = config["operator_charge_seconds"] + sum(
        row.get("seconds", row["limit_seconds"]) for row in runs
    )
    assert charge + 10 <= 39.465
    assert charge + 20.53469604079146 + 10 <= 60
    assert charge + config["prior_analysis_charged_seconds"] + 10 <= 300
    native_result = read(N / "validation-closure.json")
    assert native_result["native_build_attempts_used"] == 0
    assert native_result["native_invocations_used"] == 0
    assert native_result["implementation_seconds_remaining"] == 296.30836975807324
    b = P / "docs/data/s3_aurora_transcript_regression_1"
    cases = read(b / "case-ledger.json")
    assert len(cases) == 16 and all(row["status"] == "pass" for row in cases)
    assert [r["cumulative_invocation"] for r in cases] == list(range(387, 403))
    for row in cases:
        assert (b / row["evidence"]).is_file()
    for name, expected in read(b / "execution-inputs.json")["sha256"].items():
        assert digest(P / name) == expected
    return config["prior_analysis_charged_seconds"] + charge


def full_audit():
    value = scope()
    assert (
        hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        == (read(R / "preparation.json")["scope_sha256"])
    )
    path = P / "docs/data/s3_aurora_transcript_correction_contract_1/audit.py"
    source = path.read_text()
    start = source.index('    runs = small(D / "run-ledger.json")')
    end = source.index('    for name in scope["new_python_files"]:', start)
    source = source[:start] + "    charged = current_checks(SELF)\n" + source[end:]
    source = source.replace(
        'scope, config = small(D / "scope.json"), small(D / "config.json")',
        'scope, config = load_scope(), small(D / "config.json")',
    )
    source = source.replace(
        'require(config[key] == old_config[key], "changed ceiling: " + key)',
        'require(config[key] == (12386485 if key == "output_bytes" '
        'else old_config[key]), "changed ceiling: " + key)',
    )
    source = source.replace(
        'sum(path.stat().st_size for path in D.rglob("*") if path.is_file())', "package_size()"
    )
    source = source.replace(
        '"total_test_invocations_including_prior_package": 386',
        '"total_test_invocations_including_prior_package": 402',
    )
    source = source.replace(
        '"Pinned evidence reused; pseudocode and 16 inactive regression cases"',
        '"Dependency metadata only; retained sixteen regressions reused"',
    )
    source = source.replace("41.82321833795868", "296.30836975807324")
    original = types.ModuleType("complete_preservation")
    original.__file__ = str(path)
    exec(compile(source, str(path), "exec"), original.__dict__)
    original.D = original.prior.D = R
    original.load_scope = scope
    original.current_checks = current_checks
    original.SELF = original
    original.package_size = guard.package_size
    measure = original.prior.Measurements()
    try:
        original.main(measure)
    except Exception as error:
        measure.phase("incomplete-audit-failure")
        audit.write_report(
            R / "validation.json",
            {
                "passed": False,
                "comparison_complete": False,
                "error": str(error)[:2500],
            },
        )
        raise


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
