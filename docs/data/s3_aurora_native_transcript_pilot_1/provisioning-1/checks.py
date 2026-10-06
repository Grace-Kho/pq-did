"""Finalise the stopped acquisition using the established preservation workflow."""

import gzip
import hashlib
import json
import os
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
N = R.parent
P = N.parents[2]
L = P / "docs/data/s3_aurora_native_dependency_lock_1/continuation-1"
ROOT = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
sys.dont_write_bytecode = True


def load(path):
    m = types.ModuleType("retained_" + path.stem)
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    return m


prior = load(L / "checks.py")
guard = load(R / "run.py")
audit, read, digest = prior.audit, prior.read, prior.digest
NAMES = {
    "run.py",
    "provision.py",
    "checks.py",
    "run-at-attempt.py",
    "provision-at-attempt.py",
    "config.json",
    "prefixes.json",
    "admission.json",
    "failure-analysis.json",
    "commands.json",
    "provision-result.json",
    "native-case-outcomes.json",
    "run.lock",
    "run-ledger.json",
    "STOP.json",
    "artifact-inventory.json.gz",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    *{
        name + suffix
        for name in ("provision", "quality", "prepare", "full-audit")
        for suffix in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = L / "manifest.json"
    assert digest(seal) == "e83682e08a9bdd8ca0b2fc542621ee87e4e8eca492ce0e2801111a2b6055ec36"
    required = set(value["required_names"]) | set(read(seal)["sha256"])
    required.add(str(seal.relative_to(P)))
    for name, expected in read(seal)["sha256"].items():
        if name not in DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str(seal.relative_to(P))] = digest(seal)
    for name, prefix in read(R / "prefixes.json").items():
        # Exact newly authorised append-only reports: preserve every existing byte.
        if name in value["frozen_package_inputs"]:
            assert value["frozen_package_inputs"].pop(name) == prefix["sha256"]
        value["append_only_documentation"][name] = prefix
    checked = read(R / "checked-inputs.json")["sha256"]
    value["frozen_package_inputs"].update(checked)
    required.update(checked)
    with gzip.open(R / "artifact-inventory.json.gz", "rt") as stream:
        artifacts = json.load(stream)
    for row in artifacts["files"]:
        assert row["kind"] == "regular", "unhandled retained artifact type"
        required.add(row["path"])
        value["frozen_package_inputs"][row["path"]] = row["sha256"]
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / name).relative_to(P)) for name in NAMES}
    )
    value["new_python_files"] += [
        str((R / name).relative_to(P)) for name in ("run.py", "checks.py", "provision.py")
    ]
    return value


def quality():
    for name, expected in read(R / "failure-analysis.json")[
        "historical_worker_source_sha256"
    ].items():
        assert digest(R / name) == expected
    files = [str(R / name) for name in ("run.py", "provision.py", "checks.py")]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.5
        )
    # A failure-artifact inventory preserves what the authorised command created.
    # It does not establish agreement with the rejected dependency lock.
    rows = []
    for base, dirs, names in os.walk(ROOT):
        assert all(not (Path(base) / name).is_symlink() for name in dirs)
        for name in names:
            path = Path(base) / name
            assert path.is_file() and not path.is_symlink()
            rows.append(
                {
                    "path": str(path.relative_to(P)),
                    "kind": "regular",
                    "bytes": path.stat().st_size,
                    "sha256": digest(path),
                }
            )
    data = {
        "purpose": "Quarantined failed-acquisition preservation, not dependency admission",
        "origin_commands": "commands.json",
        "files": sorted(rows, key=lambda x: x["path"]),
        "total_bytes": sum(x["bytes"] for x in rows),
    }
    (R / "artifact-inventory.json.gz").write_bytes(
        gzip.compress(json.dumps(data).encode(), mtime=0)
    )
    expected = {"src", "packages", "prefix", "evidence"}
    assert {p.name for p in ROOT.iterdir()} == expected
    assert {p.name for p in (ROOT / "src").iterdir()} == {"libiop"}
    assert all(not any((ROOT / name).iterdir()) for name in ("packages", "prefix", "evidence"))
    assert read(R / "provision-result.json")["native_admitted"] is False
    audit.write_report(
        R / "checked-inputs.json",
        {
            "sha256": {
                str((R / name).relative_to(P)): digest(R / name)
                for name in (
                    "run.py",
                    "provision.py",
                    "checks.py",
                    "run-at-attempt.py",
                    "provision-at-attempt.py",
                    "config.json",
                    "prefixes.json",
                    "admission.json",
                    "failure-analysis.json",
                    "commands.json",
                    "provision-result.json",
                    "native-case-outcomes.json",
                    "provision.json",
                    "provision.log",
                    "provision.service.json",
                    "STOP.json",
                    "artifact-inventory.json.gz",
                )
            },
            "no_retry": True,
            "new_tests": 0,
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
            "protected_original_baselines_unchanged": True,
        },
    )


def current_checks(original):
    runs = read(R / "run-ledger.json")
    assert sum(row["name"] == "full-audit" for row in runs) == 1
    original.prior.check_runs(R, {"quality", "prepare"})
    assert runs[0]["name"] == "provision" and runs[0]["status"] == "failed"
    assert all(row["status"] in {"pass", "launched"} for row in runs[1:])
    config = read(R / "config.json")
    charge = 5 + sum(row.get("seconds", row["limit_seconds"]) for row in runs)
    assert 5 + runs[0]["seconds"] <= 60
    assert charge + 30 <= 291.7509900990408
    assert 377.69163024192676 + charge + 30 <= 674
    assert config["test_invocations"] == {} and config["prior_test_invocations"] == 402
    assert read(R / "provision-result.json")["native_admitted"] is False
    assert not (ROOT / "build").exists() and not (ROOT / "overlay").exists()
    for name in DOCS:
        prefix = read(R / "prefixes.json")[name]
        assert digest(P / name, prefix_bytes=prefix["bytes"]) == prefix["sha256"]
    return 377.69163024192676 + charge


def full_audit():
    assert (
        hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest()
        == (read(R / "preparation.json")["scope_sha256"])
    )
    path = P / "docs/data/s3_aurora_transcript_correction_contract_1/audit.py"
    source = path.read_text()
    start = source.index('    runs = small(D / "run-ledger.json")')
    end = source.index('    for name in scope["new_python_files"]:', start)
    source = source[:start] + "    charged = current_checks(SELF)\n" + source[end:]
    for before, after in (
        (
            'scope, config = small(D / "scope.json"), small(D / "config.json")',
            'scope, config = load_scope(), small(D / "config.json")',
        ),
        (
            'require(config[key] == old_config[key], "changed ceiling: " + key)',
            'require(config[key] == ({"output_bytes":12386485,"aggregate_seconds":674}.get(key, '
            'old_config[key])), "changed ceiling: " + key)',
        ),
        ('sum(path.stat().st_size for path in D.rglob("*") if path.is_file())', "package_size()"),
        (
            '"total_test_invocations_including_prior_package": 386',
            '"total_test_invocations_including_prior_package": 402',
        ),
        (
            '"Pinned evidence reused; pseudocode and 16 inactive regression cases"',
            '"Native provisioning stopped on tree identity mismatch; no build or native cases"',
        ),
        (
            '"implementation_allowance_remaining_unchanged": 41.82321833795868',
            '"implementation_remaining_including_audit_reservation": 674 - charged',
        ),
    ):
        assert before in source
        source = source.replace(before, after)
    m = types.ModuleType("preservation")
    m.__file__ = str(path)
    exec(compile(source, str(path), "exec"), m.__dict__)
    m.D = m.prior.D = R
    m.load_scope, m.current_checks, m.SELF = scope, current_checks, m
    m.package_size = guard.package_size
    measure = m.prior.Measurements()
    try:
        m.main(measure)
    except Exception as error:
        measure.phase("incomplete-audit-failure")
        audit.write_report(
            R / "validation.json",
            {"passed": False, "comparison_complete": False, "error": str(error)[:2500]},
        )
        raise


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
