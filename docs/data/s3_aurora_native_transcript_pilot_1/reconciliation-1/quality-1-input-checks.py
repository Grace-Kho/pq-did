"""Complete the established audit after reconciliation and two stopped builds."""

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
O = N / "provisioning-1"
ROOT = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
PYTHON = ("run.py", "provision.py", "checks.py", "native_sources.py", "native_work.py")
sys.dont_write_bytecode = True


def load(path):
    module = types.ModuleType("retained_" + path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(O / "checks.py")
guard = load(R / "run.py")
audit, read, digest = prior.audit, prior.read, prior.digest
NAMES = {
    *PYTHON,
    "config.json",
    "prefixes.json",
    "commands.json",
    "object-associations.json",
    "dependency-lock-v2.json",
    "lock-correction.json",
    "provision-result.json",
    "libgmp-dev-members.json",
    "libsodium-dev-members.json",
    "run-ledger.json",
    "run.lock",
    "STOP.json",
    "STOP-build-2.json",
    "build-only-correction.json",
    "build-1-CMakeLists.txt",
    "native-exp2.patch",
    "native-inputs.json",
    "native-inputs-v2.json",
    "native-case-outcomes.json",
    "runbook-v2.md",
    "artifact-inventory.json.gz",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    *{"build-1-source-" + n for n in ("run.py", "native_work.py", "checks.py")},
    *{"pre-quality-" + n for n in PYTHON},
    *{
        name + suffix
        for name in ("build-1", "build-2")
        for suffix in ("-attempt.json", "-commands.json")
    },
    *{
        name + suffix
        for name in ("provision", "build-1", "build-2", "quality", "prepare", "full-audit")
        for suffix in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = O / "manifest.json"
    assert digest(seal) == "71edab13cfc0ab322d5668e466bf65668d8e7ab94f9884d32f9b77ad9f9d48f8"
    required = set(value["required_names"]) | set(read(seal)["sha256"])
    required.add(str(seal.relative_to(P)))
    for name, expected in read(seal)["sha256"].items():
        if name not in DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str(seal.relative_to(P))] = digest(seal)
    for name, prefix in read(R / "prefixes.json").items():
        if name in value["frozen_package_inputs"]:
            assert value["frozen_package_inputs"].pop(name) == prefix["sha256"]
        value["append_only_documentation"][name] = prefix
    checked = read(R / "checked-inputs.json")["sha256"]
    for name, expected in checked.items():
        assert value["frozen_package_inputs"].get(name, expected) == expected
        value["frozen_package_inputs"][name] = expected
    required.update(checked)
    with gzip.open(R / "artifact-inventory.json.gz", "rt") as stream:
        artifacts = json.load(stream)
    for row in artifacts["files"]:
        path = P / row["path"]
        required.add(row["path"])
        if row["kind"] == "regular":
            assert not path.is_symlink()
            assert value["frozen_package_inputs"].get(row["path"], row["sha256"]) == row["sha256"]
            value["frozen_package_inputs"][row["path"]] = row["sha256"]
        else:
            # Include unused dangling .so aliases; never follow/hash their targets.
            assert row["kind"] == "symlink" and path.is_symlink()
            assert os.readlink(path) == row["target"]
        assert path.lstat().st_mode == row["mode"]
        assert path.lstat().st_size == row["bytes"]
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / name).relative_to(P)) for name in NAMES}
    )
    value["new_python_files"] += [str((R / name).relative_to(P)) for name in PYTHON]
    value["new_markdown_files"] += [str((R / "runbook-v2.md").relative_to(P))]
    return value


def quality():
    files = [str(R / name) for name in PYTHON]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.5
        )
    for case in read(R / "native-case-outcomes.json")["cases"]:
        assert digest(P / case["retained_expectation"]) == case["retained_sha256"]
    patches = {
        "libiop/libiop/bcs/hashing/blake2b.hpp",
        "libiop/libiop/bcs/hashing/blake2b.tcc",
        "libiop/libiop/bcs/bcs_common.hpp",
        "libiop/libiop/bcs/bcs_common.tcc",
        "libiop/libiop/bcs/hashing/exp2_public_pilot.hpp",
    }
    for path in (ROOT / "work").rglob("*"):
        if path.is_file():
            name = path.relative_to(ROOT / "work").as_posix()
            if name not in patches:
                assert digest(path) == digest(ROOT / "src" / name), name
    inputs = read(R / "native-inputs-v2.json")
    for name, expected in inputs["sha256"].items():
        assert digest(P / name) == expected, name
    rows = []
    for base, dirs, names in os.walk(ROOT):
        for name in list(dirs):
            if (Path(base) / name).is_symlink():
                names.append(name)
                dirs.remove(name)
        for name in names:
            path = Path(base) / name
            stat = path.lstat()
            row = {"path": str(path.relative_to(P)), "bytes": stat.st_size, "mode": stat.st_mode}
            if path.is_symlink():
                row.update(kind="symlink", target=os.readlink(path))
            else:
                assert path.is_file()
                row.update(kind="regular", sha256=digest(path))
            rows.append(row)
    data = {
        "purpose": "Acquired dependencies and stopped build preservation; not native success",
        "files": sorted(rows, key=lambda row: row["path"]),
        "total_bytes": sum(row["bytes"] for row in rows),
    }
    (R / "artifact-inventory.json.gz").write_bytes(
        gzip.compress(json.dumps(data).encode(), mtime=0)
    )
    assert guard.artifact_limits() is None
    allowed = {path.name for path in R.iterdir() if path.is_file()}
    assert allowed <= NAMES, sorted(allowed - NAMES)
    frozen = allowed - {
        "run-ledger.json",
        "run.lock",
        "quality.log",
        "quality.service.json",
        "quality.json",
    }
    audit.write_report(
        R / "checked-inputs.json",
        {
            "sha256": {str((R / name).relative_to(P)): digest(R / name) for name in sorted(frozen)},
            "new_native_invocations": 0,
            "builds_used": 2,
            "original_and_repair_baselines_preserved": True,
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
    assert [row["name"] for row in runs] == [
        "provision",
        "build-1",
        "build-2",
        "quality",
        "prepare",
        "full-audit",
    ]
    original.prior.check_runs(R, {"quality", "prepare"})
    assert runs[0]["status"] == "pass"
    for row in runs[1:3]:
        assert row["status"] == "failed" and row["exit_code"] == 1 and row["stop"] is None
    assert all(row["status"] in {"pass", "launched"} for row in runs[3:])
    charge = 5 + sum(row.get("seconds", row["limit_seconds"]) for row in runs)
    assert 9.061018427833915 + 5 + runs[0]["seconds"] <= 60
    assert charge + 30 <= 282.6899716712069
    assert 386.7526486697607 + charge + 30 <= 674
    assert read(R / "config.json")["test_invocations"] == {}
    assert read(R / "provision-result.json")["native_admitted"] is True
    assert not (ROOT / "build/exp2_native").exists()
    assert read(R / "native-case-outcomes.json")["admitted_native_invocations"] == 0
    return 386.7526486697607 + charge


def full_audit():
    assert (
        hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest()
        == read(R / "preparation.json")["scope_sha256"]
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
            '"Reconciled trees/provisioned pins; two failed native builds; zero native cases"',
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
        if not (R / "validation.json").exists():
            audit.write_report(
                R / "validation.json",
                {"passed": False, "comparison_complete": False, "error": str(error)[:2500]},
            )
        raise


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
