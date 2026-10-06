"""Read-only fourth-build admission and one preservation finalisation."""

import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
OLD = R.parent / "resource-guard-repair-1"
PREVIOUS = R.parent / "reconciliation-1"
A = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
sys.dont_write_bytecode = True


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(OLD / "checks.py")
guard = load(R / "run.py")
policy = load(OLD / "policy.py")
policy.PHASES.update(
    {
        "admission/quality": (268435456, 3),
        "admission/prepare": (268435456, 3),
        "admission/full-audit": (268435456, 7),
    }
)
audit, read, digest = prior.audit, prior.read, prior.digest
PYTHON = ("run.py", "checks.py")
NAMES = {
    *PYTHON,
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "run-ledger.json",
    "run.lock",
    "STOP.json",
    "STOP-prepare.json",
    "STOP-full-audit.json",
    "admission-result.json",
    "native-case-outcomes.json",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    *{
        n + suffix
        for n in ("quality", "prepare", "full-audit")
        for suffix in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = OLD / "manifest.json"
    assert digest(seal) == "deb4cb1a0acf4d4ccec71eea111eee2d7f3bc9b6020607e6264854d476498221"
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
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / name).relative_to(P)) for name in NAMES}
    )
    value["new_python_files"] += [str((R / name).relative_to(P)) for name in PYTHON]
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
    assert digest(OLD / "manifest.json") == (
        "deb4cb1a0acf4d4ccec71eea111eee2d7f3bc9b6020607e6264854d476498221"
    )
    for manifest in ("manifest.json", "checked-inputs.json"):
        for name, expected in read(OLD / manifest)["sha256"].items():
            assert digest(P / name) == expected, name
    previous = read(OLD / "validation-closure.json")
    assert previous["complete"] and previous["cumulative_invocations"] == 411
    assert previous["native_artifacts_unchanged_bytes"] == 15223375
    assert previous["cumulative_evidence_bytes"] == 12118832
    contract = P / "docs/data/s3_aurora_compiler_compatibility_contract_1"
    proposal = read(contract / "proposal.json")
    request = read(OLD / "next-build-request.json")
    assert request["commands"] == [
        [arg.replace("compatibility-v1", "guarded-build-v1") for arg in proposal[key]]
        for key in ("configure_argv", "build_argv")
    ]
    assert digest(contract / "variable-members.patch") == (
        "8a28d44432c4dfd2ff41a07bb4affd1a154b52ae781289210410586b43e4c357"
    )
    root = A / "compatibility-v1"
    assert digest(root / "work/libiop/libiop/relations/variable.tcc") == (
        "74ae2e8f6c7caed735be225dc63f25a84bb5b790579f0afe124aafcb0d7bc3bd"
    )
    assert digest(root / "overlay/semantic_cases.cpp") == digest(contract / "semantic_cases.cpp")
    for name in ("exp2_native.cpp", "canonical.bin", "nonce-mutated.bin"):
        assert digest(root / "overlay" / name) == digest(A / "overlay" / name)
    for row in read(R.parent / "case-plan.json")["cases"]:
        assert digest(P / row["retained_expectation"]) == row["retained_sha256"]
    assert not (A / "guarded-build-v1").exists()
    evidence = []
    for path in sorted((root / "build").rglob("*")):
        if path.is_file():
            role, ceiling = policy.classify(path, R, root, compiler_active=True)
            if role == "evidence":
                evidence.append(
                    {
                        "path": str(path.relative_to(P)),
                        "bytes": path.stat().st_size,
                        "sha256": digest(path),
                        "role": role,
                        "per_file_ceiling": ceiling,
                    }
                )
    total = sum(row["bytes"] for row in evidence)
    assert total == 344971 and len(evidence) == 24
    assert total > 200000 and total > 267653
    assert guard.artifact_limits() is None
    audit.write_report(
        R / "admission-result.json",
        {
            "approval_inputs_verified": True,
            "build_admitted": False,
            "reason": "Existing configured build exceeds approved evidence reservation/headroom",
            "classification_source": str((OLD / "policy.py").relative_to(P)),
            "classification_source_sha256": digest(OLD / "policy.py"),
            "runbook_sha256": digest(OLD / "next-build-runbook.md"),
            "request_sha256": digest(OLD / "next-build-request.json"),
            "retained_build_evidence": evidence,
            "retained_build_evidence_bytes": total,
            "reservation": 200000,
            "headroom": 267653,
            "reservation_shortfall_before_completion": total - 200000,
            "headroom_shortfall_before_completion": total - 267653,
            "new_measurements": "Filesystem sizes/hashes of historical artifacts only",
            "estimate_limit": "A fresh build may differ; no defensible fit established",
            "no_new_artifact_directory": True,
            "build_attempts_consumed_now": 0,
            "builds_used": 3,
            "build_ceiling": 4,
            "new_native_invocations": 0,
        },
    )
    cases = [f"SEM-{n:02d}" for n in range(1, 9)] + [f"TR-{n:02d}" for n in range(1, 17)]
    audit.write_report(
        R / "native-case-outcomes.json",
        {
            "new_invocations": 0,
            "cumulative_invocations": 411,
            "ceiling": 438,
            "cases": [
                {"id": name, "status": "not-run", "reason": "build not admitted: evidence budget"}
                for name in cases
            ],
        },
    )


def prepare():
    assert read(R / "quality.json")["status"] == "pass"
    present = {path.name for path in R.iterdir() if path.is_file()}
    assert present <= NAMES, sorted(present - NAMES)
    frozen = present - {
        "run-ledger.json",
        "run.lock",
        "prepare.json",
        "prepare.log",
        "prepare.service.json",
    }
    audit.write_report(
        R / "checked-inputs.json",
        {
            "sha256": {str((R / n).relative_to(P)): digest(R / n) for n in sorted(frozen)},
            "new_builds": 0,
            "new_native_or_tooling_invocations": 0,
        },
    )
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
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [row["name"] for row in rows] == ["quality", "prepare", "full-audit"]
    for row in rows[:-1]:
        policy.validate_record(row, "admission/" + row["name"])
    assert rows[-1]["status"] == "launched"
    assert not read(R / "admission-result.json")["build_admitted"]
    assert read(R / "native-case-outcomes.json")["new_invocations"] == 0
    assert not (A / "guarded-build-v1").exists()
    assert read(R / "config.json")["test_invocations"] == {}
    charge = 5 + sum(row.get("seconds", row["limit_seconds"]) for row in rows)
    assert charge <= 100 and charge <= 127.92377264366951
    return 427.14697401295416 + charge


def full_audit():
    assert (
        hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest()
        == read(R / "preparation.json")["scope_sha256"]
    )
    path = PREVIOUS / "checks.py"
    text = path.read_text()
    function = text[text.index("def full_audit():") : text.index("\ndef run(")]
    function = function.replace(
        "Reconciled trees/provisioned pins; two failed native builds; zero native cases",
        "Fourth-build admission stopped on retained metadata budget; no build/case launched",
    ).replace('including_prior_package": 402', 'including_prior_package": 411')
    module = types.ModuleType("audit_wrapper")
    module.__dict__.update(globals())
    exec(compile(function, str(path), "exec"), module.__dict__)
    module.full_audit()


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
