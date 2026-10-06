"""One full preservation continuation after eight guarded tooling cases."""

import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
C = P / "docs/data/s3_aurora_compiler_compatibility_contract_1"
PREVIOUS = R.parent / "reconciliation-1"
A = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/compatibility-v1"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
sys.dont_write_bytecode = True


def load(path):
    m = types.ModuleType(path.stem)
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    return m


OLD = R.parent / "compatibility-1"
prior = load(OLD / "checks.py")
policy = load(R / "policy.py")
guard = load(R / "run.py")
audit, read, digest = prior.audit, prior.read, prior.digest
PYTHON = ("run.py", "policy.py", "fixtures.py", "checks.py")
NAMES = {
    *PYTHON,
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "run-ledger.json",
    "run.lock",
    "STOP.json",
    "STOP-quality.json",
    "STOP-tooling.json",
    "STOP-prepare.json",
    "STOP-full-audit.json",
    "quality-result.json",
    "quality-result-v2.json",
    "STOP-quality-5.json",
    "quality-1-inputs.json.gz",
    "quality-2-inputs.json.gz",
    "budget-correction-inputs.json.gz",
    "budget-correction.json",
    "tooling-rerun-ledger.json",
    "RG-08-rerun-1.txt",
    "STOP-quality-4.json",
    "STOP-tooling-rerun-1.json",
    "STOP-quality-2.json",
    "STOP-quality-3.json",
    "tooling-ledger.json",
    "checked-inputs.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "next-build-request.json",
    "next-build-runbook.md",
    *{f"RG-{n:02d}.txt" for n in range(1, 9)},
    *{
        n + s
        for n in (
            "quality",
            "quality-2",
            "quality-3",
            "quality-4",
            "quality-5",
            "tooling",
            "tooling-rerun-1",
            "prepare",
            "full-audit",
        )
        for s in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = OLD / "manifest.json"
    assert digest(seal) == "af7436a168337d025d766756d545790ee5c4734b458b968a61280b58ae61c99d"
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
    value["new_markdown_files"] += [str((R / "next-build-runbook.md").relative_to(P))]
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
    seal = OLD / "manifest.json"
    assert digest(seal) == "af7436a168337d025d766756d545790ee5c4734b458b968a61280b58ae61c99d"
    for name, expected in read(seal)["sha256"].items():
        assert digest(P / name) == expected, name
    assert digest(A / "work/libiop/libiop/relations/variable.tcc") == (
        "74ae2e8f6c7caed735be225dc63f25a84bb5b790579f0afe124aafcb0d7bc3bd"
    )
    assert guard.artifact_limits() is None
    assert guard.package_size() + 60000 < 240000
    audit.write_report(
        R / "quality-result-v2.json",
        {
            "passed": True,
            "historical_seal_verified": digest(seal),
            "native_sources_unchanged": True,
            "native_builds": 0,
            "native_invocations": 0,
        },
    )


def prepare():
    cases = read(R / "tooling-ledger.json")
    assert [row["id"] for row in cases] == [f"RG-{n:02d}" for n in range(1, 9)]
    assert all(row["status"] == "pass" for row in cases)
    assert not any((R / "tmp").iterdir())
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
            "sha256": {str((R / name).relative_to(P)): digest(R / name) for name in sorted(frozen)},
            "tooling_invocations": len(cases),
            "native_invocations": 0,
            "builds_unchanged": 3,
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
            "historical_failed_records_and_all_repair_entries_preserved": True,
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [row["name"] for row in rows] == [
        "quality",
        "quality-2",
        "quality-3",
        "tooling",
        "quality-4",
        "quality-5",
        "tooling-rerun-1",
        "prepare",
        "full-audit",
    ]
    assert rows[0]["status"] == "failed" and rows[0]["stop"] is None
    assert "F401" in (R / "quality.log").read_text()
    assert rows[1]["status"] == "failed" and rows[1]["stop"] is None
    assert "E501" in (R / "quality-2.log").read_text()
    assert rows[4]["status"] == "failed" and rows[4]["stop"] is None
    assert "refusing to overwrite" in (R / "quality-4.log").read_text()
    for row in [*rows[2:4], *rows[5:-1]]:
        policy.validate_record(row, "repair/" + row["name"])
    old = read(OLD / "run-ledger.json")
    for index in (0, 2, 3):
        policy.validate_record(old[index], "compatibility/" + old[index]["name"])
    # Historical failures remain failures. Validation does not bless them as successes.
    for index in (1, 4):
        try:
            policy.validate_record(old[index], "compatibility/" + old[index]["name"])
        except ValueError:
            pass
        else:
            raise AssertionError("historical failed record incorrectly admitted")
    assert old[1]["stop"] == "diagnostic/package output stop"
    assert old[4]["exit_code"] == 1 and not read(OLD / "result.json")["passed"]
    assert rows[-1]["status"] == "launched"
    charge = 5 + sum(row.get("seconds", row["limit_seconds"]) for row in rows)
    assert charge <= 40 and 11.543774288264103 + charge <= 150
    assert 416.6145209448878 + charge <= 674
    cases = read(R / "tooling-ledger.json")
    assert len(cases) == 8 and all(row["status"] == "pass" for row in cases)
    reruns = read(R / "tooling-rerun-ledger.json")
    assert len(reruns) == 1 and reruns[0]["status"] == "pass"
    assert 402 + len(cases) + len(reruns) + 24 <= 438
    assert read(OLD / "native-case-outcomes.json")["admitted_native_invocations"] == 0
    return 416.6145209448878 + charge


def full_audit():
    expected = read(R / "preparation.json")["scope_sha256"]
    assert hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest() == expected
    path = PREVIOUS / "checks.py"
    text = path.read_text()
    begin, end = text.index("def full_audit():"), text.index("\ndef run(")
    function = text[begin:end].replace(
        "Reconciled trees/provisioned pins; two failed native builds; zero native cases",
        "Eight tooling cases; corrected resource policy; no native build or invocation",
    )
    function = function.replace('including_prior_package": 402', 'including_prior_package": 411')
    function = function.replace(
        '    m = types.ModuleType("preservation")',
        "    source = source.replace('\"test_invocations\": {},', "
        '\'"test_invocations": {"tooling": 9},\')\n'
        "    source = source.replace('\"unique_new_tests\": 0,', '\"unique_new_tests\": 8,')\n"
        '    m = types.ModuleType("preservation")',
    )
    m = types.ModuleType("audit_wrapper")
    m.__dict__.update(globals())
    exec(compile(function, str(path), "exec"), m.__dict__)
    m.full_audit()


def run(name):
    {
        "quality": quality,
        "quality-2": quality,
        "quality-3": quality,
        "quality-4": quality,
        "quality-5": quality,
        "prepare": prepare,
        "full-audit": full_audit,
    }[name]()
