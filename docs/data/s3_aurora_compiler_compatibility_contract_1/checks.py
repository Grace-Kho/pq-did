"""Static patch review and unchanged complete preservation comparisons only."""

import difflib
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[2]
PREVIOUS = P / "docs/data/s3_aurora_native_transcript_pilot_1/reconciliation-1"
ARTIFACT = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
REPORT = P / "docs/stage3_aurora_compiler_compatibility_contract.md"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
sys.dont_write_bytecode = True


def load(path):
    module = types.ModuleType("retained_" + path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(PREVIOUS / "checks.py")
guard = load(R / "run.py")
audit, read, digest = prior.audit, prior.read, prior.digest
NAMES = {
    "run.py",
    "checks.py",
    "config.json",
    "prefixes.json",
    "reviewed-inputs.json",
    "opening-ledger.json",
    "variable-members.patch",
    "semantic-target.patch",
    "semantic_cases.cpp",
    "proposal.json",
    "runbook.md",
    "run-ledger.json",
    "run.lock",
    "checked-inputs.json",
    "static-review.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "STOP.json",
    *{
        name + suffix
        for name in ("quality", "prepare", "full-audit")
        for suffix in (".json", ".log", ".service.json")
    },
}


def scope():
    value = prior.scope()
    seal = PREVIOUS / "manifest.json"
    assert digest(seal) == "f3125c0cdbee596222ebf0736a8647afc94d37a02e21511fec2d5dffe3d2bd56"
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
    required.add(str(REPORT.relative_to(P)))
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(
        set(value["optional_names"]) | {str((R / n).relative_to(P)) for n in NAMES}
    )
    value["new_python_files"] += [str((R / n).relative_to(P)) for n in ("run.py", "checks.py")]
    value["new_markdown_files"] += [
        str(REPORT.relative_to(P)),
        str((R / "runbook.md").relative_to(P)),
    ]
    return value


def quality():
    files = [str(R / n) for n in ("run.py", "checks.py")]
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files], check=True, timeout=0.5
        )
    inputs = read(R / "reviewed-inputs.json")
    for name, expected in inputs["sha256"].items():
        assert digest(P / name) == expected, name
    original = (P / inputs["target_path"]).read_text()
    proposed = original
    for before, after in inputs["replacements"].items():
        assert proposed.count(before) == 1
        proposed = proposed.replace(before, after)
    assert hashlib.sha256(proposed.encode()).hexdigest() == inputs["proposed_target_sha256"]
    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            proposed.splitlines(keepends=True),
            fromfile="a/libiop/relations/variable.tcc",
            tofile="b/libiop/relations/variable.tcc",
        )
    )
    assert diff == (R / "variable-members.patch").read_text()
    commands = []
    for directory, patch in (
        (ARTIFACT / "src/libiop", "variable-members.patch"),
        (ARTIFACT / "work/libiop", "variable-members.patch"),
        (ARTIFACT / "overlay", "semantic-target.patch"),
    ):
        command = [
            "git",
            "--no-replace-objects",
            "-C",
            str(directory),
            "apply",
            "--check",
            str(R / patch),
        ]
        run = subprocess.run(command, capture_output=True, text=True, timeout=0.5)
        commands.append(
            {
                "argv": command,
                "exit_code": run.returncode,
                "stdout": run.stdout,
                "stderr": run.stderr,
            }
        )
        assert run.returncode == 0, commands[-1]
    assert digest(P / inputs["target_path"]) == inputs["target_sha256"]
    proposal = read(R / "proposal.json")
    assert proposal["authorised"] is False
    assert len(proposal["semantics_ids"]) + len(proposal["transcript_ids"]) == 24
    assert proposal["new_build_attempts_requested"] == 1
    assert 55 + 24 * 2 + 17 + 30 == proposal["admission_reservation_seconds"] == 150
    for name, expected in proposal["review_artifacts_sha256"].items():
        assert digest(R / name) == expected
    assert guard.package_size() < 262144
    audit.write_report(
        R / "static-review.json",
        {
            "passed": True,
            "patch_applicability_commands": commands,
            "source_mutations": 0,
            "compilations": 0,
            "native_invocations": 0,
            "expected_postimage_sha256": inputs["proposed_target_sha256"],
            "patch_sha256": inputs["patch_sha256"],
            "future_allowance_inactive": True,
        },
    )
    files = [
        path
        for path in R.iterdir()
        if path.is_file()
        and path.name
        not in {
            "run-ledger.json",
            "run.lock",
            "quality.json",
            "quality.log",
            "quality.service.json",
        }
    ]
    assert all(path.name in NAMES for path in files)
    audit.write_report(
        R / "checked-inputs.json",
        {
            "sha256": {str(path.relative_to(P)): digest(path) for path in files},
            "native_builds_unchanged": 2,
            "cumulative_invocations_unchanged": 402,
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
            "historical_repair_and_build_failure_entries_preserved": True,
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [row["name"] for row in rows] == ["quality", "prepare", "full-audit"]
    original.prior.check_runs(R, {"quality", "prepare"})
    assert all(row["status"] in {"pass", "launched"} for row in rows)
    charge = 5 + sum(row.get("seconds", row["limit_seconds"]) for row in rows)
    assert charge + 10 <= 30
    assert charge + 120.20447600178886 + 10 <= 300
    last = read(PREVIOUS / "validation-closure.json")
    assert last["cumulative_invocations_used"] == 402
    assert last["native_build_attempts_used"] == 2
    assert last["implementation_remaining_seconds"] == 268.92925334337633
    assert last["native_package_remaining_seconds"] == 264.3718736843439
    assert last["provisioning_remaining_seconds"] == 41.843650440103374
    assert read(R / "config.json")["test_invocations"] == {}
    return 120.20447600178886 + charge


def full_audit():
    expected = read(R / "preparation.json")["scope_sha256"]
    assert hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest() == expected
    # Reuse the preceding complete auditor, changing package accounting only.
    path = PREVIOUS / "checks.py"
    text = path.read_text()
    begin = text.index("def full_audit():")
    end = text.index("\ndef run(", begin)
    function = text[begin:end]
    function = function.replace(
        '"implementation_remaining_including_audit_reservation": 674 - charged',
        '"implementation_allowance_remaining_unchanged": 268.92925334337633',
    )
    function = function.replace(
        "Reconciled trees/provisioned pins; two failed native builds; zero native cases",
        "Source-only compatibility contract; no configuration/build/native case",
    )
    m = types.ModuleType("audit_wrapper")
    m.__dict__.update(globals())
    exec(compile(function, str(path), "exec"), m.__dict__)
    m.full_audit()


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
