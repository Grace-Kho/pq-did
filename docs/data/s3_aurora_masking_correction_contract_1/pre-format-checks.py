"""Static review and the retained full preservation workflow; no test dispatch."""

import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[2]
PREVIOUS = P / "docs/data/s3_aurora_query_masking_contract_1"
REPORT = P / "docs/stage3_aurora_masking_correction_contract.md"
DOCS = tuple(json.loads((R / "prefixes.json").read_text()))
sys.dont_write_bytecode = True
PYTHON = ("run.py", "checks.py")
PHASES = {"quality": 3, "prepare": 3, "full-audit": 7}
NAMES = {
    *PYTHON,
    "config.json",
    "prefixes.json",
    "opening-ledger.json",
    "prior-package-closure.json",
    "literature.json",
    "reviewed-inputs.json",
    "contract.json",
    "static-review.json",
    "checked-inputs.json",
    "run-ledger.json",
    "run.lock",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "STOP.json",
    *{"STOP-" + phase + ".json" for phase in PHASES},
    *{
        phase + suffix
        for phase in PHASES
        for suffix in (".json", ".log", ".service.json", ".fatal.json")
    },
}


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


prior = load(PREVIOUS / "checks.py")
guard = load(R / "run.py")
audit, read, digest = prior.audit, prior.read, prior.digest


def scope():
    value = prior.scope()
    seal = PREVIOUS / "manifest.json"
    expected_seal = "887421bc7b58261c7fe207a9a2b9791ef8e12976245ffa685484f033c978c960"
    assert digest(seal) == expected_seal
    required = set(value["required_names"]) | set(read(seal)["sha256"])
    required.add(str(seal.relative_to(P)))
    for name, expected in read(seal)["sha256"].items():
        if name not in DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str(seal.relative_to(P))] = expected_seal
    for name, prefix in read(R / "prefixes.json").items():
        assert read(seal)["sha256"][name] == prefix["sha256"]
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
    value["new_python_files"] += [str((R / n).relative_to(P)) for n in PYTHON]
    value["new_markdown_files"] += [str(REPORT.relative_to(P))]
    return value


def quality():
    files = [str(R / n) for n in PYTHON]
    commands = []
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        argv = [str(P / ".venv/bin/ruff"), *args, "--no-cache", *files]
        subprocess.run(argv, check=True, timeout=0.5)
        commands.append(argv)
    for name, expected in read(R / "reviewed-inputs.json")["sha256"].items():
        assert digest(P / name) == expected, name
    old = read(PREVIOUS / "validation-closure.json")
    assert old["complete"] and old["report_readback_complete"] and old["outer_guard_passed"]
    assert old["cumulative_evidence_bytes"] == 16323830
    assert old["package_output_remaining_bytes"] == 919201
    assert guard.package_size() < 1048576 - 262144
    assert 16323830 + 1048576 < 18874368
    audit.write_report(
        R / "static-review.json",
        {
            "passed": True,
            "commands": commands,
            "native_evidence_reused": True,
            "new_functional_invocations": 0,
            "builds": 0,
            "cumulative_invocations_unchanged": 448,
            "query_masking_package_closed": True,
            "unused_evidence_reservation_released_bytes": 919201,
            "consumption_refunded": 0,
            "output_admission_passed": True,
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
        {"sha256": {str((R / n).relative_to(P)): digest(R / n) for n in sorted(frozen)}},
    )
    value = scope()
    inventory = audit.inventory_check(
        P,
        value["additional_name_inventory_roots"],
        set(value["required_names"]),
        optional_names=set(value["optional_names"]),
    )
    assert inventory["passed"], inventory
    audit.write_report(
        R / "preparation.json",
        {
            "inventory": inventory,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
            "retained_repair_entries_preserved": True,
        },
    )


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [row["name"] for row in rows] == ["quality", "prepare", "full-audit"]
    original.prior.check_runs(R, {"quality", "prepare"})
    assert all(row["status"] in {"pass", "launched"} for row in rows)
    config = read(R / "config.json")
    charge = config["operator_charge_seconds"] + sum(
        row.get("seconds", row["limit_seconds"]) for row in rows
    )
    assert charge + 10 <= 60
    assert charge + config["prior_analysis_charged_seconds"] + 10 <= 300
    old = read(PREVIOUS / "validation-closure.json")
    opening = read(R / "opening-ledger.json")
    assert old["cumulative_invocations"] == opening["cumulative_invocations"] == 448
    assert old["builds_used"] == opening["builds_used"] == 5
    assert (
        old["native_package_remaining_seconds_unchanged"] == opening["native_remaining_unchanged"]
    )
    assert (
        old["implementation_remaining_seconds_unchanged"]
        == opening["implementation_remaining_unchanged"]
    )
    assert config["test_invocations"] == {}
    assert not read(R / "contract.json")["profile_adopted"]
    closure = read(R / "prior-package-closure.json")
    assert (
        closure["unused_evidence_reservation_released_bytes"]
        == old["package_output_remaining_bytes"]
    )
    assert closure["consumption_refunded"] == 0
    return config["prior_analysis_charged_seconds"] + charge


def full_audit():
    assert (
        hashlib.sha256(json.dumps(scope(), sort_keys=True).encode()).hexdigest()
        == read(R / "preparation.json")["scope_sha256"]
    )
    # Same comparison implementation as the completed native and analysis packages.
    path = P / "docs/data/s3_aurora_native_transcript_pilot_1/reconciliation-1/checks.py"
    source = path.read_text()
    function = source[source.index("def full_audit():") : source.index("\ndef run(")]
    function = function.replace('"output_bytes":12386485', '"output_bytes":18874368')
    function = function.replace('"aggregate_seconds":674', '"aggregate_seconds":300')
    function = function.replace('including_prior_package": 402', 'including_prior_package": 448')
    function = function.replace(
        '"implementation_remaining_including_audit_reservation": 674 - charged',
        '"implementation_allowance_remaining_unchanged": 111.82163787621539',
    )
    function = function.replace(
        "Reconciled trees/provisioned pins; two failed native builds; zero native cases",
        "Masking correction source contract; no source patch/test/build/proof; prior evidence reused",
    )
    module = types.ModuleType("preservation_wrapper")
    module.__dict__.update(globals())
    exec(compile(function, str(path), "exec"), module.__dict__)
    module.full_audit()


def run(name):
    {"quality": quality, "prepare": prepare, "full-audit": full_audit}[name]()
