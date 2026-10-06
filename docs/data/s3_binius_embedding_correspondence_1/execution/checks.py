"""Reuse the established analysis guard and complete preservation comparisons."""

import hashlib
import inspect
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit  # noqa: E402

C = P / "docs/data/s3_binius_embedding_correspondence_1"
REPORT = P / "docs/stage3_binius_embedding_correspondence.md"
PHASES = (
    "preflight",
    "acquire",
    "quality",
    "quality-2",
    "quality-3",
    "quality-4",
    "prepare",
    "prepare-2",
    "full-audit",
    "readback",
)
OUTPUTS = {
    "run-ledger.json",
    "run.lock",
    "static-review.json",
    "checked-inputs-v2.json",
    "preparation.json",
    "validation.json",
    "phases.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "final-inventory.json",
    "resource-closure.json",
    "audit-failure.json",
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


prior = load(C / "checks.py")
p = prior.p
g = load(R / "run.py")
read = prior.read
write = audit.write_report
digest = audit.digest_file


def name(path):
    return path.relative_to(P).as_posix()


def historical():
    opening = read(R / "approval.json")
    assert digest(C / "manifest.json") == opening["proposal_manifest_sha256"]
    assert digest(C / "validation-closure.json") == opening["proposal_closure_sha256"]
    closure = read(C / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    seals = read(C / "manifest.json")["sha256"]
    seals.update(closure["finalisation_sha256"])
    seals[name(C / "manifest.json")] = opening["proposal_manifest_sha256"]
    seals[name(C / "validation-closure.json")] = opening["proposal_closure_sha256"]
    return seals


def verify_snapshot():
    seals = historical()
    prefixes = read(R / "prefixes.json")
    for path, expected in seals.items():
        if path in prefixes:
            assert prefixes[path]["sha256"] == expected
            actual = digest(P / path, prefix_bytes=prefixes[path]["bytes"])
        else:
            actual = digest(P / path)
        assert actual == expected, path
    return len(seals)


def scope():
    value = prior.scope()
    seals = historical()
    value["frozen_package_inputs"].update(seals)
    for path, prefix in read(R / "prefixes.json").items():
        assert seals[path] == prefix["sha256"]
        value["frozen_package_inputs"].pop(path)
        value["append_only_documentation"][path] = prefix
    checked = read(R / "checked-inputs-v2.json")["sha256"]
    value["frozen_package_inputs"].update(checked)
    value["required_names"] = sorted(
        set(value["required_names"])
        | (
            set(seals)
            - {
                "PQ_DID_Binius64_Independent_Review.md",
                "PQ_DID_Binius64_Native_Embedding_Analysis.md",
            }
        )
        | set(checked)
        | {name(REPORT)}
    )
    value["optional_names"] = sorted(set(value["optional_names"]) | {name(R / n) for n in OUTPUTS})
    if not any(name(R).startswith(root + "/") for root in value["additional_name_inventory_roots"]):
        value["additional_name_inventory_roots"].append(name(R))
    value["new_python_files"] += [name(R / n) for n in ("run.py", "admission.py", "checks.py")]
    value["new_markdown_files"] += ["experiments/binius_embedding_correspondence_1/README.md"]
    value["additional_name_inventory_roots"].append("experiments/binius_embedding_correspondence_1")
    return value


def quality():
    commands = []
    for args in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        command = [
            str(P / ".venv/bin/ruff"),
            *args,
            "--no-cache",
            *[str(R / n) for n in ("run.py", "admission.py", "checks.py")],
        ]
        subprocess.run(command, check=True, timeout=0.7)
        commands.append(command)
    count = verify_snapshot()
    acquisition = read(R / "source-acquisition.json")
    assert acquisition["passed"] and len(acquisition["sources"]) == 15
    assert sum(row["bytes"] for row in acquisition["sources"]) == 176779
    tree = read(
        P / "docs/data/oct31_binius64_replacement_decision_1/sources/implementation-tree.json"
    )
    index = {row["path"]: row for row in tree["tree"]}
    for row in acquisition["sources"]:
        path = P / row["retained_path"]
        assert digest(path) == row["sha256"]
        assert path.stat().st_size == row["bytes"] == index[row["upstream_path"]]["size"]
        assert row["git_blob"] == index[row["upstream_path"]]["sha"]
    outcomes = read(R / "case-outcomes.json")
    assert len(outcomes["fixed_cases"]) == 25 and outcomes["new_invocations"] == 0
    assert all(row["status"] == "unrun" for row in outcomes["fixed_cases"])
    assert (
        read(R / "representation-blocker.json")["status"]
        == "blocked-before-component-implementation"
    )
    manuscript = P / "docs/manuscript/PQ_DID__Implementation.pdf"
    assert digest(manuscript) == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    assert g.package_size() < 2097152
    write(
        R / "static-review-final.json",
        {
            "passed": True,
            "commands": commands,
            "sealed_predecessor_paths": count,
            "retained_source_blobs_rechecked": 15,
            "approved_proposal_identity_verified": True,
            "tests": 0,
            "builds": 0,
            "proofs": 0,
            "invocations_unchanged": 1140,
            "source_acquisition_memory_compliance_certified": False,
            "resource_observation": (
                "Prior acquisition qualification unchanged; new acquisition cgroup metrics separate"
            ),
        },
    )


def prepare():
    assert read(R / "quality-4.json")["status"] == "pass"
    assert not any((R / "tmp").iterdir())
    frozen = {}
    for path in sorted(R.rglob("*")):
        if path.is_dir():
            continue
        assert not path.is_symlink()
        if path.relative_to(R).as_posix() not in OUTPUTS or path.name in {
            "static-review.json",
            "quality.json",
            "quality.log",
            "quality.service.json",
        }:
            frozen[name(path)] = digest(path)
    extra = P / "experiments/binius_embedding_correspondence_1/README.md"
    frozen[name(extra)] = digest(extra)
    write(
        R / "checked-inputs-v2.json", {"sha256": frozen, "historical_baselines_regenerated": False}
    )
    value = scope()
    inventory = p.inventory(value)
    write(
        R / "preparation.json",
        {
            "passed": inventory["passed"],
            "inventory": inventory,
            "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
            "historical_baselines_regenerated": False,
        },
    )
    assert inventory["passed"], inventory


def current_checks(original):
    rows = read(R / "run-ledger.json")
    assert [row["name"] for row in rows] == [
        "preflight",
        "acquire",
        "quality",
        "quality-2",
        "prepare",
        "quality-3",
        "quality-4",
        "prepare-2",
        "full-audit",
    ]
    original.prior.check_runs(R, {"preflight", "acquire", "quality-2", "quality-4", "prepare-2"})
    correction = read(R / "formatting-correction.json")
    assert digest(R / "quality.json") == correction["failed_guard_sha256"]
    assert rows[2]["status"] == "failed" and rows[2]["stop"] is None
    assert read(R / "quality.json")["exit_code"] == 1
    assert "E501 Line too long" in (R / "quality.log").read_text()
    repair = read(R / "preparation-correction.json")
    assert digest(R / "prepare.json") == repair["failed_guard_sha256"]
    assert digest(R / "checked-inputs.json") == repair["partial_snapshot_sha256"]
    assert rows[4]["status"] == "failed" and rows[4]["stop"] is None
    assert "refusing to overwrite an existing report" in (R / "prepare.log").read_text()
    known = read(R / "completion-corrections.json")
    for path, expected in known["sha256"].items():
        assert digest(R / path) == expected
    assert rows[5]["name"] == "quality-3" and rows[5]["status"] == "failed"
    assert rows[-1]["status"] == "launched"
    config = read(R / "config.json")
    charge = config["operator_charge_seconds"] + sum(
        row.get("seconds", row["limit_seconds"]) for row in rows
    )
    assert charge + 10 < 200
    assert config["synthetic_case_limit"] == 1168
    assert not any(row["name"].startswith("EC-") for row in rows)
    assert g.package_size() < 1048576
    assert (
        read(R / "representation-blocker.json")["status"]
        == "blocked-before-component-implementation"
    )
    return 5263.382030437819 + charge


def full_audit():
    source = inspect.getsource(p.full_audit)
    replacements = (
        ('"command_seconds": 300', '"command_seconds": 60'),
        ('"child_seconds": 295', '"child_seconds": 55'),
        ('"aggregate_seconds": 4274', '"aggregate_seconds": 6074'),
        ('"output_bytes": 33554432', '"output_bytes": 41943040'),
        (
            'package="OCT31-KYC-NATIVE-MILESTONE-1"',
            'package="S3-BINIUS-EMBEDDING-CORRESPONDENCE-1"',
        ),
        ("prior_output_bytes=16665098", "prior_output_bytes=34358034"),
        (
            "module.current_storage = guard.storage",
            'module.current_storage = lambda: {"new_evidence_bytes": g.package_size()}',
        ),
        (
            '"implementation_remaining_including_audit_reservation": 4274 - charged',
            '"implementation_remaining_including_audit_reservation": 6074 - charged',
        ),
        ("module.current_cases = current_cases", "module.current_cases = lambda: {}"),
        (
            "module.current_invocations = lambda: 448 + "
            'len(guard.read(D / "ledger.json")["invocations"])',
            "module.current_invocations = lambda: 1140",
        ),
        (
            "Approved isolated native/baseline/benchmark milestone",
            (
                "Approved source acquisition; component blocked at representation admission; "
                "no tests, builds or proofs"
            ),
        ),
    )
    for before, after in replacements:
        assert before in source, before
        source = source.replace(before, after)
    shim = types.SimpleNamespace(
        read=read, write=write, output_role=lambda _: ("evidence", 1048576)
    )
    module = types.ModuleType("analysis_preservation")
    module.__dict__.update(vars(p))
    module.__dict__.update(D=R, scope=scope, current_checks=current_checks, g=g, guard=shim)
    exec(compile(source, str(R / "checks.py"), "exec"), module.__dict__)
    module.full_audit()


def readback():
    assert read(R / "result.json")["passed"]
    assert read(R / "full-audit.json")["status"] == "pass"
    inventory = p.inventory(scope())
    assert inventory["passed"], inventory
    write(R / "final-inventory.json", inventory)
    verify_snapshot()
    for path, expected in read(R / "manifest.json")["sha256"].items():
        assert digest(P / path) == expected, path
    text = REPORT.read_text()
    assert (
        "Preservation" in text
        and "component-only" in text
        and "not complete private authentication" in text
    )
    print(
        json.dumps(
            {
                "passed": True,
                "final_inventory_count": inventory["count"],
                "report_readback": True,
                "new_invocations": 0,
            }
        )
    )


def run(phase):
    {
        "quality": quality,
        "quality-2": quality,
        "quality-3": quality,
        "quality-4": quality,
        "prepare": prepare,
        "prepare-2": prepare,
        "full-audit": full_audit,
        "readback": readback,
    }[phase]()
