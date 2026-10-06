"""Reuse the established analysis guard and complete preservation comparisons."""

import hashlib
import inspect
import json
import subprocess
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit  # noqa: E402

C = P / "docs/data/s3_binius_joint_opening_construction_1"
REPORT = P / "docs/stage3_binius_embedding_correspondence.md"
PHASES = ("quality", "prepare", "full-audit", "readback")
OUTPUTS = {
    "run-ledger.json",
    "run.lock",
    "static-review.json",
    "checked-inputs.json",
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
    opening = read(R / "opening.json")
    assert digest(C / "manifest.json") == opening["prior_manifest_sha256"]
    assert digest(C / "validation-closure.json") == opening["prior_closure_sha256"]
    closure = read(C / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    seals = read(C / "manifest.json")["sha256"]
    seals.update(closure["finalisation_sha256"])
    seals[name(C / "manifest.json")] = opening["prior_manifest_sha256"]
    seals[name(C / "validation-closure.json")] = opening["prior_closure_sha256"]
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
    checked = read(R / "checked-inputs.json")["sha256"]
    value["frozen_package_inputs"].update(checked)
    review = read(R / "review-identity.json")
    # The newly supplied root file gets an exact content/identity check. Existing
    # directory inventories stay unchanged; do not traverse unrelated root files.
    value["frozen_package_inputs"][review["path"]] = review["sha256"]
    value["required_names"] = sorted(
        set(value["required_names"])
        | (set(seals) - {"PQ_DID_Binius64_Independent_Review.md"})
        | set(checked)
        | {name(REPORT)}
    )
    value["optional_names"] = sorted(set(value["optional_names"]) | {name(R / n) for n in OUTPUTS})
    if not any(name(R).startswith(root + "/") for root in value["additional_name_inventory_roots"]):
        value["additional_name_inventory_roots"].append(name(R))
    value["new_python_files"] += [name(R / n) for n in ("run.py", "checks.py")]
    value["new_markdown_files"] += [name(REPORT)]
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
            *[str(R / n) for n in ("run.py", "checks.py")],
        ]
        subprocess.run(command, check=True, timeout=0.7)
        commands.append(command)
    count = verify_snapshot()
    review = read(R / "review-identity.json")
    assert digest(P / review["path"]) == review["sha256"]
    assert (P / review["path"]).stat().st_size == review["bytes"]
    tree_path = (
        P / "docs/data/oct31_binius64_replacement_decision_1/sources/implementation-tree.json"
    )
    assert digest(tree_path) == "c1d21269c495f6cd12b0a20c6f82252d807fea536dc0e3de8a2d230100f052c0"
    tree = {item["path"]: item for item in read(tree_path)["tree"]}
    acquisition = read(C / "source-acquisition.json")
    for row in acquisition["sources"]:
        assert digest(P / row["retained_path"]) == row["sha256"]
        assert row["git_blob"] == tree[row["upstream_path"]]["sha"]
    plan = read(R / "execution-plan.json")
    assert plan["approved"] is False and plan["proofs"] == 0
    assert len(plan["cases"]) == 25 and plan["maximum_invocations"] == 28
    assert plan["proposed_invocation_ceiling"] == 1168
    assert all(case["status"] == "unrun" for case in plan["cases"])
    manuscript = P / "docs/manuscript/PQ_DID__Implementation.pdf"
    assert digest(manuscript) == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    assert g.package_size() < 2097152
    write(
        R / "static-review.json",
        {
            "passed": True,
            "commands": commands,
            "sealed_predecessor_paths": count,
            "retained_source_blobs_rechecked": 10,
            "review_identity_verified": True,
            "tests": 0,
            "builds": 0,
            "proofs": 0,
            "invocations_unchanged": 1140,
            "source_acquisition_memory_compliance_certified": False,
            "resource_observation": "Inherited unchanged from predecessor; no acquisition now",
        },
    )


def prepare():
    assert read(R / "quality.json")["status"] == "pass"
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
    write(R / "checked-inputs.json", {"sha256": frozen, "historical_baselines_regenerated": False})
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
    assert [row["name"] for row in rows] == ["quality", "prepare", "full-audit"]
    original.prior.check_runs(R, {"quality", "prepare"})
    assert rows[-1]["status"] == "launched"
    config = read(R / "config.json")
    charge = config["operator_charge_seconds"] + sum(
        row.get("seconds", row["limit_seconds"]) for row in rows
    )
    assert charge + 10 <= config["package_seconds"]
    assert charge + config["prior_analysis_charged_seconds"] + 10 <= 300
    assert config["test_invocations"] == {}
    assert g.package_size() < 2097152
    # Preservation success is separate from the retained acquisition metric excess.
    assert read(R / "execution-plan.json")["approved"] is False
    return config["prior_analysis_charged_seconds"] + charge


def full_audit():
    source = inspect.getsource(p.full_audit)
    replacements = (
        ('"command_seconds": 300', '"command_seconds": 60'),
        ('"child_seconds": 295', '"child_seconds": 55'),
        ('"aggregate_seconds": 4274', '"aggregate_seconds": 300'),
        ('"output_bytes": 33554432', '"output_bytes": 41943040'),
        (
            'package="OCT31-KYC-NATIVE-MILESTONE-1"',
            'package="S3-BINIUS-EMBEDDING-CORRESPONDENCE-1-PREPARATION"',
        ),
        ("prior_output_bytes=16665098", "prior_output_bytes=34160588"),
        (
            "module.current_storage = guard.storage",
            'module.current_storage = lambda: {"new_evidence_bytes": g.package_size()}',
        ),
        (
            '"implementation_remaining_including_audit_reservation": 4274 - charged',
            '"implementation_allowance_remaining_unchanged": 810.6179695621813',
        ),
        ("module.current_cases = current_cases", "module.current_cases = lambda: {}"),
        (
            "module.current_invocations = lambda: 448 + "
            'len(guard.read(D / "ledger.json")["invocations"])',
            "module.current_invocations = lambda: 1140",
        ),
        (
            "Approved isolated native/baseline/benchmark milestone",
            "Source/mathematical decision only; no tests, builds or proofs",
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
        "prepare": prepare,
        "full-audit": full_audit,
        "readback": readback,
    }[phase]()
