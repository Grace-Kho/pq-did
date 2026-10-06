"""Bounded native prerequisite assessment and reused preservation workflow."""

import hashlib
import json
import os
import resource
import subprocess
import sys
import types
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
B = P / "docs/data/s3_aurora_transcript_regression_1"
F = B / "repair-2/finalisation-1"
C = B / "repair-2/continuation-1"
E = P / "experiments/aurora_native_transcript_pilot_1"
REPORT = P / "docs/stage3_aurora_native_transcript_pilot.md"
BRIDGE = P / "docs/data/s3_aurora_transcript_bridge_1"
A = json.loads((D / "admission.json").read_text())
DOCS = ("docs/status.md", "docs/traceability.md", "docs/spec_issues.md")
previous = types.ModuleType("completed_preservation")
previous.__file__ = str(F / "run.py")
exec(compile((F / "run.py").read_text(), previous.__file__, "exec"), previous.__dict__)
load = previous.h.load
read = previous.read
audit = previous.r.audit
digest = audit.digest_file
old_scope = previous.scope
g = load(B / "run_checks.py", ((
    'unit = "pqdid-auroraregression-" + name',
    'unit = "pqdid-auroranative-" + name',
),))
g.BASE = g.D = D
g.E = E
g.REPORT = REPORT
g.__file__ = str(D / "run.py")
g.CONFIG.update(
    package=A["package"], aggregate_seconds=674, package_seconds=300,
    prior_implementation_charged_seconds=A["implementation_opening_charged_seconds"],
    operator_charge_seconds=5, cleanup_and_evidence_reserve_seconds=30,
    synthetic_case_limit=426, prior_test_invocations=402, expected_total_test_invocations=402,
    test_invocations={}, prior_output_bytes=A["legacy_cumulative_output_bytes"],
    new_evidence_subcap_bytes=2097152,
    command_reservations_seconds=A["command_reservations_seconds"],
    native_memory_bytes=1073741824, build_artifacts_bytes=134217728,
    native_build_attempts_maximum=2, native_test_invocations_maximum=24,
    accounting="New package: five operator/bookkeeping seconds plus actual guard durations; "
    "prior implementation charges retained; analysis/isolation unchanged.",
)
g.FILES = [str(D / "run.py"), str(E)]
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(D / "run.py"), "work", name]
    for name in A["command_reservations_seconds"]
}
NAMES = {
    "run.py", "admission.json", "prefixes.json", "config.json", "run.lock",
    "run-ledger.json", "native-preflight.json", "native-preflight.log",
    "native-preflight.service.json", "dependency-assessment.json", "source-copy.json",
    "case-plan.json", "quality.json", "quality.log", "quality.service.json",
    "checked-inputs.json", "preparation.json", "prepare.json", "prepare.log",
    "prepare.service.json", "validation.json", "phases.json", "full-audit.json",
    "full-audit.log", "full-audit.service.json", "result.json", "STOP.json",
    "validation-closure.json", "manifest.json",
}


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=1)
    assert len(result.stdout.encode()) + len(result.stderr.encode()) < 61440
    return {"argv": args, "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def preflight():
    assert digest(F / "manifest.json") == A["previous_finalisation_manifest_sha256"]
    assert read(F / "result.json")["passed"]
    assert digest(P / "docs/manuscript/PQ_DID__Implementation.pdf") == (
        "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    rows = [*read(BRIDGE / "sources.json")["rows"],
            *read(BRIDGE / "sources-supplement.json")["rows"]]
    copied = []
    for row in rows:
        assert row["commit"] == "a2ed2ec2f3e85f29b6035951553b02cb737c817a"
        data = (BRIDGE / row["local"]).read_bytes()
        assert len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == (
            row["git_blob_sha1"]
        )
        if row["path"] in A["selected_sources"]:
            target = E / "upstream" / row["path"]
            assert not target.exists()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            assert digest(target) == row["sha256"]
            copied.append({"path": str(target.relative_to(P)), "upstream_path": row["path"],
                           "sha256": row["sha256"], "git_blob_sha1": row["git_blob_sha1"]})
    assert len(copied) == len(A["selected_sources"])
    audit.write_report(D / "source-copy.json", {
        "recorded_commit": rows[0]["commit"], "snapshot_files_verified": len(rows),
        "copied": copied, "patched_files": [], "complete_checkout": False,
        "provenance": "Sealed commit-addressed source snapshot and Git blob identities; "
        "no local commit/tree object or complete transitive checkout available.",
    })
    queries = [command(args) for args in (
        ["/usr/bin/c++", "--version"], ["/usr/bin/cmake", "--version"],
        ["/usr/bin/ninja", "--version"], ["/usr/bin/pkg-config", "--modversion", "libsodium"],
        ["/usr/bin/pkg-config", "--modversion", "libff"],
        ["/usr/bin/dpkg-query", "-W", "-f=${Package} ${Version} ${Status}\n",
         "libsodium23", "libsodium-dev"],
    )]
    paths = ["/usr/include/sodium/crypto_generichash_blake2b.h", "/usr/include/sodium.h",
             "/usr/local/include/sodium/crypto_generichash_blake2b.h",
             "/usr/include/libff/algebra/field_utils/field_utils.hpp",
             "/usr/local/include/libff/algebra/field_utils/field_utils.hpp",
             "/usr/include/libiop/bcs/hashing/hashing.hpp",
             "/usr/local/include/libiop/bcs/hashing/hashing.hpp",
             str(P / "native/.deps/libiop"), str(P / "native/.deps/libff"),
             "/opt/libiop", "/opt/libff"]
    presence = {name: Path(name).exists() for name in paths}
    search = command(["/usr/bin/rg", "--files", "--hidden",
                      "-g", "field_utils.hpp", "-g", "crypto_generichash_blake2b.h",
                      "-g", "libsodium.pc", "-g", "hashing.hpp", "-g", "bcs_common.hpp",
                      "native", ".tools", ".cache", "/usr/include", "/usr/local/include", "/opt"])
    runtime = Path("/usr/lib/x86_64-linux-gnu/libsodium.so.23.3.0")
    # A dependency absence is a recorded admission blocker, not a transcript failure.
    blocked = not any(presence.values()) and queries[3]["exit_code"] != 0
    assert blocked, "Unexpected prerequisite state: review before any build admission"
    audit.write_report(D / "dependency-assessment.json", {
        "status": "native-admission-blocked", "queries": queries,
        "header_checkout_presence": presence, "bounded_source_search": search,
        "runtime_library": {"path": str(runtime), "exists": runtime.exists(),
                            "sha256": digest(runtime) if runtime.exists() else None},
        "missing": ["libsodium development headers/pkg-config metadata",
                    "libff field headers/library and transitive revision pins",
                    "complete libiop headers including bcs/hashing/hashing.hpp",
                    "complete commit checkout and pinned transitive dependency closure"],
        "native_build_admitted": False, "build_attempts": 0, "native_invocations": 0,
        "header_stubs_or_manual_ABI_substitutes": False,
        "runtime_library_is_not_development_or_source_pin": True,
        "dependencies_installed": False,
    })
    cases = read(P / "docs/data/s3_aurora_transcript_correction_contract_1/regressions.json")
    ledger = read(B / "case-ledger.json")
    assert len(ledger) == len(cases["cases"]) == 16
    plan = []
    for item, retained in zip(cases["cases"], ledger, strict=True):
        assert item["id"] == retained["id"] and retained["status"] == "pass"
        plan.append({"id": item["id"], "definition": item["case"],
                     "expected": item["expected"], "status": "not-run-dependency-blocked",
                     "native_invocation": None,
                     "retained_expectation": str((B / retained["evidence"]).relative_to(P)),
                     "retained_sha256": digest(B / retained["evidence"])})
    audit.write_report(D / "case-plan.json", {
        "cases": plan, "distinct_definitions": 15, "counted_repeat": "TR-02",
        "negative_control": "TR-16 old omission; not executed natively; not a forgery",
        "expected_results_generated": False, "native_tests_consumed": 0,
        "prior_tests_consumed": 402, "ceiling": 426,
    })


def quality():
    for args in (("format",), ("check", "--select", "I", "--fix"), ("check",),
                 ("format", "--check")):
        subprocess.run([str(P / ".venv/bin/ruff"), *args, "--no-cache", str(D / "run.py")],
                       check=True, timeout=0.4)
    audit.write_report(D / "checked-inputs.json", {"sha256": {
        str((D / name).relative_to(P)): digest(D / name)
        for name in ("run.py", "admission.json", "config.json", "prefixes.json",
                     "source-copy.json", "dependency-assessment.json", "case-plan.json")
    }})


def scope():
    value = old_scope()
    retained = read(F / "manifest.json")["sha256"]
    required = set(value["required_names"]) | set(retained) | {
        str((F / "manifest.json").relative_to(P))
    }
    for name, expected in retained.items():
        if name not in DOCS:
            assert value["frozen_package_inputs"].get(name, expected) == expected
            value["frozen_package_inputs"][name] = expected
    value["frozen_package_inputs"][str((F / "manifest.json").relative_to(P))] = (
        A["previous_finalisation_manifest_sha256"]
    )
    value["frozen_package_inputs"].update(read(D / "checked-inputs.json")["sha256"])
    for row in read(D / "source-copy.json")["copied"]:
        required.add(row["path"])
        value["frozen_package_inputs"][row["path"]] = row["sha256"]
    required.update((str(REPORT.relative_to(P)), str((E / "README.md").relative_to(P))))
    value["required_names"] = sorted(required)
    value["optional_names"] = sorted(set(value["optional_names"]) | {
        str((D / name).relative_to(P)) for name in NAMES
    })
    value["additional_name_inventory_roots"] = [
        *value["additional_name_inventory_roots"], str(E.relative_to(P))
    ]
    value["new_python_files"] = [*value["new_python_files"], str((D / "run.py").relative_to(P))]
    value["new_markdown_files"] = [*value["new_markdown_files"], str(REPORT.relative_to(P)),
                                   str((E / "README.md").relative_to(P))]
    return value


def prepare():
    value = scope()
    result = audit.inventory_check(P, value["additional_name_inventory_roots"],
                                   set(value["required_names"]),
                                   optional_names=set(value["optional_names"]))
    assert result["passed"], result
    audit.write_report(D / "preparation.json", {
        "inventory": result,
        "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        "historical_repair_entries_from_seals": True, "baseline_regenerated": False,
    })


def full_audit():
    value = scope()
    assert hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() == (
        read(D / "preparation.json")["scope_sha256"]
    )
    for name, row in read(D / "prefixes.json").items():
        assert digest(P / name, prefix_bytes=row["bytes"]) == row["sha256"]
    r = previous.r
    source = (B / "repair-1/repair.py").read_text()
    assert source.count("assert package_bytes() < 262144") == 2
    source = source.replace("assert package_bytes() < 262144", "assert package_bytes() < 2097152")
    exec(compile(source, r.__file__, "exec"), r.__dict__)
    r.R = D
    r.load_scope = scope
    r.package_bytes = g.package_size
    historical = read(F / "validation-closure.json")["combined_package_charge_seconds"]
    reused_check = next(row for row in read(C / "run-ledger.json") if row["name"] == "checks")
    reused_check["service"] = read(C / reused_check["service_record"])
    r.hydrated_runs = lambda: [reused_check, *read(D / "run-ledger.json")]

    def routed(path):
        result = read(path)
        if path == B / "config.json":
            old = read(B / "run-ledger.json")
            result.update(package=A["package"], aggregate_seconds=674,
                          prior_output_bytes=A["legacy_cumulative_output_bytes"])
            result["operator_charge_seconds"] = (
                historical + 5 - sum(row["seconds"] for row in old[:-1])
                - reused_check["seconds"] - 5 - old[-1]["seconds"]
            )
        return result

    def module(name):
        changes = ()
        if name == "audit":
            changes = (
                ('(D / row["evidence"]).is_file()',
                 '(REGRESSION_EVIDENCE_INPUT / row["evidence"]).is_file()'),
                ('config["aggregate_seconds"] == 374', 'config["aggregate_seconds"] == 674'),
                ("charged + 10 <= 374 and package_charge + 10 <= 25",
                 f"charged + 30 <= 674 and package_charge - {historical!r} + 30 <= 300"),
                ('experiment = P / "experiments/aurora_transcript_regression_1"',
                 'experiment = P / "experiments/aurora_native_transcript_pilot_1"'),
                ('package_bytes += (P / "docs/stage3_aurora_transcript_regression.md").stat().st_size',
                 'package_bytes += (P / "docs/stage3_aurora_native_transcript_pilot.md").stat().st_size'),
                ('package_bytes < 262144, "new package subcap"',
                 'package_bytes < 2097152, "new package subcap"'),
            )
        result = load(B / (name + ".py"), changes)
        result.REGRESSION_EVIDENCE_INPUT = B
        return result

    r.read = routed
    r.module = module
    r.full_audit()


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        {"native-preflight": preflight, "quality": quality,
         "prepare": prepare, "full-audit": full_audit}[sys.argv[2]]()
    else:
        config = D / "config.json"
        if not config.exists():
            config.write_text(json.dumps(g.CONFIG, indent=2) + "\n")
        assert read(config) == g.CONFIG
        raise SystemExit(g.main(sys.argv[1]))
