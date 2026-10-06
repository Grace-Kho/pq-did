"""Continue the sealed milestone audit without changing its historical evidence.

The shared live ledger remains at E; the reused auditor writes only into C. Its
case counters use a labelled immutable post-case snapshot. Every historical row
and each old report prefix retain their independently recorded expectations.
"""

import hashlib
import json
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(P))
from experiments.kyc_milestone_1 import preservation as p  # noqa: E402
from experiments.kyc_milestone_1 import run as guard  # noqa: E402
from scripts import preservation_audit as audit  # noqa: E402

E = guard.D
C = Path(__file__).resolve().parent
PRIOR_SEAL = "c0475e4cbbcae25e3bfa1d2c08dedd338c99549f77726450f934e18fb15d4b1c"
REPORTS = (
    "docs/status.md",
    "docs/traceability.md",
    "docs/spec_issues.md",
    "docs/stage2_mldsa_reference_baseline.md",
    "docs/stage3_aurora_masking_native.md",
    "docs/kyc_milestone_benchmarks.md",
    "docs/oct31_kyc_native_milestone.md",
)
JOBS = (
    "native-final-preflight",
    "native-final-cases",
    "native-final-transcripts",
    "native-final-c09",
    "native-final-quality",
    "native-final-quality-2",
    "native-final-prepare",
    "native-final-prepare-2",
    "native-final-full-audit",
    "native-final-readback",
)
FUTURE_JOBS = {
    "native-final-prepare-2",
    "native-final-full-audit",
    "native-final-readback",
}
SUFFIXES = (".json", ".input.json", ".worker.json", ".log")
INPUTS = (
    "opening.json",
    "prior-ledger.json",
    "prior-native-coverage.json",
    "confirmation.json",
    "confirmed-inputs.json",
    "outcomes.json",
    "preflight.py",
    "checks.py",
    "failed-preparation-1/checks.py",
    "failed-preparation-1/preparation.json",
    "failed-preparation-1/new-inventory.json",
    "failed-preparation-1/ledger.json",
    "failed-preparation-1/invocation-snapshot.json",
    "failed-preparation-1/retention.json",
)
OUTPUTS = (
    "preparation.json",
    "new-inventory.json",
    "invocation-snapshot.json",
    "ledger.json",
    "validation.json",
    "phases.json",
    "final-inventory.json",
    "resource-closure.json",
    "result.json",
    "validation-closure.json",
    "manifest.json",
    "audit-failure.json",
)
ORIGINAL_SCOPE = p.scope


def name(path):
    return path.relative_to(P).as_posix()


def trusted_inputs():
    opening = guard.read(C / "opening.json")
    assert opening["prior_manifest_sha256"] == PRIOR_SEAL
    assert opening["requested_cases"] == (
        [f"N-{index:02}" for index in range(1, 25)]
        + [f"TR-{index:02}" for index in range(1, 17)]
        + ["C-09"]
    )
    assert audit.digest_file(E / "manifest.json") == PRIOR_SEAL
    seals = guard.read(E / "manifest.json")["sha256"]
    assert set(opening["report_prefixes"]) == set(REPORTS)
    for path, prefix in opening["report_prefixes"].items():
        assert prefix["sha256"] == seals[path]
        assert audit.digest_file(P / path, prefix_bytes=prefix["bytes"]) == prefix["sha256"]
    for original, retained in (
        ("ledger.json", "prior-ledger.json"),
        ("native-coverage.json", "prior-native-coverage.json"),
    ):
        assert audit.digest_file(C / retained) == seals[name(E / original)]
    assert audit.digest_file(E / "validation-closure.json") == opening["prior_closure_sha256"]
    closure = guard.read(E / "validation-closure.json")
    assert closure["manifest_sha256"] == PRIOR_SEAL
    # The small old result was not self-included in its manifest. Its exact
    # serialisation is determined by the independently sealed original closure.
    expected_result = {
        "package": closure["package"],
        "preservation_passed": closure["preservation_complete"],
        "overall_complete": closure["complete"],
        "outcome": closure["overall_outcome"],
        "closure": "validation-closure.json",
        "manifest_sha256": PRIOR_SEAL,
    }
    expected_bytes = (json.dumps(expected_result, indent=2) + "\n").encode()
    expected_result_hash = hashlib.sha256(expected_bytes).hexdigest()
    assert audit.digest_file(E / "result.json") == expected_result_hash
    return opening, seals, expected_result_hash


def live_records():
    opening, _, _ = trusted_inputs()
    prior = guard.read(C / "prior-ledger.json")
    rows = guard.read(E / "ledger.json")
    assert set(rows) == set(prior) == {"jobs", "invocations", "builds", "bookkeeping"}
    for key in rows:
        assert rows[key][: len(prior[key])] == prior[key], key
    assert rows["builds"] == prior["builds"], "No continuation build authorised"
    new_cases = rows["invocations"][len(prior["invocations"]) :]
    assert [row["case_id"] for row in new_cases] == opening["requested_cases"]
    assert all(row["status"] == "pass" for row in new_cases)
    new_jobs = rows["jobs"][len(prior["jobs"]) :]
    assert all(row["name"] in JOBS for row in new_jobs)
    assert len({row["name"] for row in new_jobs}) == len(new_jobs)
    old_coverage = guard.read(C / "prior-native-coverage.json")
    coverage = guard.read(E / "native-coverage.json")
    assert set(coverage) == set(old_coverage) == {"cases"}
    assert coverage["cases"][: len(old_coverage["cases"])] == old_coverage["cases"]
    added_coverage = coverage["cases"][len(old_coverage["cases"]) :]
    assert [row["case_id"] for row in added_coverage] == opening["requested_cases"][:-1]
    by_id = {row["invocation_id"]: row for row in new_cases}
    confirmed = guard.read(C / "confirmed-inputs.json")
    assert confirmed["passed"] and confirmed["previous_full_seal"] == PRIOR_SEAL
    for row in added_coverage:
        assert row["status"] == "pass"
        assert by_id[row["invocation_id"]]["case_id"] == row["case_id"]
        assert row["actual_calls"], row["case_id"]
        binary = "aurora_masking_native" if row["case_id"].startswith("N-") else "exp2_native"
        assert row["binary_sha256"] == confirmed["binary_sha256"][binary]
        assert row["source_manifest_sha256"] == confirmed["build_inputs"]["patch-manifest.json"]
    outcomes = guard.read(C / "outcomes.json")
    assert outcomes["all_passed"] and outcomes["new_builds"] == 0
    assert len(outcomes["rows"]) == len(new_cases)
    for outcome, case in zip(outcomes["rows"], new_cases, strict=True):
        for key in ("case_id", "invocation_id", "status"):
            assert outcome[key] == case[key]
    return rows, prior


def scope():
    opening, seals, result_hash = trusted_inputs()
    # The inherited scope must continue resolving its retained E inputs. Only
    # the reused audit output directory changes to C.
    previous = p.D
    try:
        p.D = E
        value = ORIGINAL_SCOPE()
    finally:
        p.D = previous
    mutable = {name(E / "ledger.json"), name(E / "native-coverage.json"), *REPORTS}
    for path in mutable:
        value["frozen_package_inputs"].pop(path, None)
    value["frozen_package_inputs"].update(
        {path: digest for path, digest in seals.items() if path not in mutable}
    )
    value["frozen_package_inputs"].update(
        {
            name(E / "manifest.json"): PRIOR_SEAL,
            name(E / "validation-closure.json"): opening["prior_closure_sha256"],
            name(E / "result.json"): result_hash,
        }
    )
    value["append_only_documentation"].update(opening["report_prefixes"])
    current = guard.read(C / "new-inventory.json")
    value["frozen_package_inputs"].update(current["sha256"])
    value["required_names"] = sorted(
        set(value["required_names"]) | set(seals) | set(current["required_names"])
    )
    value["optional_names"] = sorted(set(value["optional_names"]) | set(current["optional_names"]))
    value["new_python_files"] = sorted(
        set(value["new_python_files"]) | {name(C / "checks.py"), name(C / "preflight.py")}
    )
    value["new_markdown_files"] = sorted(set(value["new_markdown_files"]) | set(REPORTS))
    roots = value["additional_name_inventory_roots"]
    assert roots.count("benchmarks/kyc_milestone_1") == 1 and "benchmarks" not in roots
    roots[roots.index("benchmarks/kyc_milestone_1")] = "benchmarks"
    return value


def prepare():
    rows, prior = live_records()
    retained = guard.read(C / "failed-preparation-1/retention.json")
    for path, expected in retained["sha256"].items():
        assert audit.digest_file(P / path) == expected, path
    assert not guard.read(C / "preparation.json")["passed"]
    assert audit.digest_file(C / "preparation.json") == audit.digest_file(
        C / "failed-preparation-1/preparation.json"
    ), "Only the preserved first failure may be replaced as working preparation"
    (C / "tmp").mkdir(exist_ok=True)
    assert not any((C / "tmp").iterdir())
    guard.write(C / "ledger.json", rows)
    guard.write(
        C / "invocation-snapshot.json",
        {
            "scope": "Post-case snapshot; live accounting remains in the shared E ledger",
            "source": name(E / "ledger.json"),
            "snapshot_sha256": audit.digest_file(C / "ledger.json"),
            "prior_invocations": len(prior["invocations"]),
            "completed_invocations": len(rows["invocations"]),
            "new_invocations": rows["invocations"][len(prior["invocations"]) :],
        },
    )
    required = {name(C / item) for item in INPUTS}
    required.update({name(C / "ledger.json"), name(C / "invocation-snapshot.json")})
    optional = {name(C / item) for item in OUTPUTS}
    optional.difference_update(required)
    for row in rows["invocations"][len(prior["invocations"]) :]:
        required.add(name(E / "cases" / (row["invocation_id"] + ".json")))
    for job in JOBS:
        paths = {name(E / "jobs" / (job + suffix)) for suffix in SUFFIXES}
        if job in FUTURE_JOBS:
            optional.update(paths)
        else:
            required.update(paths)
    # Freeze every completed new input/result, including the complete appended
    # coverage record. Never admit an unexpected pathname merely because it exists.
    frozen = {path: audit.digest_file(P / path) for path in sorted(required)}
    frozen[name(E / "native-coverage.json")] = audit.digest_file(E / "native-coverage.json")
    guard.write(
        C / "new-inventory.json",
        {
            "required_names": sorted(required),
            "optional_names": sorted(optional),
            "sha256": frozen,
            "scope": "Explicit continuation outputs and recorded case IDs only",
        },
    )
    value = scope()
    checked = p.inventory(value)
    result = {
        "passed": checked["passed"],
        "inventory": checked,
        "historical_baselines_regenerated": False,
        "scope_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
        "prior_manifest_sha256": PRIOR_SEAL,
    }
    guard.write(C / "preparation.json", result)
    assert result["passed"], checked


def current_checks(_):
    rows, _ = live_records()
    policy = guard.POLICY
    assert sum(row["name"] == "native-final-full-audit" for row in rows["jobs"]) == 1
    assert len(rows["invocations"]) <= 600 and len(rows["builds"]) <= 8
    snapshot = guard.read(C / "ledger.json")
    assert rows["invocations"] == snapshot["invocations"]
    assert rows["builds"] == snapshot["builds"]
    for ordinal, case in enumerate(rows["invocations"], 1):
        assert case["ordinal"] == ordinal and case["cumulative_invocations"] == 448 + ordinal
        assert case["status"] in {"pass", "failed", "incomplete"}
    for row in rows["jobs"]:
        assert row["phase"] in policy["phase_memory"]
        authorised = policy["phase_memory"][row["phase"]]
        assert row["memory_limit_bytes"] == authorised
        if row["status"] == "launched":
            assert row["name"] == "native-final-full-audit"
            continue
        assert row["stop"] is None, row["name"]
        assert row["seconds"] <= row["limit_seconds"] + 5
        measured = row["worker"]
        assert measured["before"]["memory.max"] == str(authorised)
        assert int(measured["after"]["memory.peak"]) <= authorised
        assert measured["before"]["memory.swap.max"] == "0"
        assert measured["resource_breach"] is False
    assert guard.consumed(rows) <= policy["implementation_ceiling_seconds"]
    assert guard.read(C / "preparation.json")["passed"]
    return guard.consumed(rows)


def full_audit():
    assert not (C / "validation.json").exists(), "Complete audit already attempted"
    p.D = C
    p.scope = scope
    p.current_checks = current_checks
    p.full_audit()


def readback():
    assert guard.read(C / "validation.json")["passed"]
    assert guard.read(E / "jobs/native-final-full-audit.json")["status"] == "pass"
    live_records()
    value = scope()
    expected = guard.read(C / "preparation.json")["scope_sha256"]
    assert hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() == expected
    checked = p.inventory(value)
    assert checked["passed"], checked
    guard.write(C / "final-inventory.json", checked)
    for path in (C / "ledger.json", E / "policy.json", C / "validation.json"):
        guard.read(path)
    for report in REPORTS:
        assert (P / report).read_text().count("```") % 2 == 0
    seals = guard.read(C / "manifest.json")["sha256"]
    assert set(REPORTS) <= set(seals), "Final full-file report seals missing"
    assert name(E / "ledger.json") not in seals, "Live readback job updates shared ledger"
    for path, expected_hash in seals.items():
        assert audit.digest_file(P / path) == expected_hash, path
    print(json.dumps({"final_inventory": checked, "readback": True}))


if __name__ == "__main__":
    {"prepare": prepare, "full-audit": full_audit, "readback": readback}[sys.argv[1]]()
