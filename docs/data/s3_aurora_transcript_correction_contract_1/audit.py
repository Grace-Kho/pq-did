"""One complete correction-contract audit; no regression harness execution."""

# ruff: noqa: E402

import ast
import importlib.util
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

D = Path(__file__).resolve().parent
P = D.parents[2]
E = P / "docs/data/s2_authority_isolation_pilot_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit

spec = importlib.util.spec_from_file_location("historical_audit_helpers", E / "audit.py")
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
prior.D = D
require, small = prior.require, prior.small_json


def documentation(scope):
    links = 0
    for name in [*scope["append_only_documentation"], *scope["new_markdown_files"]]:
        path = P / name
        text = path.read_text()
        require(text.count("```") % 2 == 0, "unbalanced Markdown fence: " + name)
        require(all(line.rstrip() == line for line in text.splitlines()), "trailing whitespace")
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", text):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            dest = (path.parent / unquote(parsed.path)).resolve()
            require(
                dest.exists() or str(dest.relative_to(P)) in scope["optional_names"],
                "broken link: " + target,
            )
            links += 1
    return links


def main(measure):
    scope, config = small(D / "scope.json"), small(D / "config.json")
    old_config = small(E / "config.json")
    for key in (
        "memory_bytes",
        "swap_bytes",
        "workers",
        "cpu_threads",
        "command_seconds",
        "child_seconds",
        "aggregate_seconds",
        "controlled_children",
        "output_bytes",
        "temporary_bytes",
        "per_file_bytes",
        "per_command_log_bytes",
        "disk_bytes",
        "disk_stop_bytes",
        "diagnostic_bytes",
        "diagnostic_stop_bytes",
        "headroom_reserve_bytes",
    ):
        require(config[key] == old_config[key], "changed ceiling: " + key)
    require(config["full_audit_attempts"] == 1, "one audit limit")
    measure.phase("start")
    for name, expected in scope["baseline_identities"].items():
        require(
            audit.digest_file(P / name, progress=measure.progress) == expected,
            "historical baseline identity changed: " + name,
        )
    measure.phase("original-and-supplemental-baseline-identities-complete")
    primary = audit.compare(
        P,
        audit.iter_manifest(P / "docs/data/s2_revoke_state_1/preservation-before.json"),
        expected_count=8759,
        permitted=set(scope["original_permitted_documentation"]),
        progress=measure.progress,
    )
    require(primary.passed, "primary comparison: " + json.dumps(primary.report()))
    measure.phase("original-8759-content-complete")
    latest = {}
    for name, count in scope["supplementary_manifests"].items():
        rows = small(P / name)["sha256"]
        require(len(rows) == count, "supplement manifest count")
        latest.update(rows)
    supplement = audit.compare(
        P,
        ((name, value) for name, value in latest.items() if name not in primary.names),
        expected_count=scope["supplementary_count"],
        permitted=set(scope["supplementary_allowed_docs"]),
        progress=measure.progress,
    )
    require(supplement.passed, "supplement comparison: " + json.dumps(supplement.report()))
    require(not primary.names & supplement.names, "overlapping content partitions")
    known = primary.names | supplement.names | set(scope["baseline_identities"])
    require(len(known) == scope["known_manifest_union_names"], "missing coverage")
    for name, prefix in scope["append_only_documentation"].items():
        require(
            audit.digest_file(P / name, prefix_bytes=prefix["bytes"]) == prefix["sha256"],
            "historical report prefix altered: " + name,
        )
    measure.phase("supplemental-content-and-complete-report-prefixes-verified")
    source = small(P / "docs/data/s2_concrete_security_assessment_1/source-revision.json")
    for name, expected in {**source["sha256"], **scope["frozen_package_inputs"]}.items():
        require(audit.digest_file(P / name) == expected, "assessed input changed: " + name)
    seal_path = P / "docs/proposals/s2_authority_isolation_pilot_1/v2/source-manifest.json"
    seal = small(seal_path)
    require(
        audit.digest_file(seal_path)
        == "994327b3b0d32d22b6ce9aa09a5125ec798d509ebbdcfa79819bf2225f1a6c32",
        "approved isolation seal",
    )
    for name, expected in {**seal["sha256"], **seal["control_inputs_sha256"]}.items():
        require(audit.digest_file(P / name) == expected, "sealed pilot input changed: " + name)
    fixtures = E / "activation-inputs"
    require(
        {path.name for path in fixtures.iterdir()} == set(seal["synthetic_inputs_sha256"]),
        "sealed synthetic input inventory",
    )
    for name, expected in seal["synthetic_inputs_sha256"].items():
        require(audit.digest_file(fixtures / name) == expected, "sealed fixture: " + name)
    proof = small(P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json")
    require(proof["attempts_used"] == 2 and proof["remaining"] == 1, "proof ledger count")
    require(small(E / "correction-v2/result.json")["passed"], "previous audit result")
    require(
        small(P / "docs/data/s2_concrete_security_assessment_1/host-closure.json")[
            "workload_terminated"
        ],
        "host prerequisite",
    )
    session = small(E / "activation-v2-session/session.json")
    require(session["remaining_after_supplemental_charge_seconds"] == 250.22, "isolation budget")
    require(session["historical_test_invocations"] == 100, "isolation test ledger")
    measure.phase("assessed-source-sealed-pilot-inputs-and-ledgers-complete")
    runs = small(D / "run-ledger.json")
    require(sum(row["name"] == "full-audit" for row in runs) == 1, "one audit admission")
    prior.check_runs(
        D,
        {
            "preflight",
            "source-format",
            "imports",
            "quality",
            "format",
            "prepare",
        },
    )
    require(all(row["status"] in {"pass", "launched"} for row in runs), "failed job")
    previous = small(P / "docs/data/s3_aurora_transcript_bridge_1/validation-closure.json")
    require(previous["total_test_invocations"] == 386, "previous tests")
    require(
        config["prior_test_invocations"] == config["synthetic_case_limit"] == 386,
        "test allowance unchanged",
    )
    require(config["test_invocations"] == {}, "no test/probe commands")
    require(
        previous["implementation_aggregate_charged_seconds_unchanged"]
        == config["prior_implementation_charged_seconds"],
        "implementation untouched",
    )
    require(
        previous["analysis_aggregate_remaining_seconds"]
        == 300 - config["prior_analysis_charged_seconds"],
        "analysis ledger continued",
    )
    package_charge = config["operator_charge_seconds"] + sum(
        row.get("seconds", row["limit_seconds"]) for row in runs
    )
    charged = config["prior_analysis_charged_seconds"] + package_charge
    require(
        charged + config["cleanup_and_evidence_reserve_seconds"] <= 300,
        "analysis allowance and reserve",
    )
    contract = small(D / "contract.json")
    require(contract["existing_source_changed"] == [], "existing sources frozen")
    require(contract["new_test_invocations"] == 0, "no invocations")
    require(contract["new_circuit_generations"] == 0, "no circuits")
    proposal = small(D / "proposal.json")
    require(proposal["authorised"] is False, "future proposal must remain inactive")
    require(proposal["profile_adopted"] is False, "no profile adoption")
    correction = small(D / "correction.json")
    require(correction["implemented"] is False, "contract only")
    require(correction["issue_closed"] is False, "bridge remains open")
    require(correction["transcript_version"] == 2, "distinct experimental version")
    cases = small(D / "regressions.json")["cases"]
    require(len(cases) == len({case["id"] for case in cases}) == 16, "future case inventory")
    require(all(case["executed"] is False for case in cases), "no regressions executed")
    require(proposal["new_counted_invocations"] == 16, "inactive request")
    require(proposal["proposed_cumulative_ceiling"] == 402, "future cumulative count")
    require(proposal["new_implementation_seconds_added"] == 0, "no time reset")
    for name, expected in small(D / "reviewed-inputs.json")["sha256"].items():
        require(audit.digest_file(P / name) == expected, "reviewed input changed: " + name)
    report_text = (P / "docs/stage3_aurora_transcript_correction_contract.md").read_text()
    for marker in contract["required_report_markers"]:
        require(marker in report_text, "missing review section: " + marker)
    for name in scope["new_python_files"]:
        ast.parse((P / name).read_text(), filename=name)
    for path in [*D.glob("*.json"), P / "analysis/concrete_security/security_profile.json"]:
        small(path)
    links = documentation(scope)
    inventory = audit.inventory_check(
        P,
        scope["additional_name_inventory_roots"],
        set(scope["required_names"]),
        optional_names=set(scope["optional_names"]),
    )
    require(inventory["passed"], "inventory: " + json.dumps(inventory))
    require(not any((D / "tmp").iterdir()), "temporary files remain")
    package_bytes = sum(path.stat().st_size for path in D.rglob("*") if path.is_file())
    require(
        config["prior_output_bytes"] + package_bytes < config["output_bytes"],
        "continued output ceiling",
    )
    require(
        all(
            path.stat().st_size <= config["per_file_bytes"]
            for path in D.rglob("*")
            if path.is_file()
        ),
        "new evidence per-file ceiling",
    )
    measure.phase("validation-budget-inventory-documentation-and-storage-complete")
    report = {
        "package": config["package"],
        "passed": True,
        "comparison_complete": True,
        "resource_guard_status": "pending-outer-finalisation",
        **primary.report(),
        "supplementary_comparison": supplement.report(),
        "content_partition_union": len(primary.names | supplement.names),
        "content_partition_overlap": 0,
        "identity_inclusive_unique_paths": len(known),
        "name_inventory": inventory,
        "only_existing_changes": list(scope["append_only_documentation"]),
        "existing_report_prefixes_preserved": True,
        "baseline_regenerated": False,
        "test_invocations": {},
        "unique_new_tests": 0,
        "total_test_invocations_including_prior_package": 386,
        "new_execution_calculations": 0,
        "source_review": "Pinned evidence reused; pseudocode and 16 inactive regression cases",
        "scoped_existing_verifier_regressions": 0,
        "implementation_allowance_remaining_unchanged": 41.82321833795868,
        "isolation_allowance_remaining_unchanged": 250.22,
        "local_links_checked": links,
        "package_bytes_before_report": package_bytes,
        "temporary_storage_bytes": 0,
        "charged_seconds_including_inflight_audit_reservation": charged,
        "proofs": 0,
        "zkvm_executions": 0,
        "estimator_runs": 0,
        "activation": False,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
    }
    audit.write_report(D / "validation.json", report)
    require(small(D / "validation.json") == report, "report readback")
    measure.phase("report-written-and-readback-complete")
    print(
        json.dumps(
            {
                "content_passed": True,
                "outer_guard_pending": True,
                "historical_paths": len(known),
                "inventory": inventory,
            }
        )
    )


if __name__ == "__main__":
    measure = prior.Measurements()
    try:
        main(measure)
    except Exception as error:
        measure.phase("incomplete-audit-failure")
        if not (D / "validation.json").exists():
            audit.write_report(
                D / "validation.json",
                {
                    "passed": False,
                    "comparison_complete": False,
                    "failure_type": type(error).__name__,
                    "failure": str(error)[:3000],
                },
            )
        raise
