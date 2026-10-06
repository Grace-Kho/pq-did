"""Bounded write-once closure; no repeated protected content audit."""

# ruff: noqa: E402

import json
import os
import re
import resource
import signal
import sys
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
signal.alarm(5)
os.sched_setaffinity(0, set(sorted(os.sched_getaffinity(0))[:2]))
STARTED = time.monotonic()
D = Path(__file__).resolve().parent
P = D.parents[2]
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit


def read(name):
    return json.loads((D / name).read_text())


def main():
    assert not (D / "manifest.json").exists()
    assert not (D / "validation-closure.json").exists()
    config, scope = read("config.json"), read("scope.json")
    result, validation, runs = read("result.json"), read("validation.json"), read("run-ledger.json")
    assert result["passed"] and result["report_generation_completed"]
    assert result["resource_guard_passed"] and result["guard_exit_code"] == 0
    assert sum(row["name"] == "full-audit" for row in runs) == 1
    assert [row["name"] for row in runs if row["status"] != "pass"] == ["preflight"]
    assert read("manual-correction.json")["explicit_recheck"] == "preflight-corrected"
    wall = sum(row["seconds"] for row in runs)
    charged = config["prior_analysis_charged_seconds"] + config["operator_charge_seconds"] + wall
    remaining = config["aggregate_seconds"] - charged
    assert remaining > 0
    assert validation["total_test_invocations_including_prior_package"] == 386
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    temporary = max(row["temporary_storage_observed_peak"] for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
    report = P / "docs/stage3_aurora_auth_construction_contract.md"
    suffix = f"""

## Measured documentation and preservation closure

The construction review is complete. AURORA-BRIDGE-001 remains a prerequisite
for a private Aurora prototype: pinned transcript/query/mask and transformation
correspondence. No profile is adopted and no experiment is admitted.
Helper lint/format and documentation/static consistency checks pass. No test,
circuit generation, arithmetic probe, build, estimator or cryptographic execution ran.
The single [preservation audit](data/s3_aurora_auth_construction_contract_1/result.json)
completed content/inventory comparison, report readback and outer guard, exit 0.
Coverage: {validation["content_partition_union"]:,} disjoint content paths;
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths.
Original baselines and historical document prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | {result["wall_seconds"]:.9f} s |
| Audit cgroup-v2 memory.peak | {int(result["cgroup_memory_peak_bytes"]):,} bytes |
| Audit sampled process-tree RSS | {result["sampled_tree_RSS_peak_bytes"]:,} bytes |
| Maximum guarded-job cgroup peak | {peak:,} bytes |
| Maximum separately sampled tree RSS | {rss:,} bytes |
| Guarded commands | {len(runs)}, {wall:.9f} s |
| New analysis charge, including five bookkeeping seconds | {wall + 5:.9f} s |
| Cumulative analysis charge | {charged:.9f}/300 s |
| Analysis remaining | **{remaining:.9f} s** |
| Implementation unchanged | **41.823218338 s**, **386/386 tests** |
| Temporary disk observed peak | {temporary:,} bytes; zero retained |
| Evidence bytes at audit completion | {result["package_bytes_at_guard_completion"]:,} |

One diagnosed documentation-inventory preflight failure is retained and charged;
the explicit corrected preflight passed. No test/probe, audit retry or resource breach.
The unchanged 256 MiB cgroup guard
covers the worker and descendants, including charged file-cache/kernel memory;
swap is zero. Sampled RSS is a separate metric. Final bounded bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file inside the
five-second charge; it does not repeat content comparisons.
The [closure](data/s3_aurora_auth_construction_contract_1/validation-closure.json)
and [additive seal](data/s3_aurora_auth_construction_contract_1/manifest.json)
record the exact balances. Isolation remains safely stopped/unactivated with
250.22 s and 22 original cases pending. Stages 2–3 remain open; proof ledger
**two attempts used, one unused**, CPU proving paused.
"""
    with report.open("a") as stream:
        stream.write(suffix)
    short = f"""

Aurora construction-contract closure: documentation/static checks and the
[single preservation audit](data/s3_aurora_auth_construction_contract_1/result.json)
pass, {validation["content_partition_union"]:,} disjoint content paths,
{result["wall_seconds"]:.9f} s, {int(result["cgroup_memory_peak_bytes"]):,}-byte
cgroup peak under the unchanged 256 MiB ceiling. Analysis charge
{charged:.9f}/300 s; **{remaining:.9f} s remain**. Implementation unchanged
**41.823218338 s; 386/386 tests**. One diagnosed preflight inventory-path failure
and its charged manual correction are preserved; no experimental retry or resource
breach. **AURORA-BRIDGE-001 open**: resolve the pinned oracle/query/mask manifest
and transformation correspondence before a private prototype. Proposed next package
S3-AURORA-TRANSCRIPT-BRIDGE-1 only; no experiment or profile adopted.
Stages 2–3 remain open; raw-view integration and CPU proving paused, isolation
safely stopped/unactivated, proof ledger two used/one unused.
"""
    for name, prefix in scope["append_only_documentation"].items():
        with (P / name).open("a") as stream:
            stream.write(short)
        assert audit.digest_file(P / name, prefix_bytes=prefix["bytes"]) == prefix["sha256"]
    links = 0
    for name in [*scope["append_only_documentation"], *scope["new_markdown_files"]]:
        path = P / name
        content = path.read_text()
        assert content.count("```") % 2 == 0
        assert all(line.rstrip() == line for line in content.splitlines())
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", content):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            dest = (path.parent / unquote(parsed.path)).resolve()
            assert dest.exists() or str(dest.relative_to(P)) in scope["optional_names"]
            links += 1
    inventory = audit.inventory_check(
        P,
        scope["additional_name_inventory_roots"],
        set(scope["required_names"]),
        optional_names=set(scope["optional_names"]),
    )
    assert inventory["passed"] and not any((D / "tmp").iterdir())
    closure = {
        "package": config["package"],
        "status": "complete-construction-review-aurora-bridge-required",
        "full_audit_passed": True,
        "result_sha256": audit.digest_file(D / "result.json"),
        "scope_sha256": audit.digest_file(D / "scope.json"),
        "run_ledger_sha256": audit.digest_file(D / "run-ledger.json"),
        "previous_manifest_sha256": read("preflight-evidence.json")["previous_manifest_sha256"],
        "guarded_commands": len(runs),
        "guarded_wall_seconds": wall,
        "prior_analysis_charged_seconds": config["prior_analysis_charged_seconds"],
        "new_package_charged_seconds": config["operator_charge_seconds"] + wall,
        "prior_test_invocations": config["prior_test_invocations"],
        "prior_output_bytes": config["prior_output_bytes"],
        "operator_and_bookkeeping_charge_seconds": config["operator_charge_seconds"],
        "analysis_aggregate_charged_seconds": charged,
        "analysis_aggregate_remaining_seconds": remaining,
        "implementation_aggregate_charged_seconds_unchanged": 332.1767816620413,
        "implementation_aggregate_remaining_seconds_unchanged": 41.82321833795868,
        "max_cgroup_memory_peak_bytes": peak,
        "max_sampled_tree_RSS_bytes": rss,
        "full_audit_cgroup_peak_bytes": int(result["cgroup_memory_peak_bytes"]),
        "full_audit_wall_seconds": result["wall_seconds"],
        "temporary_storage_observed_peak_bytes": temporary,
        "final_temporary_bytes": 0,
        "test_invocations": config["test_invocations"],
        "total_test_invocations": 386,
        "unique_new_tests": 0,
        "generation_probe_invocations": 0,
        "remaining_test_invocations": 0,
        "functional_test_failures": 0,
        "retained_lint_failures": 0,
        "prelaunch_admission_diagnostics": 0,
        "retained_documentation_preflight_failures": 1,
        "manual_documentation_corrections": 1,
        "resource_breaches": 0,
        "native_ABI_runs": 0,
        "targeted_repeated_invocations": 0,
        "full_audit_attempts": 1,
        "final_local_links_checked": links,
        "final_name_inventory_count": inventory["count"] + 2,
        "bookkeeping_elapsed_before_write_seconds": time.monotonic() - STARTED,
        "bookkeeping_limits": "256MiB address space, CPU/alarm5s, two CPUs, file1MiB; "
        "included five seconds",
        "proofs": 0,
        "zkvm_executions": 0,
        "activation": False,
        "dependencies_installed": False,
        "circuit_generation": 0,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
        "CPU_proving_paused": True,
        "isolation_state": "safe-stopped-unactivated",
        "isolation_tests_unchanged": 100,
        "isolation_identity_cases_pending": 22,
        "isolation_remaining_seconds_unchanged": 250.22,
        "open_obligations": [
            "DEP-001",
            "DEP-002 production/release",
            "Delta_tail",
            "side-channel/erasure/storage/entropy",
            "SEC-001..005",
            "OC-REL/EXT/PRIV/BUDGET",
            "complete private-proof knowledge/privacy",
        ],
        "next_recommendation": "S3-AURORA-TRANSCRIPT-BRIDGE-1; not started",
        "next_package_started": False,
    }
    audit.write_report(D / "validation-closure.json", closure)
    files = {path for path in D.rglob("*") if path.is_file()}
    files.update([report, *[P / name for name in scope["append_only_documentation"]]])
    files.update(P / name for name in scope["frozen_package_inputs"])
    manifest = {
        "package": config["package"],
        "kind": "Additive Aurora construction-contract seal; no baseline regeneration",
        "previous_manifest_sha256": closure["previous_manifest_sha256"],
        "scope_sha256": closure["scope_sha256"],
        "self_excluded": "manifest.json",
        "sha256": {str(path.relative_to(P)): audit.digest_file(path) for path in sorted(files)},
    }
    audit.write_report(D / "manifest.json", manifest)
    final = audit.inventory_check(
        P,
        scope["additional_name_inventory_roots"],
        set(scope["required_names"]),
        optional_names=set(scope["optional_names"]),
    )
    assert final["passed"] and final["count"] == closure["final_name_inventory_count"]
    assert read("validation-closure.json") == closure and read("manifest.json") == manifest
    assert all(path.stat().st_size <= config["per_file_bytes"] for path in files)
    total = sum(path.stat().st_size for path in D.rglob("*") if path.is_file())
    assert config["prior_output_bytes"] + total < config["output_bytes"]
    print(
        json.dumps(
            {
                "closure": "complete",
                "manifest_sha256": audit.digest_file(D / "manifest.json"),
                "sealed_files": len(files),
                "package_bytes": total,
                "cumulative_package_bytes": config["prior_output_bytes"] + total,
                "analysis_charged_seconds": charged,
                "analysis_remaining_seconds": remaining,
                "elapsed_bookkeeping_seconds": time.monotonic() - STARTED,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
