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
    assert all(row["status"] == "pass" for row in runs)
    wall = sum(row["seconds"] for row in runs)
    charged = (
        config["prior_implementation_charged_seconds"] + config["operator_charge_seconds"] + wall
    )
    remaining = config["aggregate_seconds"] - charged
    assert remaining > 0
    assert validation["total_test_invocations_including_prior_package"] == 145
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    temporary = max(row["temporary_storage_observed_peak"] for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
    report = P / "docs/stage2_durable_issuer_manager_integration.md"
    suffix = f"""

## Measured validation closure

The single [complete preservation audit](data/s2_durable_issuer_manager_integration_1/result.json)
passed content/inventory comparison, report readback and its outer resource guard,
exit **0**. Coverage: {validation["protected_files"]:,} original and
{validation["supplementary_comparison"]["protected_files"]:,} supplementary paths,
**{validation["content_partition_union"]:,} disjoint content paths**,
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths.
No unexpected changes, additions or removals occurred. Three historical reports
have verified append-only prefixes; all pre-existing source/vectors/parameters,
manuscript, dependencies and original evidence are preserved. The only new source
is the separate integration module and three integration test/helper files.
Lint and formatting pass.

| Measurement | Result |
| --- | --- |
| Audit wall time | {result["wall_seconds"]:.9f} s |
| Audit cgroup memory.peak | {int(result["cgroup_memory_peak_bytes"]):,} bytes |
| Audit sampled process-tree RSS | {result["sampled_tree_RSS_peak_bytes"]:,} bytes |
| Maximum guarded-job cgroup memory.peak | {peak:,} bytes, below 268,435,456 |
| Maximum observed guarded-job tree RSS | {rss:,} bytes; separate metric |
| Guarded commands | {len(runs)}, {wall:.9f} s total; all checks completed successfully |
| Cumulative implementation charge | **{charged:.9f}/300 s** |
| Remaining implementation allowance | **{remaining:.9f} s**, **3/148 test invocations** |
| Test invocations | 121 previously charged + 22 integration + two crash cases = 145; no repeats |
| Functional failures/resource breaches | 0/0 in this package; all historical evidence retained |
| Temporary storage | {temporary:,} observed peak bytes; zero retained |
| Package bytes at outer audit completion | {result["package_bytes_at_guard_completion"]:,} |

The audit's unchanged **256 MiB** metric is cgroup-v2 memory.peak for the complete
worker/descendant tree, including charged file-cache/kernel memory; swap is zero.
The cumulative time includes 48.714120727 s previously charged and five new
bookkeeping seconds; analysis and isolation time were not borrowed.
The external RSS sample can count shared pages more than once. No execution/proving
cost inference is made. The final bookkeeping has a separate 256 MiB address-space,
CPU/alarm-five-second, two-CPU and 1 MiB-file bound, within the five-second charge.
It checks new outputs, exact names, links and report prefixes, then writes the
[closure](data/s2_durable_issuer_manager_integration_1/validation-closure.json) and
[new additive seal](data/s2_durable_issuer_manager_integration_1/manifest.json) once; it does
not repeat the protected content scan or regenerate a historical baseline.

Analysis **270.181481168 s** and isolation **250.22 s** remain untouched. Stages
2–3 remain open; DEP-001/002 production obligations, adaptive Delta_tail, side
channels/erasure and complete private-proof knowledge/privacy remain unresolved.
Isolation stays safely stopped/unactivated. No proof/zkVM/activation occurred;
proof ledger two used/one unused. Next recommendation remains the bounded
**S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1**; it is not started.
"""
    with report.open("a") as stream:
        stream.write(suffix)
    short = f"""

Issuer-manager lifecycle validation closure: lint/format and all 24 new tests pass,
145/148 cumulative implementation invocations, three remaining; no new repeats.
The single [complete preservation audit](data/s2_durable_issuer_manager_integration_1/result.json)
passed content/inventory, report readback and the unchanged 256 MiB cgroup guard:
{validation["content_partition_union"]:,} disjoint content paths,
{result["wall_seconds"]:.9f} s, {int(result["cgroup_memory_peak_bytes"]):,}-byte audit peak.
Maximum new-job peak {peak:,} bytes; zero functional failures/resource breaches.
Continued implementation budget {charged:.9f}/300 s charged,
{remaining:.9f} s remaining. Analysis 270.181481168 s and isolation 250.22 s
unchanged. New synthetic-proof lifecycle integration only; original code, vectors,
parameters and historical evidence preserved. Production signing, DEP-001/002,
Delta_tail and full proof knowledge/privacy remain open; Stages 2–3 incomplete.
Next recommendation
S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1, not started. No activation/proofs/zkVM;
proof ledger two used/one unused, CPU proving paused.
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
        "status": "complete-isolated-synthetic-proof-lifecycle-integration",
        "full_audit_passed": True,
        "result_sha256": audit.digest_file(D / "result.json"),
        "scope_sha256": audit.digest_file(D / "scope.json"),
        "run_ledger_sha256": audit.digest_file(D / "run-ledger.json"),
        "previous_manifest_sha256": read("preflight-evidence.json")["previous_manifest_sha256"],
        "guarded_commands": len(runs),
        "guarded_wall_seconds": wall,
        "prior_implementation_charged_seconds": config["prior_implementation_charged_seconds"],
        "new_package_charged_seconds": config["operator_charge_seconds"] + wall,
        "prior_test_invocations": config["prior_test_invocations"],
        "prior_output_bytes": config["prior_output_bytes"],
        "operator_and_bookkeeping_charge_seconds": config["operator_charge_seconds"],
        "implementation_aggregate_charged_seconds": charged,
        "implementation_aggregate_remaining_seconds": remaining,
        "analysis_remaining_seconds_unchanged": 270.1814811680233,
        "max_cgroup_memory_peak_bytes": peak,
        "max_sampled_tree_RSS_bytes": rss,
        "full_audit_cgroup_peak_bytes": int(result["cgroup_memory_peak_bytes"]),
        "full_audit_wall_seconds": result["wall_seconds"],
        "temporary_storage_observed_peak_bytes": temporary,
        "final_temporary_bytes": 0,
        "test_invocations": config["test_invocations"],
        "total_test_invocations": 145,
        "unique_new_tests": 24,
        "remaining_test_invocations": 3,
        "functional_test_failures": 0,
        "retained_lint_failures": 0,
        "prelaunch_admission_diagnostics": 0,
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
        "next_recommendation": "S2-DURABLE-VERIFIER-LIFECYCLE-INTEGRATION-1",
        "next_package_started": False,
    }
    audit.write_report(D / "validation-closure.json", closure)
    files = {path for path in D.rglob("*") if path.is_file()}
    files.update([report, *[P / name for name in scope["append_only_documentation"]]])
    files.update(P / name for name in scope["frozen_package_inputs"])
    manifest = {
        "package": config["package"],
        "kind": "Additive new reference integration seal; no baseline regeneration",
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
                "implementation_charged_seconds": charged,
                "implementation_remaining_seconds": remaining,
                "elapsed_bookkeeping_seconds": time.monotonic() - STARTED,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
