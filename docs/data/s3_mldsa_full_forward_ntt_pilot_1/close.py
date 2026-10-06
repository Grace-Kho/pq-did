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
    assert all(
        row["status"] == "pass" or (row["name"].startswith("batch-") and row["status"] == "failed")
        for row in runs
    )
    pilot = read("pilot-summary.json")
    wall = sum(row["seconds"] for row in runs)
    charged = (
        config["prior_implementation_charged_seconds"] + config["operator_charge_seconds"] + wall
    )
    remaining = config["aggregate_seconds"] - charged
    assert remaining > 0 and config["operator_charge_seconds"] + wall <= 135
    assert (
        validation["total_test_invocations_including_prior_package"] == pilot["total_invocations"]
    )
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    temporary = max(row["temporary_storage_observed_peak"] for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert row["name"].startswith("batch-") or all(
            int(events[key]) == 0 for key in ["max", "oom", "oom_kill"]
        )
    report = P / "docs/stage3_mldsa_full_forward_ntt_pilot.md"
    suffix = f"""

## Preservation and final resource closure

Lint/format and the single complete preservation audit pass, exit0, including
content, inventory, report readback and outer guard. Coverage:
{validation["content_partition_union"]:,} disjoint content paths and
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths.
Original baselines and report prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | {result["wall_seconds"]:.9f} s |
| Audit cgroup memory.peak | {int(result["cgroup_memory_peak_bytes"]):,} bytes /256MiB |
| Audit sampled tree RSS | {result["sampled_tree_RSS_peak_bytes"]:,} bytes |
| Maximum guarded cgroup peak | {peak:,} bytes |
| Maximum separately sampled tree RSS | {rss:,} bytes |
| Guarded commands and wall time | {len(runs)}; {wall:.9f} s |
| Package charge, including five bookkeeping seconds | {wall + 5:.9f}/135 s |
| Cumulative implementation charge | {charged:.9f}/374 s |
| Remaining implementation allowance | **{remaining:.9f} s** |
| Invocation count | **{pilot["total_invocations"]}/386** |
| Analysis balance unchanged | **245.423783159 s** |
| Temporary disk observed peak | {temporary:,} bytes; zero temporary files retained |

The cgroup-v2 metric covers worker descendants and charged cache/kernel memory;
swap is zero. Sampled RSS is a separate observation. Synthetic checkpoints and
failure diagnostics are retained as explicitly named evidence, not live resources.
Final bookkeeping uses256MiB address space, CPU/alarm5s, two CPUs and1MiB/file
within the five-second charge; it does not repeat content comparisons.
[Guard result](data/s3_mldsa_full_forward_ntt_pilot_1/result.json),
[closure](data/s3_mldsa_full_forward_ntt_pilot_1/validation-closure.json) and
[additive seal](data/s3_mldsa_full_forward_ntt_pilot_1/manifest.json) record completion.
Analysis/isolation were not borrowed; isolation remains safe-stopped/unactivated,
250.22s and22 identity cases pending. Stages2–3 open; CPU paused; proof ledger2/1.
"""
    with report.open("a") as stream:
        stream.write(suffix)
    short = f"""

Full-forward pilot preservation closure: audit and report guard pass,
{validation["content_partition_union"]:,} protected content paths,
{result["wall_seconds"]:.9f}s and{int(result["cgroup_memory_peak_bytes"]):,}-byte
cgroup peak under256MiB. Package{wall + 5:.9f}/135s;
implementation{charged:.9f}/374s, **{remaining:.9f}s remain**;
invocations**{pilot["total_invocations"]}/386**. Analysis245.423783159s/isolation250.22s
unchanged. Outcome: {pilot["decision"]}. No further package started.
See [complete report](stage3_mldsa_full_forward_ntt_pilot.md).
Stages2–3/security obligations remain open; proof ledger2used/1unused.
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
        "status": "complete-isolated-full-forward" if pilot["passed"] else "stopped-incomplete",
        "pilot_passed": pilot["passed"],
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
        "analysis_aggregate_charged_seconds_unchanged": 54.57621684111655,
        "analysis_remaining_seconds_unchanged": 245.42378315888345,
        "max_cgroup_memory_peak_bytes": peak,
        "max_sampled_tree_RSS_bytes": rss,
        "full_audit_cgroup_peak_bytes": int(result["cgroup_memory_peak_bytes"]),
        "full_audit_wall_seconds": result["wall_seconds"],
        "temporary_storage_observed_peak_bytes": temporary,
        "final_temporary_bytes": 0,
        "test_invocations_reserved_by_batch": config["test_invocations"],
        "total_test_invocations": pilot["total_invocations"],
        "new_invocations": pilot["new_invocations"],
        "complete_generation_partitions": pilot["completed_partitions"],
        "remaining_test_invocations": 386 - pilot["total_invocations"],
        "failure_details": pilot["failure"],
        "retained_lint_failures": 0,
        "prelaunch_admission_diagnostics": 0,
        "failed_work_guards": sum(r["status"] == "failed" for r in runs),
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
        "aggregate_gates_charged": pilot["aggregate_emitted_gates_or_charged_bound"]
        + pilot["unresolved_prefix_reserved_gates"],
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
        "next_recommendation": pilot["next_recommendation"],
        "next_package_started": False,
    }
    audit.write_report(D / "validation-closure.json", closure)
    files = {path for path in D.rglob("*") if path.is_file()}
    files.update([report, *[P / name for name in scope["append_only_documentation"]]])
    files.update(P / name for name in scope["frozen_package_inputs"])
    manifest = {
        "package": config["package"],
        "kind": "Additive isolated full-forward pilot seal; no baseline regeneration",
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
