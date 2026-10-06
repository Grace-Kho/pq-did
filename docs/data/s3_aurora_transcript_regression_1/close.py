"""Write-once measured closure within the reserved five bookkeeping seconds."""

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
E = P / "experiments/aurora_transcript_regression_1"
REPORT = P / "docs/stage3_aurora_transcript_regression.md"
sys.path.insert(0, str(P))
sys.path.insert(0, str(D))
from scope_loader import load_scope

from scripts import preservation_audit as audit


def read(name):
    return json.loads((D / name).read_text())


def main():
    assert not (D / "manifest.json").exists() and not (D / "validation-closure.json").exists()
    config, scope = read("config.json"), load_scope()
    result, validation = read("result.json"), read("validation.json")
    runs, cases = read("run-ledger.json"), read("case-ledger.json")
    assert result["passed"] and result["report_generation_completed"]
    assert result["resource_guard_passed"] and result["guard_exit_code"] == 0
    assert len(cases) == 16 and all(row["status"] == "pass" for row in cases)
    assert len(runs) == 5 and all(row["status"] == "pass" for row in runs)
    assert sum(row["name"] == "full-audit" for row in runs) == 1
    wall = sum(row["seconds"] for row in runs)
    charge = config["operator_charge_seconds"] + wall
    total = config["prior_implementation_charged_seconds"] + charge
    remaining = 374 - total
    assert charge + 10 <= 25 and remaining >= 0
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    assert all(row["temporary_storage_observed_peak"] == 0 for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[k]) == 0 for k in ("max", "oom", "oom_kill"))
    suffix = f"""

## Measured completion and preservation

All sixteen individually admitted cases passed. TR-02 is the authorised counted
repeat; no automatic retry or extra probe ran. These are **isolated Python
reimplementation** results, not native upstream patch validation. The corrected
behaviour is implemented/tested only at that layer. No Aurora proof was produced.

The single [preservation audit](data/s3_aurora_transcript_regression_1/result.json)
completed comparisons, inventory, report readback and the outer guard, exit 0:
**{validation["content_partition_union"]:,} disjoint content paths**, with
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths.
Original baselines, pinned upstream inputs and historical report prefixes remain
unchanged. Inventory names inherited by reference are expanded and checked in full;
the delta removes no coverage. No source or scope was changed after execution.

| Measurement | Result |
| --- | --- |
| Guarded commands, including preflight and audit | {len(runs)}; {wall:.9f} s |
| Implementation charge, including five bookkeeping seconds | {charge:.9f} s |
| Cumulative implementation charge | {total:.9f}/374 s |
| Remaining implementation allowance | **{remaining:.9f} s** |
| Package cap / protected reserve | 25 s / 10 s; preserved |
| Cumulative invocations | **402/402**, sixteen new admitted cases |
| Analysis unchanged | **211.513455542 s** remaining |
| Isolation unchanged | 250.22 s, 22 identity cases pending |
| Audit wall time | {result["wall_seconds"]:.9f} s |
| Audit cgroup-v2 memory.peak | {int(result["cgroup_memory_peak_bytes"]):,} bytes |
| Audit sampled process-tree RSS | {result["sampled_tree_RSS_peak_bytes"]:,} bytes |
| Maximum guarded-job cgroup peak / sampled RSS | {peak:,} / {rss:,} bytes |
| Temporary storage observed / retained | 0 / 0 bytes |

The unchanged 256 MiB cgroup scope covers each worker and descendants, including
charged file-cache/kernel memory, with zero swap. RSS is separately sampled.
The external monitor is outside that cgroup, as in the preserved workflow.
Closure bookkeeping has a 256 MiB address-space ceiling, five-second CPU/alarm,
two CPUs and 1 MiB/file; its charge is included above. All guard records retain
commands, effective limits, headroom, statuses and measurements. No new failures
or resource breaches occurred. The final additive seal and ledger are
[here](data/s3_aurora_transcript_regression_1/validation-closure.json).

AURORA-BRIDGE-001 and Stages 2–3 remain open. Raw-view integration and CPU proving
remain paused; isolation safely stopped/unactivated. Proof ledger: **two attempts
used, one unused**. Next action is the bounded source-only round-plan/IOP adapter
contract specified above; it has not started and admits no private prototype.
"""
    with REPORT.open("a") as stream:
        stream.write(suffix)
    short = f"""

EXP2 regression closure: all **16/16** public synthetic cases passed in the isolated
Python reimplementation; no native patch or proof-system validation is claimed.
The [single preservation audit](data/s3_aurora_transcript_regression_1/result.json)
passed {validation["content_partition_union"]:,} content paths in
{result["wall_seconds"]:.9f} s, cgroup peak {int(result["cgroup_memory_peak_bytes"]):,}
bytes under 256 MiB. Package charge **{charge:.9f} s**, cumulative implementation
**{total:.9f}/374 s**, **{remaining:.9f} s remain**. Invocations **402/402**;
analysis211.513455542 s and isolation250.22 s unchanged. AURORA-BRIDGE-001 open;
Stages 2–3 open, proof ledger two used/one unused. Next: bounded source-only
S3-AURORA-ROUND-PLAN-ADAPTER-CONTRACT-1; not started. No private prototype admitted.
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
        "status": "complete-isolated-reimplementation-regressions",
        "implementation_layer": "source-faithful Python reimplementation of EXP2 contract",
        "native_upstream_patch_executed": False,
        "private_prototype_admitted": False,
        "bridge_issue": "AURORA-BRIDGE-001",
        "bridge_closed": False,
        "full_audit_passed": True,
        "full_audit_attempts": 1,
        "result_sha256": audit.digest_file(D / "result.json"),
        "scope_sha256": audit.digest_file(D / "scope.json"),
        "run_ledger_sha256": audit.digest_file(D / "run-ledger.json"),
        "previous_manifest_sha256": read("preflight-evidence.json")["previous_manifest_sha256"],
        "prior_output_bytes": config["prior_output_bytes"],
        "new_package_charged_seconds": charge,
        "guarded_wall_seconds": wall,
        "operator_and_bookkeeping_charge_seconds": 5,
        "implementation_aggregate_charged_seconds": total,
        "implementation_aggregate_remaining_seconds": remaining,
        "analysis_aggregate_charged_seconds_unchanged": 88.48654445819557,
        "analysis_aggregate_remaining_seconds_unchanged": 211.51345554180443,
        "prior_test_invocations": 386,
        "new_counted_invocations": 16,
        "total_test_invocations": 402,
        "remaining_test_invocations": 0,
        "explicit_authorised_repeat": "TR-02",
        "automatic_retries": 0,
        "failed_cases": 0,
        "new_resource_breaches": 0,
        "max_cgroup_memory_peak_bytes": peak,
        "max_sampled_tree_RSS_bytes": rss,
        "audit_wall_seconds": result["wall_seconds"],
        "audit_cgroup_memory_peak_bytes": int(result["cgroup_memory_peak_bytes"]),
        "temporary_observed_peak_bytes": 0,
        "temporary_retained_bytes": 0,
        "local_links_checked": links,
        "proofs": 0,
        "zkvm_executions": 0,
        "activation": False,
        "installations": False,
        "CPU_proving_paused": True,
        "raw_view_integration_paused": True,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
        "isolation_state": "safe-stopped-unactivated",
        "isolation_remaining_seconds_unchanged": 250.22,
        "isolation_identity_cases_pending": 22,
        "next_recommendation": "S3-AURORA-ROUND-PLAN-ADAPTER-CONTRACT-1",
        "next_package_started": False,
        "open_obligations": [
            "native transcript/IOP integration",
            "masking/query simulation",
            "commitment transformation",
            "adaptive extraction/privacy",
            "concrete hash",
            "Delta_tail",
            "production security",
        ],
    }
    audit.write_report(D / "validation-closure.json", closure)
    files = {path for root in (D, E) for path in root.rglob("*") if path.is_file()}
    files.update([REPORT, *[P / name for name in scope["append_only_documentation"]]])
    manifest = {
        "package": config["package"],
        "kind": "Additive seal, no baseline regeneration",
        "previous_manifest_sha256": closure["previous_manifest_sha256"],
        "self_excluded": "manifest.json",
        "sha256": {str(p.relative_to(P)): audit.digest_file(p) for p in sorted(files)},
    }
    audit.write_report(D / "manifest.json", manifest)
    final = audit.inventory_check(
        P,
        scope["additional_name_inventory_roots"],
        set(scope["required_names"]),
        optional_names=set(scope["optional_names"]),
    )
    assert final["passed"] and final["count"] == inventory["count"] + 2
    assert read("validation-closure.json") == closure and read("manifest.json") == manifest
    package_bytes = REPORT.stat().st_size + sum(
        p.stat().st_size for root in (D, E) for p in root.rglob("*") if p.is_file()
    )
    assert package_bytes < 262144 and config["prior_output_bytes"] + package_bytes < 10485760
    assert all(p.stat().st_size <= 1048576 for p in files)
    assert time.monotonic() - STARTED < 5
    print(
        json.dumps(
            {
                "closure": "complete",
                "package_bytes": package_bytes,
                "cumulative_package_bytes": config["prior_output_bytes"] + package_bytes,
                "manifest_sha256": audit.digest_file(D / "manifest.json"),
                "implementation_charge": charge,
                "implementation_remaining": remaining,
                "bookkeeping_elapsed": time.monotonic() - STARTED,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
