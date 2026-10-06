"""Write final new closure/seal once; never repeat the protected content audit."""

# Long template lines preserve single-line Markdown table rows.
# ruff: noqa: E402, E501

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
    config, scope, result = read("config.json"), read("scope.json"), read("result.json")
    runs, validation = read("run-ledger.json"), read("validation.json")
    assert result["passed"] and result["report_generation_completed"]
    assert result["resource_guard_passed"] and result["guard_exit_code"] == 0
    assert sum(row["name"] == "full-audit" for row in runs) == 1
    assert all(row["status"] == "pass" for row in runs)
    wall = sum(row["seconds"] for row in runs)
    charged = config["prior_security_analysis_charged_seconds"]
    charged += config["operator_charge_seconds"] + wall
    remaining = config["aggregate_seconds"] - charged
    assert remaining > 0
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    temporary = max(row["temporary_storage_observed_peak"] for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
    text = f"""

## Measured validation closure

The [complete preservation audit](data/s3_outer_oracle_composition_1/result.json)
passed content/inventory comparison, report readback and the final unchanged
resource guard, exit **0**. It covered {validation["protected_files"]:,} original
and {validation["supplementary_comparison"]["protected_files"]:,} supplementary
content paths: **{validation["content_partition_union"]:,} disjoint content paths**,
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths. There
were no unexpected changes, removals or additions. Exactly three existing reports
received append-only updates; their original prefixes remain intact. The baseline,
prior seals, original failures, production code and parameters are unchanged.

| Measurement | Result |
| --- | --- |
| Complete-audit wall time | {result["wall_seconds"]:.9f} s |
| Audit cgroup memory.peak | {int(result["cgroup_memory_peak_bytes"]):,} bytes, ceiling 268,435,456 |
| Audit sampled process-tree RSS | {result["sampled_tree_RSS_peak_bytes"]:,} bytes; a separate metric |
| Maximum new-job charged cgroup peak | {peak:,} bytes |
| New guarded jobs | {len(runs)}, all passed, {wall:.9f} s total |
| New validation | One documentation-contract consistency check; lint/format pass |
| Repeated calculations/functional suites | Zero; previous evidence reused |
| Failures / resource breaches / retries | 0 / 0 / 0 |
| Continued analysis allowance | **{charged:.9f} / 300 s charged; {remaining:.9f} s remain** |
| Temporary data | {temporary:,} observed peak bytes, zero retained |
| Package output at outer guard completion | {result["package_bytes_at_guard_completion"]:,} bytes |

Charged cgroup memory includes the worker, descendants and charged file-cache/kernel
memory. The external RSS sample can count shared pages more than once. Neither is
an estimate of proving memory. The above charge includes prior 21.956706719007343 s
and five operator/bookkeeping seconds. The final bookkeeping is separately bounded
by 256 MiB address space, CPU/alarm five seconds, two CPUs and 1 MiB files; it only
checks new outputs, exact names, links and report prefixes, then writes the new
closure/seal once. It does not repeat the protected content comparison.

[Final evidence seal](data/s3_outer_oracle_composition_1/manifest.json) and
[validation closure](data/s3_outer_oracle_composition_1/validation-closure.json)
record the complete disposition. No overall security number, production signing,
actual identity isolation or complete private-proof claim is made. Stages 2–3,
OC-REL/EXT/PRIV/BUDGET, A-K-MODEL, Delta_tail and component reduction advantages
remain open. Isolation stays stopped/unactivated with 22 cases and 250.22 seconds
preserved; proof ledger two used/one unused, CPU proving paused. The single next
implementation recommendation is **S2-BOUNDED-MLDSA-KEYGEN-SIGN-1**; it is not started.
"""
    report = P / "docs/stage3_outer_oracle_composition.md"
    with report.open("a") as stream:
        stream.write(text)
    short = f"""

Composition-review validation closure: one documentation-contract check and
lint/format pass. The single [complete preservation audit](data/s3_outer_oracle_composition_1/result.json)
passed comparison, inventory, report readback and the unchanged 256 MiB cgroup guard,
exit 0: {validation["content_partition_union"]:,} content paths,
{result["wall_seconds"]:.9f} s, {int(result["cgroup_memory_peak_bytes"]):,}-byte charged peak.
No new failure, resource breach or retry; historical failures and seals preserved.
Continued analysis accounting **{charged:.9f}/300 s**, **{remaining:.9f} s remain**;
no isolation/proof allowance consumed. Numerical/functional validation was reused.
Finite review complete with the specified missing lemmas; no concrete knowledge/
privacy transfer or overall bit-security claim. Next implementation recommendation
S2-BOUNDED-MLDSA-KEYGEN-SIGN-1, not started. Stages 2–3 and existing obligations
remain open; isolation unactivated, proof ledger two used/one unused.
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
    assert inventory["passed"]
    assert not any((D / "tmp").iterdir())
    final_count = inventory["count"] + 2
    closure = {
        "package": config["package"],
        "assessment": "complete-with-precisely-stated-missing-lemmas",
        "full_audit_passed": True,
        "result_sha256": audit.digest_file(D / "result.json"),
        "scope_sha256": audit.digest_file(D / "scope.json"),
        "run_ledger_sha256": audit.digest_file(D / "run-ledger.json"),
        "previous_manifest_sha256": read("preflight-evidence.json")["previous_manifest_sha256"],
        "source_inventory_sha256": read("preflight-evidence.json")["source_inventory_sha256"],
        "guarded_commands": len(runs),
        "focused_documentation_checks": 1,
        "new_numerical_calculations": 0,
        "failures": 0,
        "resource_breaches": 0,
        "retries": 0,
        "full_audit_attempts": 1,
        "guarded_wall_seconds": wall,
        "prior_analysis_charged_seconds": config["prior_security_analysis_charged_seconds"],
        "operator_and_bookkeeping_charge_seconds": config["operator_charge_seconds"],
        "aggregate_charged_seconds": charged,
        "aggregate_remaining_seconds": remaining,
        "max_cgroup_memory_peak_bytes": peak,
        "max_observed_tree_RSS_bytes": rss,
        "temporary_storage_observed_peak_bytes": temporary,
        "full_audit_cgroup_peak_bytes": int(result["cgroup_memory_peak_bytes"]),
        "full_audit_seconds": result["wall_seconds"],
        "final_local_links_checked": links,
        "final_name_inventory_count": final_count,
        "final_name_inventory_method": "Exact predeclared inventory plus two write-once final records",
        "final_bookkeeping_scope": "New outputs, names, links and report prefixes; no content re-audit",
        "bookkeeping_limits": "256MiB address space, CPU/alarm5s, two CPUs, file1MiB; included five seconds",
        "bookkeeping_elapsed_before_write_seconds": time.monotonic() - STARTED,
        "proofs": 0,
        "zkvm_executions": 0,
        "estimator_runs": 0,
        "circuit_generation": 0,
        "activation": False,
        "production_source_or_parameters_changed": False,
        "functional_tests_repeated": 0,
        "CPU_proving_paused": True,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
        "isolation_state": "safe-stopped-unactivated",
        "isolation_tests_unchanged": 100,
        "isolation_identity_cases_pending": 22,
        "isolation_remaining_seconds_unchanged": 250.22,
        "open_obligations": ["OC-REL", "OC-EXT", "OC-PRIV", "OC-BUDGET", "A-K-MODEL"],
        "open_issues": [
            "SEC-001",
            "SEC-002",
            "SEC-003",
            "SEC-004",
            "SEC-005",
            "DEP-001",
            "DEP-002",
        ],
        "next_recommendation": "S2-BOUNDED-MLDSA-KEYGEN-SIGN-1",
        "next_package_started": False,
        "final_temporary_bytes": 0,
    }
    audit.write_report(D / "validation-closure.json", closure)
    files = {path for path in D.rglob("*") if path.is_file()}
    files.update([report, *[P / name for name in scope["append_only_documentation"]]])
    manifest = {
        "package": config["package"],
        "kind": "Additive new composition-review seal; no original baseline regeneration",
        "previous_manifest_sha256": closure["previous_manifest_sha256"],
        "scope_sha256": closure["scope_sha256"],
        "self_excluded": "manifest.json",
        "sha256": {str(path.relative_to(P)): audit.digest_file(path) for path in sorted(files)},
    }
    audit.write_report(D / "manifest.json", manifest)
    final_inventory = audit.inventory_check(
        P,
        scope["additional_name_inventory_roots"],
        set(scope["required_names"]),
        optional_names=set(scope["optional_names"]),
    )
    assert final_inventory["passed"] and final_inventory["count"] == final_count
    assert read("manifest.json") == manifest and read("validation-closure.json") == closure
    size = sum(path.stat().st_size for path in D.rglob("*") if path.is_file())
    assert size < config["output_bytes"]
    assert all(
        path.stat().st_size <= config["per_file_bytes"] for path in files if path.is_relative_to(D)
    )
    assert time.monotonic() - STARTED < 5
    print(
        json.dumps(
            {
                "closed": True,
                "manifest_sha256": audit.digest_file(D / "manifest.json"),
                "sealed_paths": len(files),
                "final_inventory": final_inventory,
                "charged_seconds": charged,
                "remaining_seconds": remaining,
                "final_evidence_bytes": size,
                "bookkeeping_seconds": time.monotonic() - STARTED,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
