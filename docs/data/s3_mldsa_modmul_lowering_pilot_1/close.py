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
    assert config["operator_charge_seconds"] + wall <= 30
    pilot = read("pilot-result.json")
    assert pilot["passed"] and len(pilot["invocations"]) == 16
    assert validation["total_test_invocations_including_prior_package"] == 247
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    temporary = max(row["temporary_storage_observed_peak"] for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
    report = P / "docs/stage3_mldsa_modmul_lowering_pilot.md"
    counts = []
    outcomes = []
    for row in pilot["invocations"]:
        if row["kind"] == "generation-probe":
            outcomes.append(f"| {row['case']} | paired trace complete | pass |")
            for c in row["components"]:
                counts.append(
                    f"| {row['factor']} | {c['name']} | {c['total_gates']:,} | "
                    f"{c['counts']['and_']:,} | {c['generation_and_counting_seconds']:.9f} |"
                )
        elif row["kind"] == "differential-case":
            outcomes.append(
                f"| {row['case']} | valid={row['expected_valid']}; "
                f"word={row['expected_word']}; usable={row['usable']} | pass |"
            )
        else:
            outcomes.append(f"| {row['case']} | both reject before emission | pass |")
    count_table = "\n".join(counts)
    case_table = "\n".join(outcomes)
    decision = pilot["decision"]
    recommendation = (
        "S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1: separately bounded forward/inverse "
        "butterfly composition with exact entry conversions, guards and matched counts."
        if decision == "merits-bounded-composition"
        else "A source-only review of the measured overhead before any further circuit work."
    )
    suffix = f"""

## Measured result and decision

Decision: **{decision}**. Both paired traces and every one of the fourteen named
validation cases completed on the first attempt. No additional test or probe ran.
Each paired trace contains complete, independent baseline and candidate cores;
the single final conjunction gate is separately reported as harness overhead.

| Public factor | Fully guarded core | Total gates | AND gates | Generation/counting seconds |
| --- | --- | ---: | ---: | ---: |
{count_table}

All canonical guards, scalar operations, full64 output masks and final scope
validity are included. Input rewiring/zero-extension require no gates. There are
zero equality-to-test-target gates. Gate-segment SHA-256 values, wire offsets,
phase counts and complete paired-trace fingerprints are in the
[run record](data/s3_mldsa_modmul_lowering_pilot_1/pilot-result.json).
Segment hashes refer to that paired trace, not standalone BC-1 circuit identities.
No trusted-canonical variant was measured. All counts above are complete.

| Invocation | Expected and observed outcome | Result |
| --- | --- | --- |
{case_table}

For each differential case, the reference and candidate output words and validity
match the independent exact arithmetic/control oracle. The normal evaluator also
agrees with the combined acceptance predicate. An inactive invalid input is not
accepted as a usable scalar: its scope stays fault-free but both output words are
zero and unusable. Existing rejection remains sticky.

Pilot elapsed {pilot["total_seconds"]:.9f} s. Aggregate retained trace bytes:
{pilot["aggregate_retained_trace_bytes"]:,}; all released at process exit, none on disk.
Pilot Python-process high-water RSS: {pilot["python_process_high_water_RSS_bytes"]:,}
bytes; pilot cgroup peak at final observation:
{pilot["cgroup_memory_peak_so_far_bytes"]:,} bytes. Per-component records are
**peak-so-far observations**, not isolated component memory costs. Both cores share
a generation/evaluation process; no memory or timing speedup claim follows.

The measurements justify this decision only for the two tested public constants
and this fully guarded scalar interface. Finite cases are not a universal
implementation equivalence proof. They do not generalise to private multiplication,
a complete transform/verifier, proof size or RISC Zero performance.
Recommended next package only: **{recommendation}** Not started or authorised here.
All compiler/profile conformance, full authentication and proof knowledge/privacy
obligations remain open.

## Complete preservation and resource closure

Lint/format and the single
[complete preservation audit](data/s3_mldsa_modmul_lowering_pilot_1/result.json)
pass, exit 0: {validation["content_partition_union"]:,} disjoint content paths,
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths, exact name
inventory, complete report readback and outer guard. Audit {result["wall_seconds"]:.9f}s,
cgroup-v2 memory.peak {int(result["cgroup_memory_peak_bytes"]):,} bytes under256MiB.
Maximum guarded-job cgroup peak {peak:,} bytes; separately sampled tree RSS
{rss:,} bytes. No resource breaches, failed checks or retries.

{len(runs)} guarded commands consumed {wall:.9f}s. With the established five-second
operator/bookkeeping charge, package charge is **{wall + 5:.9f}/30s**.
Cumulative implementation charge **{charged:.9f}/300s**;
**{remaining:.9f}s remain**. Tests/probes **247/247**, zero remaining:
231 historical +2 paired generation/count probes +10 differential +4 constant cases.
Analysis stays253.606485157s; isolation250.22s,100 historical/22 pending identity cases.
Temporary disk observed peak {temporary:,} bytes, zero retained. Final bounded
bookkeeping uses256MiB address space, CPU/alarm5s,two CPUs,1MiB/file inside the
five-second charge; no repeated content audit.
[Closure](data/s3_mldsa_modmul_lowering_pilot_1/validation-closure.json) and
[seal](data/s3_mldsa_modmul_lowering_pilot_1/manifest.json) retain exact balances.

Production code/parameters/profile/dependencies/manuscript/history are unchanged.
Stages 2–3 remain open; CPU proving paused, isolation safely stopped/unactivated.
No proofs, zkVM executions, installations or activation; proof ledger two used/one unused.
"""
    with report.open("a") as stream:
        stream.write(suffix)
    short = f"""

Modmul pilot closure: **{decision}**. Two paired generation probes, ten differential
cases and four invalid-constant cases pass: **247/247** cumulative, zero remaining.
Both public-constant kernels have complete matched guarded counts in the
[report](stage3_mldsa_modmul_lowering_pilot.md); no full-transform/proof claim.
Lint/format and the [single audit](data/s3_mldsa_modmul_lowering_pilot_1/result.json)
pass {validation["content_partition_union"]:,} disjoint paths, {result["wall_seconds"]:.9f}s,
{int(result["cgroup_memory_peak_bytes"]):,}-byte cgroup peak under256MiB.
Package{wall + 5:.9f}/30s; implementation{charged:.9f}/300s used,
**{remaining:.9f}s remain**. Analysis/isolation unchanged. No failures/retries.
ARITH-LOWER-001 remains open for composition/conformance; Stages2–3open,
proof ledger2used1unused. Next proposed only: {recommendation}
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
        "status": "complete-experimental-modmul-component-not-BC1",
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
        "analysis_remaining_seconds_unchanged": 253.60648515704088,
        "max_cgroup_memory_peak_bytes": peak,
        "max_sampled_tree_RSS_bytes": rss,
        "full_audit_cgroup_peak_bytes": int(result["cgroup_memory_peak_bytes"]),
        "full_audit_wall_seconds": result["wall_seconds"],
        "temporary_storage_observed_peak_bytes": temporary,
        "final_temporary_bytes": 0,
        "test_invocations": config["test_invocations"],
        "total_test_invocations": 247,
        "unique_new_tests": 14,
        "generation_probe_invocations": 2,
        "remaining_test_invocations": 0,
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
        "circuit_generation": 2,
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
        "next_recommendation": recommendation,
        "next_package_started": False,
    }
    audit.write_report(D / "validation-closure.json", closure)
    files = {path for path in D.rglob("*") if path.is_file()}
    files.update([report, *[P / name for name in scope["append_only_documentation"]]])
    files.update(P / name for name in scope["frozen_package_inputs"])
    manifest = {
        "package": config["package"],
        "kind": "Additive isolated modmul-lowering seal; no baseline regeneration",
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
