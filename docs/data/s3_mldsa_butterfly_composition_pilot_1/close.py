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
    assert validation["total_test_invocations_including_prior_package"] == 263
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    temporary = max(row["temporary_storage_observed_peak"] for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
    report = P / "docs/stage3_mldsa_butterfly_composition_pilot.md"
    counts, outcomes, savings = [], [], []
    for row in pilot["invocations"]:
        if row["kind"] == "generation-probe":
            outcomes.append(f"| {row['case']} | paired trace complete | pass |")
            for c in row["components"]:
                counts.append(
                    f"| {row['workload']} | {c['name']} | {c['total_gates']:,} | "
                    f"{c['counts']['and_']:,} | {c['generation_and_counting_seconds']:.9f} |"
                )
            b, c = row["components"]
            dg, da = b["total_gates"] - c["total_gates"], b["counts"]["and_"] - c["counts"]["and_"]
            savings.append(
                f"{row['workload']}: {dg:,} fewer total gates "
                f"({100 * dg / b['total_gates']:.4f}%), {da:,} fewer AND gates "
                f"({100 * da / b['counts']['and_']:.4f}%)."
            )
        elif row["kind"] == "differential-case":
            outcomes.append(
                f"| {row['case']} | flags={row['expected_validity_by_node']}; "
                f"words={row['expected_words']}; usable={row['usable']} | pass |"
            )
        else:
            outcomes.append(f"| {row['case']} | both reject before emission | pass |")
    count_table, case_table = "\n".join(counts), "\n".join(outcomes)
    saving_text = " ".join(savings)
    probes = [row for row in pilot["invocations"] if row["kind"] == "generation-probe"]
    b, c = probes[0]["components"]
    surviving_gates = b["total_gates"] - c["total_gates"]
    surviving_ands = b["counts"]["and_"] - c["counts"]["and_"]
    decision = pilot["decision"]
    recommendation = (
        "S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1: a separately authorised, bounded "
        "stage/transform counting and differential experiment with actual schedule, "
        "all conversion costs, explicit output invariants and unchanged gate/memory caps."
        if decision == "supports-bounded-transform-experiment"
        else "Source-only review of measured composition overhead before more circuit work."
    )
    suffix = f"""

## Measured result and decision

Decision: **{decision}**. Two paired probes, twelve differential cases and two
public-constant refusals pass on their first attempt:16 individually recorded
invocations. No other case or probe ran. Complete matched counts:

| Workload | Fully guarded component | Total gates | AND gates | Generation/counting seconds |
| --- | --- | ---: | ---: | ---: |
{count_table}

{saving_text}

All signed64 conversions, exact original overflow conditions, scalar guards,
addition/subtraction/corrections, full64 output masks and scope validity are
included, including at the second node. Input bit rewiring and zero-extension
cost no gates. No trusted-input variant, algebraic sharing between cores or
comparison-to-test-target gate is discounted. One final harness AND joins the two
final validity wires, outside the component totals. All counts are complete;
no capped prefix is presented as a complete component.
[Raw record](data/s3_mldsa_butterfly_composition_pilot_1/pilot-result.json) retains
phase offsets, segment hashes, output wires and complete paired fingerprints.
Segment hashes use global paired-trace wire numbers, not canonical BC-1 identities.

The historical guarded scalar saving was67,874 total/28,389 AND gates. After the
complete signed butterfly boundary the measured net saving is
{surviving_gates:,} total/{surviving_ands:,} AND gates, numerically
{100 * surviving_gates / 67874:.4f}%/{100 * surviving_ands / 28389:.4f}% of that
absolute scalar difference. This is an overhead comparison, not attribution of
all butterfly gates to that scalar. The old scalar interface admitted canonical
inputs only; this butterfly admits the full original checked signed64 domain.
The percentage reduction of the **matched butterfly** is the one above, not the
historical scalar percentage. No overlapping component totals are added.

| Invocation | Expected and observed outcome | Result |
| --- | --- | --- |
{case_table}

Words are ordered first-node(left,right), then second-node(left,right) where
applicable. Both implementations match the independent exact-integer oracle on
all words and node-validity flags. Every usable intermediate/final value is in
0..q-1. Rejected/inactive outputs are zero and unusable. An inactive clean scope
may have valid=1; that does not make its zero output usable. D12 shows the first
node's failure propagating through the same scope to the second node.

Pilot elapsed {pilot["total_seconds"]:.9f}s; retained trace peak
{pilot["peak_retained_trace_bytes"]:,} bytes, first trace released before second
probe; none on disk. Python process high-water RSS
{pilot["python_process_high_water_RSS_bytes"]:,} bytes; cgroup peak at final pilot
observation {pilot["cgroup_memory_peak_so_far_bytes"]:,} bytes. Per-component
memory fields are **peak-so-far**, not isolated component costs. Per-component
seconds include emission/counting; paired generation seconds also include
finalisation/hash/bookkeeping. Two generation samples establish no throughput,
percentile, whole-transform, proof-size or RISC Zero prediction.

Finite tests do not prove universal equivalence. This supports only a bounded
forward stage/transform experiment. The omitted frontier producer, full schedule,
other constants, inverse ordering/scaling, signed norm/decomposition and the full
private verifier remain unmeasured. Proposed next package: **{recommendation}**
No next-package allowance is active and no further work was launched.

## Preservation and final resource accounting

Lint/format and the single
[complete audit](data/s3_mldsa_butterfly_composition_pilot_1/result.json) pass exit0:
{validation["content_partition_union"]:,} disjoint content paths,
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths, exact
inventory, completed report/readback and outer guard. Audit wall
{result["wall_seconds"]:.9f}s, cgroup-v2 memory.peak
{int(result["cgroup_memory_peak_bytes"]):,} bytes under the unchanged256MiB ceiling.
Across guarded jobs maximum cgroup peak {peak:,} bytes; separately sampled aggregate
tree RSS {rss:,} bytes. No resource breach, failure or retry.

{len(runs)} guarded commands consume {wall:.9f}s, plus the established5s
operator/bookkeeping charge: **{wall + 5:.9f}/30s** for this package.
Implementation **{charged:.9f}/300s consumed**, **{remaining:.9f}s remain**.
Tests/probes **263/263**, zero remaining:247 historical +2 paired generation/count
probes +12 differential +2 constant refusals. Analysis stays253.606485157s;
isolation250.22s,100 historical/22 pending identity cases. Temporary disk observed
peak {temporary:,} bytes, zero retained. Final bookkeeping is limited to256MiB
address space, CPU/alarm5s, two CPUs,1MiB/file within the five-second charge;
it is not a repeated protected-content audit.
[Closure](data/s3_mldsa_butterfly_composition_pilot_1/validation-closure.json) and
[seal](data/s3_mldsa_butterfly_composition_pilot_1/manifest.json) retain exact balances.

Production code, BC-1, parameters, dependencies, manuscript and historical evidence
are preserved. Stages2–3open; CPU proving paused; isolation safely stopped and
unactivated. No proofs, zkVM execution, installations or host activation.
Proof ledger two attempts used/one unused; complete proof knowledge/privacy,
adaptive Delta_tail and production-security obligations remain open.
"""
    with report.open("a") as stream:
        stream.write(suffix)
    short = f"""

Butterfly pilot closure: **{decision}**. Two paired generation probes, twelve
differential cases and two invalid-twiddle cases pass: **263/263** cumulative,
zero invocations remaining. Full signed64 matched boundaries and the two-node
actual schedule fragment have complete counts in the
[report](stage3_mldsa_butterfly_composition_pilot.md). {saving_text}
Experimental lowering is not canonical BC-1 or a complete transform/proof result.
Lint/format and the [single audit](data/s3_mldsa_butterfly_composition_pilot_1/result.json)
pass {validation["content_partition_union"]:,} disjoint paths,
{result["wall_seconds"]:.9f}s, {int(result["cgroup_memory_peak_bytes"]):,}-byte
cgroup peak under256MiB. Package{wall + 5:.9f}/30s;
implementation{charged:.9f}/300s used; **{remaining:.9f}s remain**.
Analysis/isolation unchanged; no failures/retries. ARITH-LOWER-001 remains open
for transform composition/conformance; Stages2–3open, proof ledger2used1unused.
Next proposed only: {recommendation}
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
        "status": "complete-experimental-forward-butterfly-component-not-BC1",
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
        "total_test_invocations": 263,
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
        "kind": "Additive isolated butterfly-composition seal; no baseline regeneration",
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
