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
    assert pilot["passed"] and len(pilot["invocations"]) == 9
    probe = pilot["invocations"][0]
    assert validation["total_test_invocations_including_prior_package"] == 231
    peak = max(int(row["service"]["after"]["memory.peak"]) for row in runs)
    rss = max(row["sampled_tree_RSS_peak"] for row in runs)
    temporary = max(row["temporary_storage_observed_peak"] for row in runs)
    for row in runs:
        events = dict(
            line.split() for line in row["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
    report = P / "docs/stage3_private_hint_lowering_pilot.md"
    cases = "\n".join(
        f"| {row['case']} | {row['reference_valid']} | {row['candidate_valid']} | "
        f"{row['decoded_values_compared']} | {row['seconds']:.6f} | pass |"
        for row in pilot["invocations"][1:]
    )
    suffix = f"""

## Measured result and decision

**A justified component candidate for further integration into a separately
reviewed lowering.** One generation probe and all eight differential cases pass,
first run. No original baseline rerun, no extra construction or hidden batch.

| Case | Reference valid | Candidate valid | Decoded values compared | Seconds | Outcome |
| --- | --- | --- | --- | --- | --- |
{cases}

The generation probe completed in {probe["seconds"]:.9f} s; emitter timer
{probe["generation_seconds"]:.9f} s. Complete count:
**{probe["total_gates"]:,} gates / {probe["counts"]["and_"]:,} ANDs**, with
{probe["counts"]["xor"]:,} XOR and {probe["counts"]["not_"]:,} NOT gates,
{probe["wires"]:,} wires, {probe["trace_bytes"]:,} in-memory trace bytes.
There are zero test-comparison gates and zero extra gates for signed64 output
zero-extension. Output masking and final sticky validity ARE included.
Fingerprint: `{probe["fingerprint"]}`.
Generation-time Python-process high-water RSS:
{probe["python_process_high_water_RSS_bytes"]:,} bytes; cgroup peak at that point:
{probe["cgroup_memory_peak_at_generation_bytes"]:,} bytes. These are different scopes.
The final guard records the entire worker/descendant peak, including validation.

The preserved baseline is an **incomplete 32,000,000-gate / 13,532,448-AND prefix**.
Its final padding/validity is unreached. The complete candidate uses
{pilot["comparison"]["prefix_and_minus_complete_candidate"]:,} fewer ANDs than that
prefix. For continuation of that exact original recipe, full baseline cost is at
least its recorded prefix; this is a useful conservative component cost gap.
It is **not a measured percentage reduction between two complete decoders**, a
canonical BC-1 optimisation or a measured whole-authentication reduction.
No matched timing/memory speedup is claimed: the old baseline counted only and
used a different resource envelope; this pilot also materialised and evaluated.

The candidate removes a demonstrated large private-index cost, so it could
materially reduce this component in a new whole-circuit design. Other measured
fragments remain: response/norm 537,603 ANDs and message preparation 413,709 ANDs
are separate results, not a sum or a complete residual. Bounded polynomial/NTT/
modular arithmetic and private depth-20 hashing remain major integration/cost
uncertainties. Full authentication and proof communication are still unmeasured.
Even this complete component exceeds the previously calculated 21,344-AND limit
for the frozen 10 MiB raw-view target, if embedded without further changes while
retaining that formula. No revised proof format is selected; no full-proof byte
projection or revised R0 forecast is made. A new compiler AND proof representation
still require a construction/security decision.

Recommend only **S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1**, a separately authorised
source/range-equivalence design for the next polynomial-arithmetic bottleneck.
Do not automatically generate another circuit or proof. Full integration needs
range/representation and active/inactive/composed-circuit validation beyond this
nine-invocation pilot; no invocation allowance remains for it in this ledger.

## Complete validation and preservation closure

Lint and formatting pass. The single
[complete preservation audit](data/s3_private_hint_lowering_pilot_1/result.json)
passes content, exact inventory, report readback and outer guard, exit 0:
{validation["content_partition_union"]:,} disjoint content paths,
{validation["identity_inclusive_unique_paths"]:,} identity-inclusive paths,
{result["wall_seconds"]:.9f} s and
{int(result["cgroup_memory_peak_bytes"]):,}-byte cgroup-v2 peak.
Maximum guarded-job cgroup peak {peak:,} bytes; separately sampled tree RSS
{rss:,} bytes. Both remain below 256 MiB; swap zero, no resource events.

{len(runs)} guarded commands total {wall:.9f} s. With five seconds of established
operator/bookkeeping charge, **{wall + 5:.9f}/30 s** is consumed by this package.
Implementation cumulative **{charged:.9f}/300 s**, **{remaining:.9f} s remain**.
Invocations **231/231**, zero remaining: 222 prior + one generation + eight cases.
Analysis remains 261.815740669 s; isolation 250.22 s,100 historical invocations and
22 pending identity cases. No resets, borrowed allowances, failures or repeats.
Temporary disk peak {temporary:,} bytes, zero retained; the in-memory trace is
released on process exit. Five-second final bookkeeping uses 256 MiB address space,
five-second CPU/alarm and two CPUs within the existing charge, no repeated scan.
[Closure](data/s3_private_hint_lowering_pilot_1/validation-closure.json) and
[seal](data/s3_private_hint_lowering_pilot_1/manifest.json) retain exact balances.

Existing code/BC-1/configuration/dependencies/manuscript/evidence are preserved.
Only three historical reports gain append-only dispositions. Stages 2–3 open;
isolation safely stopped/unactivated; CPU proving paused, two attempts used and
one unused. No installations, activation, proof attempts or zkVM executions.
"""
    with report.open("a") as stream:
        stream.write(suffix)
    short = f"""

Private-hint pilot closure: **one generation + eight differential cases pass**,
**231/231** cumulative invocations, zero remaining. Candidate complete:
{probe["total_gates"]:,} gates / {probe["counts"]["and_"]:,} ANDs; original
13,532,448-AND result is a capped prefix, not a complete matched baseline.
A useful component candidate under a proposed new lowering, **not BC-1** or a
full-authentication/proof result. Lint/format and the
[single audit](data/s3_private_hint_lowering_pilot_1/result.json) pass:
{validation["content_partition_union"]:,} disjoint paths,
{result["wall_seconds"]:.9f} s,
{int(result["cgroup_memory_peak_bytes"]):,}-byte cgroup peak under256MiB.
Package {wall + 5:.9f}/30 s charged, implementation
{charged:.9f}/300 s used, **{remaining:.9f} s remain**; analysis/isolation unchanged.
No failures, repeats or resource breaches. Active parameters/compiler preserved.
Stages2–3open, isolation stopped/unactivated, proof ledger2used1unused.
Next proposed only:S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1; not started.
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
        "status": "complete-useful-experimental-hint-component-not-BC1",
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
        "analysis_remaining_seconds_unchanged": 261.8157406691462,
        "max_cgroup_memory_peak_bytes": peak,
        "max_sampled_tree_RSS_bytes": rss,
        "full_audit_cgroup_peak_bytes": int(result["cgroup_memory_peak_bytes"]),
        "full_audit_wall_seconds": result["wall_seconds"],
        "temporary_storage_observed_peak_bytes": temporary,
        "final_temporary_bytes": 0,
        "test_invocations": config["test_invocations"],
        "total_test_invocations": 231,
        "unique_new_tests": 8,
        "generation_probe_invocations": 1,
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
        "circuit_generation": 1,
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
        "next_recommendation": "S3-MLDSA-ARITHMETIC-LOWERING-REVIEW-1",
        "next_package_started": False,
    }
    audit.write_report(D / "validation-closure.json", closure)
    files = {path for path in D.rglob("*") if path.is_file()}
    files.update([report, *[P / name for name in scope["append_only_documentation"]]])
    files.update(P / name for name in scope["frozen_package_inputs"])
    manifest = {
        "package": config["package"],
        "kind": "Additive isolated hint-lowering seal; no baseline regeneration",
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
