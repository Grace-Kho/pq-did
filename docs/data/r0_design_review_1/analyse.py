"""Recalculate design scenarios from frozen evidence; no guest/backend invocation."""

import hashlib
import json
import math
from datetime import datetime
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
R = P / "experiments/r0_credvalid_po17_1"
N = P / "experiments/r0_enrol_po17_1"
C = P / "experiments/r0_credvalid_cycle_1"


def load(p):
    return json.loads(p.read_text())


def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def close(a, b):
    assert math.isclose(a, b, rel_tol=0, abs_tol=1e-7), (a, b)


def save(name, data):
    (D / name).write_text(json.dumps(data, indent=2) + "\n")


def interval(name, begin, end):
    record = load(C / "evidence" / name)
    markers = {x["phase"]: x["user_cycle"] for x in record["markers"]}
    return markers[end] - markers[begin]


exe = load(R / "evidence/execution.result.json")
res = load(R / "evidence/execution.json")
a = load(R / "evidence/admission.result.json")
i = load(R / "evidence/cost-model-inputs.json")
ledger = load(R / "evidence/cumulative_attempt_ledger.json")
assert exe["user_cycles"] == 16313474 and exe["segments"] == 182
assert exe["segment_size_distribution"] == {"15": 1, "17": 181}
assert sum(x["user_cycles"] for x in exe["segment_records"]) == 16313474
assert sum(2 ** x["po2"] for x in exe["segment_records"]) == 23756800
assert exe["journal_matches_expected"] and exe["accepted"]
assert ledger["attempts_used"] == 2 and ledger["remaining"] == 1
base_rate, lift_rate, join_rate = [
    a["rates_seconds"][x] for x in ["base_po17", "lift_po17", "join"]
]
subtotal = 182 * base_rate + 182 * lift_rate + 181 * join_rate + exe["execution_seconds"] + 10
close(subtotal, a["subtotal_seconds"])
close(subtotal * 0.5, a["uncertainty_seconds"])
close(subtotal * 1.5, a["conservative_estimate_seconds"])
close(sum(x["combined_seconds"] for x in i["base_segments"]), i["observed_segment_block_seconds"])
close(
    sum(x["seconds"] for x in i["recursion_operations"]) + sum(i["recursion_handoff_seconds"]),
    i["observed_recursion_block_seconds"],
)

# Check typed phase observations against their frozen log positions and UTC times.
log_lines = (N / "evidence/attempt2.log").read_text().splitlines()
assert sha(N / "evidence/attempt2.log") == i["source_log_sha256"]


def observed_seconds(start, end):
    for event in (start, end):
        assert event["UTC"] in log_lines[event["line"] - 1]
    return (
        datetime.fromisoformat(end["UTC"]) - datetime.fromisoformat(start["UTC"])
    ).total_seconds()


for phase in i["base_segments"]:
    close(
        observed_seconds(phase["start"], phase["core_start"]), phase["preflight_observed_seconds"]
    )
    close(
        observed_seconds(phase["core_start"], phase["end"]),
        phase["core_through_next_boundary_seconds"],
    )
    close(observed_seconds(phase["start"], phase["end"]), phase["combined_seconds"])
for phase in i["recursion_operations"]:
    close(observed_seconds(phase["start"], phase["end"]), phase["seconds"])
for left, right, handoff in zip(
    i["recursion_operations"][:-1],
    i["recursion_operations"][1:],
    i["recursion_handoff_seconds"],
    strict=True,
):
    close(observed_seconds(left["end"], right["start"]), handoff)
close(base_rate, max(x["combined_seconds"] for x in i["base_segments"]))
for kind, rate in [("lift", lift_rate), ("join", join_rate)]:
    close(
        rate,
        max(x["seconds"] for x in i["recursion_operations"] if x["kind"] == kind)
        + max(i["recursion_handoff_seconds"]),
    )


def scenario(s, base=True, lifts=True, joins=True, execution=0):
    raw = (
        s * base_rate * base
        + s * lift_rate * lifts
        + max(s - 1, 0) * join_rate * joins
        + 10
        + execution
    )
    return {
        "segments_assumed": s,
        "before_allowance_seconds": raw,
        "allowance_50_percent_seconds": raw / 2,
        "with_allowance_seconds": raw * 1.5,
    }


thresholds = {
    str(t): {
        "forecast_ratio": subtotal * 1.5 / t,
        "required_reduction_percent": 100 * (1 - t / (subtotal * 1.5)),
    }
    for t in [600, 30, 45, 10]
}
fixed = {
    key: scenario(182, **kwargs, execution=exe["execution_seconds"])
    for key, kwargs in {
        "all_base_proving_free": {"base": False},
        "all_recursion_free": {"lifts": False, "joins": False},
        "all_joins_free": {"joins": False},
    }.items()
}
small = {str(s): scenario(s, execution=exe["execution_seconds"]) for s in [1, 3, 4]}
# These are conditional extrapolations of an isolated transform, not measured phase totals.
mat = interval("matrix-after.analysis.json", "component_matrix_start", "component_matrix_done")
ntt = interval("ntt-z0.analysis.json", "component_ntt_start", "component_ntt_done")
zetas = interval("ntt-z0.analysis.json", "component_zetas_start", "component_ntt_start")
assert mat == 113393 and ntt == 409218 and zetas == 567539
public_saving = {
    "thirty_matrix_polynomials_proxy": 30 * mat,
    "six_public_key_NTTs_proxy": 6 * ntt,
    "twiddle_component_proxy": zetas,
    "public_key_unpack_prefix_measurement": 163712,
}
public_sum = sum(public_saving.values())
optimistic = {}
for name, transforms in [
    ("accelerated_keccak_all_hash_and_other_work_free", 12),
    ("public_preprocessing_all_other_work_free", 6),
    ("both_optimisations_all_other_work_free", 6),
]:
    residual = transforms * ntt
    ideal_capacity_segments = math.ceil(residual / 2**17)
    optimistic[name] = {
        "retained_forward_transforms": transforms,
        "uniform_transform_cycle_proxy": ntt,
        "conditional_residual_cycle_proxy": residual,
        "ideal_capacity_segment_floor_given_proxy": ideal_capacity_segments,
        "scenario_at_that_assumed_count": scenario(ideal_capacity_segments),
        "qualification": (
            "Not actual segmentation or a rigorous lower bound: extrapolates one "
            "input-dependent component and assumes perfect packing. All inverse NTTs, "
            "products, parsing, binding, hashing, paging and added proof work omitted."
        ),
    }


# Parse only the sizes of existing synthetic encodings; no cryptographic evaluation.
def record(data):
    pos = 0

    def read(n):
        nonlocal pos
        v = data[pos : pos + n]
        pos += n
        assert len(v) == n
        return v

    def u32():
        return int.from_bytes(read(4), "big")

    read(u32())
    count = u32()
    fields = [read(u32()) for _ in range(count)]
    assert pos == len(data)
    return fields


def enc_len(tag, fields):
    return 4 + len(tag) + 4 + sum(4 + n for n in fields)


x = record((R / "fixtures/public/cred-alpha-42.bin").read_bytes())
pp = record(x[2])
w = record((R / "fixtures/private/cred-alpha-42.bin").read_bytes())
cred = record(w[0])
cert = record(cred[0])
metadata_len = len(cred[4])
suite_len = len(pp[0])
holder_len = enc_len(b"holder", [suite_len, metadata_len, 32])
mcred_len = enc_len(b"cred", [suite_len, metadata_len, len(cert[0]), 4])


# The inspected tiny-keccak squeeze performs another permutation on an exact rate boundary.
def permutations(n, out, rate):
    return n // rate + 1 + out // rate


keccak_bound = {
    "matrix_30_at_full_1026_budget": 30 * permutations(34, 1026, 168),
    "holder_sha3_384": permutations(holder_len, 48, 104),
    "tr_shake256": permutations(1952, 64, 136),
    "mu_shake256": permutations(64 + 2 + len(b"PQ-DID/credential/v1") + mcred_len, 64, 136),
    "challenge_shake256": permutations(48, 256, 136),
    "final_challenge_shake256": permutations(64 + 768, 48, 136),
}
assert sum(keccak_bound.values()) < 655
sizes = {
    "matrix_canonical_u32_bytes": 30 * 256 * 4,
    "six_scaled_t1_NTT_u32_bytes": 6 * 256 * 4,
    "suite_twiddles_u32_bytes": 256 * 4,
    "tr_bytes": 64,
}
assert sum(sizes.values()) == 37952
# Pin the exact inspected local SDK functions and measurement files.
crate = next((C / "tooling/cargo/registry/src").iterdir())
paths = [
    R / "evidence/execution.result.json",
    R / "evidence/execution.json",
    R / "evidence/admission.result.json",
    R / "evidence/cost-model-inputs.json",
    R / "evidence/cumulative_attempt_ledger.json",
    N / "evidence/attempt2.log",
    N / "evidence/attempt2.json",
    N / "evidence/verify.result.json",
    C / "evidence/baseline-prefix.analysis.json",
    C / "evidence/matrix-after.analysis.json",
    C / "evidence/ntt-z0.analysis.json",
    C / "relation/src/mldsa.rs",
    C / "relation/src/lib.rs",
    P / "docs/implementation_spec.md",
    P / "docs/benchmark_targets.md",
]
for tail in [
    "risc0-zkvm-3.0.6/src/guest/env/mod.rs",
    "risc0-zkvm-3.0.6/src/guest/env/batcher.rs",
    "risc0-zkvm-platform-2.2.3/src/syscall.rs",
    "risc0-zkvm-3.0.6/src/host/server/exec/syscall/keccak.rs",
    "risc0-zkvm-3.0.6/src/host/server/prove/keccak.rs",
    "risc0-zkvm-3.0.6/src/host/server/prove/prover_impl.rs",
    "risc0-zkvm-3.0.6/src/host/server/prove/mod.rs",
    "risc0-zkvm-3.0.6/src/host/server/prove/union_peak.rs",
    "risc0-zkvm-3.0.6/src/host/recursion/prove/mod.rs",
    "risc0-zkvm-3.0.6/src/host/recursion/prove/zkr.rs",
    "risc0-circuit-keccak-4.0.6/src/lib.rs",
    "risc0-circuit-keccak-4.0.6/src/prove/mod.rs",
    "risc0-circuit-keccak-4.0.6/src/prove/zkr.rs",
    "risc0-circuit-keccak-4.0.6/src/control_id.rs",
    "risc0-circuit-keccak-4.0.6/build.rs",
    "risc0-zkvm-3.0.6/src/host/client/env.rs",
    "risc0-zkvm-3.0.6/Cargo.toml",
    "risc0-build-3.0.6/Cargo.toml",
]:
    paths.append(crate / tail)
result = {
    "package": "R0-DESIGN-REVIEW-1",
    "kind": "existing-measurement analysis, not a new benchmark",
    "source_sha256": {str(p.relative_to(P)): sha(p) for p in paths},
    "phase_log_UTC_intervals_and_rates_checked": True,
    "baseline": {
        "user_cycles": exe["user_cycles"],
        "segments": exe["segments"],
        "distribution": exe["segment_size_distribution"],
        "padded_capacity": exe["padded_capacity"],
        "execution_API_seconds": exe["execution_seconds"],
        "guarded_execution_seconds": res["wall_seconds"],
        "kernel_cgroup_peak_bytes": res["cgroup_memory_peak_bytes"],
        "sampled_tree_RSS_bytes": res["sampled_process_tree_RSS_peak"],
        "host_only_peak_bytes": None,
        "actual_CredValid_proving_seconds": None,
        "actual_CredValid_prover_peak_bytes": None,
    },
    "forecast_audit": {
        "rates_seconds": a["rates_seconds"],
        "subtotal_seconds": subtotal,
        "allowance_fraction": 0.5,
        "allowance_seconds": subtotal / 2,
        "forecast_seconds": subtotal * 1.5,
        "forecast_hours": subtotal * 1.5 / 3600,
        "allowance_applied_once_to_entire_subtotal": True,
    },
    "target_gaps": thresholds,
    "fixed_partition_free_component_scenarios": fixed,
    "assumed_small_partition_scenarios": small,
    "component_cycle_proxies": {
        "matrix_one": mat,
        "forward_NTT_one": ntt,
        "twiddles": zetas,
        "public_preprocessing_items": public_saving,
        "public_preprocessing_sum": public_sum,
        "public_preprocessing_fraction_of_baseline": public_sum / 16313474,
        "residual_after_proxy_saving": 16313474 - public_sum,
        "missing_public_tr_cost": None,
        "scope": (
            "Component/prefix proxies only; no measured complete-phase saving. "
            "Binding, input/page, cache/communication costs excluded."
        ),
    },
    "optimistic_retained_work_scenarios": optimistic,
    "keccak_static_upper_scenario": {
        "holder_input_bytes": holder_len,
        "Mcred_bytes": mcred_len,
        "permutations_by_call": keccak_bound,
        "permutations_bound": sum(keccak_bound.values()),
        "batch_po2_default": 17,
        "capacity_per_batch": 655,
        "batches_for_bound": 1,
        "added_operations": {
            "Keccak_base_proof": 1,
            "Keccak_lift_at_recursion_po2_18": 1,
            "ordinary_union": 0,
            "resolve": 1,
        },
        "scope": (
            "Source calculation for original fixture shapes and same refill scheme, "
            "not executed acceleration. Bounds all 30 matrix streams by 1026 generated bytes. "
            "Extra guest hash calls or changed adapter schedule invalidate this bound."
        ),
        "added_operation_times_seconds": None,
        "added_peak_memory_bytes": None,
    },
    "public_preprocessing_raw_sizes": sizes,
    "public_preprocessing_total_raw_bytes": sum(sizes.values()),
    "one_time_table_software_SHA3_permutations_minimum": sum(sizes.values()) // 104 + 1,
    "proof_attempt_ledger": {
        "used": 2,
        "unused": 1,
        "sha256": sha(R / "evidence/cumulative_attempt_ledger.json"),
        "unchanged": True,
    },
    "new_guest_executions": 0,
    "new_proof_attempts": 0,
    "candidate_installs": 0,
    "resource_limit_changes": 0,
}
save("calculations.json", result)
print(
    json.dumps(
        {
            "forecast_seconds": subtotal * 1.5,
            "target_gaps": thresholds,
            "small_partition": small,
            "public_saving_proxy": public_sum,
            "optimistic": optimistic,
            "keccak_static": result["keccak_static_upper_scenario"],
        },
        indent=2,
    )
)
