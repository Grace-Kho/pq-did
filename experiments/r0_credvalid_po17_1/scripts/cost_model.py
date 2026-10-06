"""Read-only timing extraction plus conditional admission; never launches a prover."""

import datetime as dt
import hashlib
import json
import re
from pathlib import Path

R = Path(__file__).resolve().parents[1]
N = R.parent / "r0_enrol_po17_1"
C = R.parent / "r0_credvalid_cycle_1"
P = R.parents[1]


def load(p):
    return json.loads(p.read_text())


def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def save(name, value):
    (R / "evidence" / name).write_text(json.dumps(value, indent=2) + "\n")


# Source UTC timestamps share one clock; the retained log is complete.
log = N / "evidence/attempt2.log"
progress = load(N / "evidence/attempt2.sdk-progress.json")
assert progress["middle_omitted_bytes"] == 0
patterns = {
    "execution_complete": "prove_session:",
    "preflight": ": segment_preflight",
    "core": ": prove_segment_core",
    "lift_start": "Proving lift: claim",
    "lift_end": "Proving lift finished:",
    "join_start": "Proving join: a.claim",
    "join_end": "Proving join finished:",
}
events = {key: [] for key in patterns}
for number, line in enumerate(log.read_text().splitlines(), 1):
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    stamp = re.search(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z", line)
    for key, marker in patterns.items():
        if marker in line and stamp:
            events[key].append({"UTC": stamp[0], "line": number})
assert [len(events[k]) for k in patterns] == [1, 3, 3, 3, 3, 2, 2]


def seconds(a, b):
    return (
        dt.datetime.fromisoformat(b["UTC"]) - dt.datetime.fromisoformat(a["UTC"])
    ).total_seconds()


base = []
for i, start in enumerate(events["preflight"]):
    end = events["preflight"][i + 1] if i < 2 else events["lift_start"][0]
    core = events["core"][i]
    base.append(
        {
            "segment": i,
            "po2": 17,
            "start": start,
            "core_start": core,
            "end": end,
            "preflight_observed_seconds": seconds(start, core),
            "core_through_next_boundary_seconds": seconds(core, end),
            "combined_seconds": seconds(start, end),
        }
    )
operations = []
for kind in ["lift", "join"]:
    for i, (start, end) in enumerate(
        zip(events[kind + "_start"], events[kind + "_end"], strict=True)
    ):
        operations.append(
            {
                "kind": kind,
                "ordinal": i + 1,
                "input_segment_po2": 17 if kind == "lift" else None,
                "start": start,
                "end": end,
                "seconds": seconds(start, end),
            }
        )
operations.sort(key=lambda x: x["start"]["UTC"])
gaps = [seconds(a["end"], b["start"]) for a, b in zip(operations, operations[1:], strict=False)]
resource = load(N / "evidence/attempt2.json")
receipt = load(N / "receipts/attempt2.bin.json")
observed_block = seconds(events["preflight"][0], events["join_end"][-1])
residual = resource["wall_seconds"] - observed_block
crate = next((C / "tooling/cargo/registry/src").iterdir())
source_notes = {
    "risc0-zkvm-3.0.6/src/host/server/exec/executor.rs": (
        "run: default temporary FileSegmentRef for every segment; retained by S"
        "ession until pipeline returns"
    ),
    "risc0-zkvm-3.0.6/src/host/server/session.rs": (
        "FileSegmentRef::resolve: file contents plus deserialised Segment tempo"
        "rarily coexist; full segment files retained, not all decoded traces re"
        "sident"
    ),
    "risc0-zkvm-3.0.6/src/host/server/prove/prover_impl.rs": (
        "Sequential segment preflight/core/verify; all SegmentReceipts retained"
        " in Composite; Composite verification before recursion; default no PoV"
        "W; final Succinct verification and Session stats"
    ),
    "risc0-zkvm-3.0.6/src/host/server/prove/mod.rs": (
        "composite_to_succinct: S lifts and S-1 sequential joins, then only ass"
        "umption resolution if assumptions exist"
    ),
    "risc0-zkvm-3.0.6/src/host/recursion/prove/mod.rs": (
        "Distinct po2-selected lift and ordinary join programmes; left accumula"
        "tor, right lift and join output/scratch overlap; no identity/Groth16/P"
        "oVW requested"
    ),
    "risc0-circuit-rv32im-4.0.5/src/prove/hal/mod.rs": (
        "Per-segment HAL, preflight, witness and proof polynomial buffers; rows/cols allocations"
    ),
    "risc0-circuit-recursion-4.0.5/src/prove/witgen.rs": (
        "Concurrent ctrl/data/accum/global arrays sized by recursion programme "
        "rows, plus raw preflight and proof buffers; not only VM segment size"
    ),
}
inputs = {
    "source_log": str(log.relative_to(P)),
    "source_log_sha256": sha(log),
    "source_log_complete": True,
    "events": events,
    "base_segments": base,
    "recursion_operations": operations,
    "recursion_handoff_seconds": gaps,
    "observed_segment_block_seconds": seconds(events["preflight"][0], events["lift_start"][0]),
    "observed_recursion_block_seconds": seconds(events["lift_start"][0], events["join_end"][-1]),
    "guarded_pipeline_seconds": resource["wall_seconds"],
    "SDK_combined_seconds": receipt["pipeline_including_recursion_seconds"],
    "host_self_verify_seconds": receipt["self_verify_seconds"],
    "fresh_verifier_seconds": load(N / "evidence/verify.result.json")["seconds"],
    "combined_unattributed_guarded_residual_seconds": residual,
    "scope_notes": [
        (
            "Initialisation/loading plus guest execution occurs before first prefli"
            "ght; individual durations unavailable."
        ),
        (
            "Preflight/core boundaries measured, but core-to-next-boundary includes"
            " verification, I/O, hooks and on last segment Composite verification."
        ),
        (
            "Lift/join begin-to-finished includes their internal work; subsequent i"
            "ntegrity checks and bookkeeping occupy handoff gaps."
        ),
        (
            "Final receipt construction/IPC/save/teardown not individually instrume"
            "nted. Residual jointly covers work outside observed segment+recursion "
            "block, including self-verification. Do not split it into invented timi"
            "ngs."
        ),
        (
            "UTC log intervals and monotonic guarded duration have minor capture/cl"
            "ock differences; residual is descriptive, not an exact pure phase time"
            "r."
        ),
        (
            "One successful enrolment sample; no statistical confidence interval, p"
            "ercentile or throughput inference."
        ),
    ],
    "source_review": {
        str((crate / name).relative_to(P)): {"sha256": sha(crate / name), "finding": note}
        for name, note in source_notes.items()
    },
}
save("cost-model-inputs.json", inputs)
exe = load(R / "evidence/execution.result.json")
resources = load(R / "evidence/execution.json")
preflight = load(R / "evidence/preflight.result.json")
cfg = load(R / "config.json")
counts = {int(k): v for k, v in exe.get("segment_size_distribution", {}).items()}
segments = sum(counts.values())
assert segments == exe["segments"]
max_gap = max(gaps)
rates = {
    "base_po17": max(x["combined_seconds"] for x in base),
    "lift_po17": max(x["seconds"] for x in operations if x["kind"] == "lift") + max_gap,
    "join": max(x["seconds"] for x in operations if x["kind"] == "join") + max_gap,
}
# A smaller terminal segment, if any, uses a labelled po17 proxy; never pretend it was measured.
matched = set(counts) == {17}
components = {
    "base_segments_seconds": segments * rates["base_po17"],
    "lifts_seconds": segments * rates["lift_po17"],
    "joins_seconds": max(segments - 1, 0) * rates["join"],
    "guest_execution_seconds_proxy": exe["execution_seconds"],
    "one_time_initialisation_finalisation_allowance_seconds": 10.0,
}
subtotal = sum(components.values())
uncertainty = subtotal * cfg["cost_uncertainty_fraction"]
conservative = subtotal + uncertainty
memory = {
    "enrolment_measured_cgroup_peak_bytes": resource["cgroup_memory_peak_bytes"],
    "ceiling_bytes": 2**31,
    "enrolment_peak_is_CredValid_upper_bound": False,
    "retained_storage": (
        "Default proving run retains all serialised segment files via Session F"
        "ileSegmentRefs. Counts grow to S; page cache is charged to cgroup. Pre"
        "flight discards callback assets and does not measure this retained pro"
        "ving storage."
    ),
    "base_phase": (
        "One decoded segment/preflight/witness/proof buffer set at a time plus "
        "S increasing retained segment receipts, metadata, host, executor state"
        ", allocator cache and file cache; deserialisation can overlap file byt"
        "es and decoded data."
    ),
    "recursion_phase": (
        "All Composite segment receipts and Session refs remain live. Accumulat"
        "ed left Succinct and newly lifted right coexist with join witness/poly"
        "nomial buffers/output; recursion ctrl/data/accum/global arrays coexist"
        ". Sequential operations do not mean zero retention."
    ),
    "unknowns": (
        "No per-segment serialised sizes, retained-receipt sum or phase-specifi"
        "c concurrent working-set bound was measured for CredValid. Enrolment p"
        "eak and execution RSS cannot bound these quantities."
    ),
    "aggregate_bound_established": False,
    "known_hard_incompatibility": None,
    "decision": (
        "Unresolved memory headroom; do not assert a 2 GiB upper bound. Time in"
        "dependently excludes launch."
    ),
}
checks = {
    "execution_success": exe.get("accepted") is True,
    "exact_journal": exe.get("journal_matches_expected") is True,
    "execution_resources": resources["status"] == "pass",
    "supported_sizes": bool(counts)
    and all(k in preflight["supported_segment_po2"] for k in counts),
    "parameters_compatible": preflight["configuration_compatible"],
    "conservative_time_fits": conservative <= 600,
    "all_segment_types_measured": matched,
    "memory_admitted": memory["aggregate_bound_established"],
}
record = {
    "package": cfg["package"],
    "actual_partition": counts,
    "segments": segments,
    "workload": {
        "base_segment_proofs": segments,
        "lifts": segments,
        "joins": max(segments - 1, 0),
        "additional_recursion_operations": 0,
        "additional_recursion_basis": (
            "No guest receipt-verification assumptions, Keccak coprocessor, PoVW or"
            " Groth16; unchanged software-hash guest."
        ),
    },
    "rates_seconds": rates,
    "rate_selection": (
        "Maximum observed sample for each matching operation type, plus maximum"
        " observed recursion handoff separately on every lift/join."
    ),
    "all_segment_types_measured": matched,
    "unmatched_type_policy": (
        "Smaller final segment uses po17 as conservative engineering proxy only"
        ", not an established timing bound; unsupported extrapolation cannot ad"
        "mit a run."
    ),
    "components_before_uncertainty": components,
    "subtotal_seconds": subtotal,
    "uncertainty_fraction": cfg["cost_uncertainty_fraction"],
    "uncertainty_seconds": uncertainty,
    "conservative_estimate_seconds": conservative,
    "deadline_seconds": 600,
    "estimate_interpretation": (
        "Engineering extrapolation, not measured CredValid proving time or guar"
        "anteed upper bound. Explicit 50% allowance for host load/cache, longer"
        " repeated workload and unobserved bookkeeping. 10s initialisation/fina"
        "lisation envelope is an assumption; build excluded. Useful for rejecti"
        "ng this budget, not proving exact runtime."
    ),
    "memory": memory,
    "memory_admitted": checks["memory_admitted"],
    "checks": checks,
    "proof_admitted": all(checks.values()),
    "reason": (
        "Forecast exceeds whole-pipeline deadline; preserve final attempt. Memo"
        "ry upper bound also unresolved."
    ),
    "proofs_launched": 0,
    "cumulative_attempts_used": 2,
    "remaining": 1,
    "application_targets": {
        "generation_p95_seconds": 30,
        "end_to_end_p95_seconds": 45,
        "experimental_deadline_seconds": 600,
        "assessment": (
            "Present two-thread CPU configuration is unlikely to meet proposed KYC "
            "targets; fragment forecast is far beyond them, not a measured p95 or c"
            "omplete authentication result."
        ),
    },
}
save("admission.result.json", record)
if not record["proof_admitted"]:
    save(
        "STOP.json",
        {
            "package": cfg["package"],
            "reason": record["reason"],
            "execution_runs": 1,
            "proof_attempts_this_package": 0,
            "cumulative_attempts_used": 2,
            "remaining": 1,
            "package_closed": True,
        },
    )
    ledger = load(R / "evidence/cumulative_attempt_ledger.json")
    ledger.update(
        package_closed=True,
        outcome="execution_preflight_only_proof_not_admitted",
        admission_record="evidence/admission.result.json",
        admission_sha256=sha(R / "evidence/admission.result.json"),
    )
    save("cumulative_attempt_ledger.json", ledger)
print(
    json.dumps(
        {
            "segments": segments,
            "partition": counts,
            "rates_seconds": rates,
            "subtotal_seconds": subtotal,
            "conservative_seconds": conservative,
            "proof_admitted": record["proof_admitted"],
            "remaining": 1,
        }
    )
)
