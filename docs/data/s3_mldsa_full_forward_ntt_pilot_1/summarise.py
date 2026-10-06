"""Bounded evidence assembly/cleanup only; never generates or evaluates a circuit."""

import json
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]


def read(path):
    return json.loads(path.read_text())


def main():
    state = (
        read(D / "pilot-state.json")
        if (D / "pilot-state.json").exists()
        else {
            "passed": False,
            "invocations": [],
            "completed_partitions": 0,
            "aggregate_emitted_gates": 0,
            "inflight_gate_reservation": 0,
            "counts": {"xor": 0, "and_": 0, "not_": 0},
        }
    )
    parts = [read(p) for p in sorted(D.glob("partition-*.json"))]
    complete = [p for p in parts if p["complete"]]
    entry_lanes, nodes, final_count = [], [], 0
    stages = {str(s): {"gates": 0, "and_": 0, "butterflies": 0} for s in range(8)}
    for row in complete:
        n = row["ordinal"]
        if n < 32:
            entry_lanes.extend(v[0] for v in row["work"])
        elif n < 96:
            s = str((n - 32) // 8)
            stages[s]["gates"] += row["gates"]
            stages[s]["and_"] += row["counts"]["and_"]
            stages[s]["butterflies"] += len(row["work"])
            nodes.extend(tuple(v[:3]) for v in row["work"])
        else:
            final_count += 1
    guards = read(D / "run-ledger.json")
    work_guards_pass = all(r["status"] == "pass" for r in guards if r["name"].startswith("batch-"))
    passed = state["passed"] and work_guards_pass
    if passed:
        assert len(complete) == len(parts) == 97
        assert [p["ordinal"] for p in parts] == list(range(97))
        assert entry_lanes == list(range(256)) and len(set(nodes)) == len(nodes) == 1024
        expected = {(s, g, u) for s in range(8) for g in range(1 << s) for u in range(128 >> s)}
        assert set(nodes) == expected and final_count == 1
        assert all(row["private_inputs"] == 16386 for row in parts)
        for previous, current in zip(parts, parts[1:], strict=False):
            assert previous["output_alias_sha256"] == current["input_alias_sha256"]
            assert previous["gate_offset"] + previous["gates"] == current["gate_offset"]
        assert parts[0]["gate_offset"] == 0
        assert sum(r["gates"] for r in parts) == state["aggregate_emitted_gates"]
        assert len(state["invocations"]) == 107
        assert all(r["status"] == "pass" for r in state["invocations"])
    # Preserve synthetic checkpoints as evidence; no ephemeral state remains.
    retained = []
    for path in sorted((D / "tmp").iterdir()):
        if path.name not in {"state.json", "frontier.bin", "state.json.new", "frontier.new"}:
            raise ValueError("unexpected temporary resource; retain for review")
        destination = D / ("retained-" + path.name)
        assert not destination.exists()
        path.replace(destination)
        retained.append(destination.name)
    ands = state["counts"]["and_"]
    projection = 5363104 + 960 * ((ands + 3) // 4) if passed else None
    summary = {
        "passed": passed,
        "host_partitioned_evaluation": True,
        "composition_accounted": passed,
        "monolithic_circuit_materialised": False,
        "canonical_BC1": False,
        "proof": False,
        "completed_partitions": len(complete),
        "entry_lane_count": len(entry_lanes),
        "butterfly_count": len(nodes),
        "final_boundaries": final_count,
        "stage_counts": stages,
        "aggregate_emitted_gates_or_charged_bound": state["aggregate_emitted_gates"],
        "unresolved_prefix_reserved_gates": state["inflight_gate_reservation"],
        "counts": state["counts"],
        "new_invocations": len(state["invocations"]),
        "total_invocations": 279 + len(state["invocations"]),
        "conditional_raw_view_auth_bytes": projection,
        "projection_assumption": "Unchanged480-round raw-view encoding, d_auth42632, "
        "this private-wire subgraph embeds unchanged; T_auth>=measured T_NTT. "
        "No claim for changed input classification, sharing or a compact proof profile.",
        "retained_synthetic_checkpoints": retained,
        "failure": state.get("failure"),
        "outer_work_guards_pass": work_guards_pass,
    }
    (D / "pilot-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    rows = []
    for part in parts:
        rows.append(
            f"| {part['ordinal']:02} | {part['gates']:,} | "
            f"{part['counts']['and_']:,} | {part['generation_seconds']:.6f} | "
            f"{'complete' if part['complete'] else 'incomplete'} |"
        )
    outcomes = "\n".join(
        f"| {r['id']} | {r['kind']} | {r['status']} | "
        f"{r.get('partitions_compared', r.get('refusal', 'counted generation'))} |"
        for r in state["invocations"]
        if r["kind"] != "generation-probe"
    )
    partition_table = "\n".join(rows)
    decision = (
        "Component composition/counting validated; NO-GO for integration with the "
        "unchanged raw-view proof encoding"
        if passed
        else "INCOMPLETE: no complete-transform or complete connected-count claim"
    )
    next_action = (
        "S3-COMPACT-AUTH-PROOF-PROFILE-REVIEW-1: a bounded source-only "
        "review of compact transcript candidates, exact relation/security "
        "obligations and KYC resource admission, before more circuit integration."
        if passed
        else "A bounded source-only review of the first recorded failure "
        "and remaining composition/resource gap, before any new execution request."
    )
    summary.update(decision=decision, next_recommendation=next_action)
    (D / "pilot-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    report = f"""

## Measured experiment outcome

**{decision}.** Completed partitions: {len(complete)}/97; entry lanes:
{len(entry_lanes)}/256; butterflies: {len(nodes)}/1,024; final boundaries: {final_count}/1.
New counted invocations: {len(state["invocations"])}/107;
cumulative **{279 + len(state["invocations"])}/386**. All individual generation
admissions, including any incomplete prefix, are in
[the invocation ledger](data/s3_mldsa_full_forward_ntt_pilot_1/pilot-state.json).
No retry or extra case was launched. Failure detail: `{state.get("failure")}`.

| Case | Kind | Outcome | Completed observations / refusal |
| --- | --- | --- | --- |
{outcomes}

All planned case IDs and exact inputs remain those in the sealed plan. Six case
records contain initial values, all256 uninterrupted reference and independent
Horner outputs, expected wrapper outputs and, when completed, actual outputs plus
canonical64 byte strings. They are `case-V0.json` through `case-V5.json` alongside
the [summary](data/s3_mldsa_full_forward_ntt_pilot_1/pilot-summary.json).
Completed evaluator calls: {state.get("evaluator_calls", 0)}; independent trace
passes: {state.get("observer_passes", 0)}. These are constituent observations of
six cases, not additional test combinations. Intermediate records include
canonical-prefix, unchanged unprocessed lanes, private active and sticky R checks.

## Counts and timings

Completed emitted opcode counts: XOR={state["counts"]["xor"]:,},
AND={ands:,}, NOT={state["counts"]["not_"]:,}.
Aggregate emitted gates/charged conservative bound:
**{state["aggregate_emitted_gates"]:,}**. Any unresolved interrupted prefix retains
an additional **{state["inflight_gate_reservation"]:,}** reserved gates.
Only a passed complete result with zero unresolved prefix permits a connected
logical full-transform count. No full reference-circuit saving is measured.

| Partition ordinal | Total gates | AND gates | Generation/counting seconds | Completion |
| --- | ---: | ---: | ---: | --- |
{partition_table}

Generation/counting: **{state.get("generation_seconds", 0):.9f} s**;
ordinary circuit evaluation: **{state.get("evaluation_seconds", 0):.9f} s**;
independent trace observation: **{state.get("observer_seconds", 0):.9f} s**;
uninterrupted reference plus Horner: **{state.get("reference_seconds", 0):.9f} s**.
These are distinct measured activities, not proof-generation or statistical
latency measurements. Per-batch guards also include source checks, state transfer,
alias accounting, measurement writes and process overhead. Each partition record
contains peak-so-far process RSS/cgroup observations and retained trace bytes;
maximum retained trace is **{state.get("peak_retained_trace_bytes", 0):,} bytes**.
No trace is written to disk. Source, unchanged inherited limits and complete
command/resource records accompany the invocation ledger. Retained synthetic
checkpoints: `{retained}`; temporary directory emptied without deleting failure evidence.

## Target implications and decision

The [KYC thresholds](benchmark_targets.md) are proposed, not agreed SLAs:
raw authentication proof≤10MiB, presentation≤12MiB, generation p95≤30s,
verification p95≤2s and end-to-end p95≤45s. Six synthetic component cases establish
none of those percentiles or complete-authentication costs.

Conditional projection, if this measured private-wire subgraph embeds unchanged
and the existing480-round raw-tape/raw-view proof representation is retained:
`P_auth = 5,363,104 + 960*ceil(T_auth/4)` for the recorded42,632-bit auth witness,
and `T_auth >= T_NTT` gives **{projection} bytes** when a complete count exists.
This is a conditional encoding calculation, never a generated proof or an
unconditional lower bound for a differently lowered authentication circuit.
Changed input visibility, cross-component simplification or a different compact
proof encoding require fresh accounting and security arguments. Unmeasured
inverse transforms, private products/accumulation, hashes, samplers, norms,
decomposition, hint linkage and the Merkle/disclosure relation are excluded.
No overlapping historical fragments are added. RISC Zero forecasts are unchanged.

For a successful result, this already rules out the route that simply retains
the measured subgraph and raw-view encoding under the proposed byte targets.
Arithmetic improvement alone is insufficient; prioritise the proof representation
decision over further integration. If incomplete, no such measured full-transform
conclusion is drawn; retain the partial evidence and diagnose the recorded cause.
One next action only: **{next_action}** It has not started.
Stages 2–3 remain open. ARITH-LOWER-001 still covers full-verifier/compiler
conformance; OC-REL/EXT/PRIV/BUDGET, adaptive Delta_tail, production security and
complete proof knowledge/privacy remain unresolved. No inverse experiment,
proof, zkVM execution, installation or activation occurred. CPU proving paused;
isolation safely stopped/unactivated; proof ledger two used/one unused.
"""
    with (P / "docs/stage3_mldsa_full_forward_ntt_pilot.md").open("a") as stream:
        stream.write(report)
    short = f"""

Full-forward pilot result: **{decision}**. Complete partitions {len(complete)}/97,
butterflies {len(nodes)}/1,024; {279 + len(state["invocations"])}/386 invocations.
[Measured report](stage3_mldsa_full_forward_ntt_pilot.md) separates host partitioned
evaluation, logical alias/count accounting and actual circuit/proof construction.
No canonical BC-1 adoption or full-authentication performance claim. No retry.
Next recommendation only: {next_action} Stages2–3/security obligations remain open;
isolation safely stopped/unactivated; proof ledger2used/1unused.
"""
    for name in ["status.md", "traceability.md", "spec_issues.md"]:
        with (P / "docs" / name).open("a") as stream:
            stream.write(short)
    print(
        json.dumps(
            {
                "summary": decision,
                "completed_partitions": len(complete),
                "new_invocations": len(state["invocations"]),
                "cleanup_complete": True,
            }
        )
    )


if __name__ == "__main__":
    main()
