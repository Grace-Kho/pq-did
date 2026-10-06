"""Four counted generation probes and twelve complete schedule cases, no retry.

Each case compares one candidate with the reference's two serial partitions and
an independent integer oracle. The 36 evaluator calls are constituents of those
twelve cases, not additional input combinations. No full transform is generated.
"""

# ruff: noqa: E402

import hashlib
import json
import os
import resource
import sys
import time
from dataclasses import asdict
from pathlib import Path

resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
P = Path(__file__).resolve().parents[2]
D = P / "docs/data/s3_mldsa_forward_ntt_stage_pilot_1"
sys.path.insert(0, str(P))

from experiments.mldsa_forward_ntt_stage_1.candidate import (
    FIRST,
    MAX,
    SECOND,
    Q,
    fragment,
    reference_partition,
)
from pqdid.bounded_mldsa import _ZETAS
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import GATE, HEADER, Emitter, Limits, evaluate
from pqdid.circuits.scalar_ring import Domain, Scalar
from tests.reference.scalar_oracle import floor_pair
from tests.reference.signature_oracle import observed

MIN = -(1 << 63)
STARTED = time.monotonic()
RECORD = {"profile": "experimental-forward-four-lane-v1", "passed": False, "invocations": []}
CG = Path("/sys/fs/cgroup") / next(
    row[3:].lstrip("/")
    for row in Path("/proc/self/cgroup").read_text().splitlines()
    if row.startswith("0::")
)
CURRENT = None


def save():
    data = json.dumps(RECORD, indent=2) + "\n"
    if len(data.encode()) >= 1048576:
        raise RuntimeError("per-file evidence ceiling")
    (D / "pilot-result.json").write_text(data)


def begin(name, kind):
    global CURRENT
    if len(RECORD["invocations"]) >= 16:
        raise RuntimeError("sixteen-invocation ceiling")
    CURRENT = {"case": name, "kind": kind, "status": "started"}
    RECORD["invocations"].append(CURRENT)
    save()
    return CURRENT


def poll():
    if time.monotonic() - STARTED >= 11:
        raise TimeoutError("11-second inner deadline; no retry")
    if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024 > 134217728:
        raise MemoryError("128MiB arithmetic process-RSS ceiling")


def memory():
    return {
        "python_process_high_water_RSS_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        * 1024,
        "cgroup_memory_peak_so_far_bytes": int((CG / "memory.peak").read_text()),
    }


def generate(name, mode):
    poll()
    row = begin(name, "generation-probe")
    row.update(mode=mode, components=[])
    started = time.perf_counter()
    # Public construction provenance check belongs to this generation, not a
    # separate execution probe. No _ntt or other native verifier is run.
    for _name, _left, _right, zeta, index in (*FIRST, *SECOND):
        assert zeta == _ZETAS[index] == pow(1753, int(f"{index:08b}"[::-1], 2), Q)
    e = Emitter(
        258,
        mode="count" if mode == "count-comparison" else "materialised",
        limits=Limits(max_gates=2_000_000, max_output_bytes=8388608, max_seconds=10),
        public_data=f"S3-MLDSA-FORWARD-NTT-STAGE-PILOT-1;{name};not-BC1".encode(),
    )
    values = tuple(
        Scalar(w.from_serialised(e, e.inputs[i : i + 64]), Domain.NTT) for i in range(0, 256, 64)
    )
    labels = ("baseline", "fully-guarded", "candidate") if mode == "count-comparison" else (mode,)
    outputs = []
    for label in labels:
        before = asdict(e.counts)
        phases = []
        first_gate = e.counts.gates
        component_started = time.perf_counter()
        scope = Scope(e, active=e.inputs[-2])
        scope.rejected = e.inputs[-1]
        if label in {"reference-first", "reference-second"}:
            output = reference_partition(
                scope, values, second=label == "reference-second", phases=phases
            )
        else:
            output = fragment(scope, values, label, phases=phases)
        seconds = time.perf_counter() - component_started
        after = asdict(e.counts)
        counts = {key: after[key] - before[key] for key in ("xor", "and_", "not_")}
        row["components"].append(
            {
                "name": label,
                "private_input_bits": 258,
                "complete": True,
                "counts": counts,
                "total_gates": sum(counts.values()),
                "first_gate_offset": first_gate,
                "end_gate_offset": e.counts.gates,
                "generation_and_counting_seconds": seconds,
                "phases_global_gate_offsets": phases,
                "final_word_wire_indices": [[bit.index for bit in word] for word in output.words],
                "final_validity_wire": output.valid.index,
                **memory(),
            }
        )
        outputs.append(output)
        save()
        poll()
    joined = outputs[0].valid
    for output in outputs[1:]:
        joined = e.and_(joined, output.valid)
    circuit = e.finish(joined)
    if circuit.serialised is not None:
        for component in row["components"]:
            lo = HEADER.size + GATE.size * component["first_gate_offset"]
            hi = HEADER.size + GATE.size * component["end_gate_offset"]
            component["gate_segment_sha256"] = hashlib.sha256(
                memoryview(circuit.serialised)[lo:hi]
            ).hexdigest()
    extra = len(outputs) - 1
    assert circuit.counts.gates == extra + sum(c["total_gates"] for c in row["components"])
    assert circuit.counts.and_ == extra + sum(c["counts"]["and_"] for c in row["components"])
    assert circuit.retained_trace_bytes <= 8388608
    row.update(
        status="pass",
        complete=True,
        seconds=time.perf_counter() - started,
        counts=asdict(circuit.counts),
        total_gates=circuit.counts.gates,
        fingerprint=circuit.fingerprint,
        generation_seconds=circuit.generation_seconds,
        hypothetical_serialised_bytes=circuit.serialised_bytes,
        stored_bytes=circuit.stored_bytes,
        retained_trace_bytes=circuit.retained_trace_bytes,
        extra_harness_gates=extra,
        extra_harness_ANDs=extra,
        test_equality_gates=0,
        **memory(),
    )
    save()
    return circuit, outputs, row


def oracle(inputs, active, rejected):
    """Independent explicit A/B/C/D integer schedule, not the circuit scheduler."""
    state = list(inputs)
    nodes = []
    first_words = None
    # Independent indices/constants derivation, not FIRST/SECOND iteration.
    for left, right, index in ((0, 2, 1), (1, 3, 1), (0, 1, 2), (2, 3, 3)):
        zeta = pow(1753, int(f"{index:08b}"[::-1], 2), Q)
        a, b = state[left], state[right]
        raw_product = zeta * b
        p = floor_pair(raw_product, Q)[1]
        fits = all(MIN <= x <= MAX for x in (raw_product, a - p, a + p))
        rejected = bool(rejected or (active and not fits))
        valid = not rejected
        pair = [floor_pair(a + p, Q)[1], floor_pair(a - p, Q)[1]]
        if not active or rejected:
            pair = [0, 0]
        state[left], state[right] = pair
        nodes.append({"words": pair, "valid": int(valid)})
        if len(nodes) == 2:
            first_words = list(state)
    return {
        "nodes": nodes,
        "first_words": first_words,
        "first_valid": nodes[1]["valid"],
        "final_words": list(state) if active and not rejected else [0, 0, 0, 0],
        "final_valid": int(not rejected),
    }


def observe(record, inputs, active, rejected):
    poll()
    started = time.perf_counter()
    circuit, outputs, _row = record
    assert len(outputs) == 1
    output = outputs[0]
    witness = b"".join(x.to_bytes(8, "big", signed=True) for x in inputs)
    witness += bytes([(active << 7) | (rejected << 6)])
    result = evaluate(circuit, witness, max_seconds=2, max_wires=2_000_260)
    words, _, flags = observed(
        circuit,
        witness,
        words=(
            *output.words,
            *(word for node in output.nodes for word in (node.left.value, node.right.value)),
        ),
        flags=(output.valid, *(node.valid for node in output.nodes)),
    )
    assert result.output == flags[0]
    assert all(0 <= word < Q for word in words)
    value = {
        "words": list(words[:4]),
        "valid": flags[0],
        "nodes": [
            {"words": list(words[4 + 2 * i : 6 + 2 * i]), "valid": flags[1 + i]}
            for i in range(len(output.nodes))
        ],
        "all_observed_words_canonical": True,
        "seconds": time.perf_counter() - started,
        "evaluator_seconds": result.seconds,
        **memory(),
    }
    poll()
    return value


def main():
    global CURRENT
    count_record = generate("G1-complete-count-comparison", "count-comparison")
    counts = count_record[2]["components"]
    del count_record
    record = generate("G2-complete-candidate", "candidate")
    assert record[2]["components"][0]["counts"] == counts[2]["counts"]
    RECORD["candidate_materialised_count_identity"] = True
    cases = [
        ("D1-zero", (0, 0, 0, 0), 1, 0),
        ("D2-asymmetric-lane-order", (0, 1, 2, 3), 1, 0),
        ("D3-canonical-upper", (Q - 1,) * 4, 1, 0),
        ("D4-both-modular-corrections", (Q - 1, 0, 1, Q - 1), 1, 0),
        ("D5-negative-representatives", (-1, -2, -3, -4), 1, 0),
        ("D6-positive-noncanonical", (Q, Q + 1, 2 * Q, 2 * Q + 1), 1, 0),
        ("D7-signed-minimum-lefts", (MIN, MIN, 0, 0), 1, 0),
        ("D8-product-upper-boundaries", (0, 0, MAX // 4808194, MAX // 4808194), 1, 0),
        ("D9-first-node-product-overflow", (0, 0, MAX // 4808194 + 1, 1), 1, 0),
        ("D10-second-node-subtraction-overflow", (1, MIN, 1, 1), 1, 0),
        ("D11-inactive-invalid", (0, 0, MAX // 4808194 + 1, 1), 0, 0),
        ("D12-prior-rejection", (0, 1, 2, 3), 1, 1),
    ]
    rows = []
    for name, inputs, active, rejected in cases:
        row = begin(name, "differential-case")
        expected = oracle(inputs, active, rejected)
        row.update(inputs=list(inputs), active=active, prior_rejected=rejected, expected=expected)
        rows.append(row)
        save()
        value = observe(record, inputs, active, rejected)
        row["candidate"] = value
        assert value["nodes"] == expected["nodes"]
        assert (
            value["words"] == expected["final_words"] and value["valid"] == expected["final_valid"]
        )
        row["status"] = "candidate-complete-reference-pending"
        save()
    del record
    # These are serial partitions of the same reference/cases, not new cases.
    record = generate("G3-reference-first-stage", "reference-first")
    first_counts = record[2]["components"][0]["counts"]
    for row in rows:
        CURRENT = row
        value = observe(record, row["inputs"], row["active"], row["prior_rejected"])
        row["reference_first"] = value
        expected = row["expected"]
        assert value["nodes"] == expected["nodes"][:2]
        assert (
            value["words"] == expected["first_words"] and value["valid"] == expected["first_valid"]
        )
        row["status"] = "first-reference-partition-complete"
        save()
    del record
    record = generate("G4-reference-second-stage", "reference-second")
    second_counts = record[2]["components"][0]["counts"]
    assert all(first_counts[k] + second_counts[k] == counts[0]["counts"][k] for k in first_counts)
    RECORD["partition_count_identity"] = True
    for row in rows:
        CURRENT = row
        previous = row["reference_first"]
        value = observe(record, previous["words"], row["active"], 1 - previous["valid"])
        row["reference_second"] = value
        expected = row["expected"]
        assert value["nodes"] == expected["nodes"][2:]
        assert value["words"] == expected["final_words"] == row["candidate"]["words"]
        assert value["valid"] == expected["final_valid"] == row["candidate"]["valid"]
        row.update(
            status="pass",
            seconds=sum(
                row[key]["seconds"] for key in ("candidate", "reference_first", "reference_second")
            ),
            partial_observations=3,
            complete_schedule_compared=True,
            usable=bool(row["active"] and value["valid"]),
        )
        save()
    del record
    probes = [row for row in RECORD["invocations"] if row["kind"] == "generation-probe"]
    assert len(probes) == 4 and len(rows) == 12
    improved = (
        counts[2]["total_gates"] < counts[0]["total_gates"]
        and counts[2]["counts"]["and_"] < counts[0]["counts"]["and_"]
    )
    RECORD.update(
        passed=True,
        decision="supports-bounded-full-forward-experiment"
        if improved
        else "no-measured-improvement",
        total_invocations=16,
        generation_probes=4,
        differential_cases=12,
        circuit_generations=4,
        partitions_complete=True,
        partition_nodes=[["A", "B"], ["C", "D"]],
        partition_overlap=[],
        missing_nodes=[],
        evaluator_calls=36,
        independent_trace_observer_passes=36,
        peak_retained_trace_bytes=max(row["retained_trace_bytes"] for row in probes),
        traces_released_between_probes=True,
        trace_retained_on_disk=False,
        total_seconds=time.monotonic() - STARTED,
        available_cpus=sorted(os.sched_getaffinity(0)),
        **memory(),
    )
    poll()
    save()
    print(json.dumps({"passed": True, "invocations": 16, "decision": RECORD["decision"]}))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        RECORD["failure"] = {"type": type(error).__name__, "message": str(error)[:2000]}
        if hasattr(error, "progress"):
            RECORD["failure"]["capped_prefix"] = error.progress
        if CURRENT is not None:
            CURRENT["status"] = "failed"
        RECORD["passed"] = False
        save()
        raise
