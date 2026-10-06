"""Two paired probes, twelve differential cases and two constant refusals.

No hidden batch or retry. The first trace is released before the second generation.
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
D = P / "docs/data/s3_mldsa_butterfly_composition_pilot_1"
sys.path.insert(0, str(P))

from experiments.mldsa_butterfly_composition_1.candidate import (
    MAX,
    MIN,
    Q,
    baseline,
    forward,
    schedule_fragment,
)
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import GATE, HEADER, Emitter, Limits, evaluate
from pqdid.circuits.scalar_ring import Domain, Scalar
from tests.reference.scalar_oracle import floor_pair
from tests.reference.signature_oracle import observed

STARTED = time.monotonic()
RECORD = {"profile": "experimental-forward-butterfly-q-v1", "passed": False, "invocations": []}
CG = Path("/sys/fs/cgroup") / next(
    row[3:].lstrip("/")
    for row in Path("/proc/self/cgroup").read_text().splitlines()
    if row.startswith("0::")
)


def save():
    (D / "pilot-result.json").write_text(json.dumps(RECORD, indent=2) + "\n")


def begin(name, kind):
    if len(RECORD["invocations"]) >= 16:
        raise RuntimeError("sixteen-invocation ceiling")
    row = {"case": name, "kind": kind, "status": "started"}
    RECORD["invocations"].append(row)
    save()
    return row


def poll():
    if time.monotonic() - STARTED >= 11:
        raise TimeoutError("11-second inner pilot deadline; no retry")
    if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024 > 134217728:
        raise MemoryError("128MiB arithmetic process-RSS ceiling")


def memory():
    return {
        "python_process_high_water_RSS_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        * 1024,
        "cgroup_memory_peak_so_far_bytes": int((CG / "memory.peak").read_text()),
    }


def generate(composed):
    poll()
    row = begin("G2-two-node-fragment" if composed else "G1-single-butterfly", "generation-probe")
    private_bits = 194 if composed else 130
    row.update(
        workload="two-node schedule fragment" if composed else "single forward butterfly",
        twiddles=[4808194, 3765607] if composed else [4808194],
        components=[],
    )
    started = time.perf_counter()
    e = Emitter(
        private_bits,
        limits=Limits(max_gates=2_000_000, max_output_bytes=8388608, max_seconds=10),
        public_data=(
            "S3-MLDSA-BUTTERFLY-COMPOSITION-PILOT-1;paired;" + row["case"] + ";not-BC1"
        ).encode(),
    )
    values = tuple(
        Scalar(w.from_serialised(e, e.inputs[start : start + 64]), Domain.NTT)
        for start in range(0, private_bits - 2, 64)
    )
    outputs = []
    for label, function in (("baseline", baseline), ("candidate", forward)):
        before = asdict(e.counts)
        first_gate = e.counts.gates
        phase = []
        component_started = time.perf_counter()
        scope = Scope(e, active=e.inputs[-2])
        scope.rejected = e.inputs[-1]
        if composed:
            output = schedule_fragment(scope, values, function, phases=phase)
        else:
            output = (function(scope, values[0], values[1], 4808194, phases=phase),)
        seconds = time.perf_counter() - component_started
        after = asdict(e.counts)
        counts = {key: after[key] - before[key] for key in ("xor", "and_", "not_")}
        row["components"].append(
            {
                "name": label,
                "private_input_bits": private_bits,
                "complete": True,
                "counts": counts,
                "total_gates": sum(counts.values()),
                "first_gate_offset": first_gate,
                "end_gate_offset": e.counts.gates,
                "generation_and_counting_seconds": seconds,
                "phases_global_gate_offsets": phase,
                "output_words_by_node": [
                    [
                        [bit.index for bit in node.left.value],
                        [bit.index for bit in node.right.value],
                    ]
                    for node in output
                ],
                "validity_wires": [node.valid.index for node in output],
                **memory(),
            }
        )
        outputs.append(output)
        save()
        poll()
    circuit = e.finish(e.and_(outputs[0][-1].valid, outputs[1][-1].valid))
    for component in row["components"]:
        left = HEADER.size + GATE.size * component["first_gate_offset"]
        right = HEADER.size + GATE.size * component["end_gate_offset"]
        component["gate_segment_sha256"] = hashlib.sha256(
            memoryview(circuit.serialised)[left:right]
        ).hexdigest()
    assert circuit.counts.gates == 1 + sum(x["total_gates"] for x in row["components"])
    assert circuit.counts.and_ == 1 + sum(x["counts"]["and_"] for x in row["components"])
    row.update(
        status="pass",
        complete=True,
        seconds=time.perf_counter() - started,
        counts=asdict(circuit.counts),
        total_gates=circuit.counts.gates,
        fingerprint=circuit.fingerprint,
        generation_seconds=circuit.generation_seconds,
        trace_bytes=circuit.serialised_bytes,
        extra_harness_gates=1,
        extra_harness_ANDs=1,
        test_equality_gates=0,
        aggregate_retained_trace_bytes=circuit.retained_trace_bytes,
        **memory(),
    )
    assert row["aggregate_retained_trace_bytes"] <= 8388608
    save()
    return circuit, outputs, scope, values, e


def oracle(a, b, zeta, active, rejected):
    """Exact host integers and independent Fraction/floor, not circuit reduction."""
    product = zeta * b
    p = floor_pair(product, Q)[1]
    right, left = a - p, a + p
    fits = all(MIN <= value <= MAX for value in (product, right, left))
    valid = not rejected and (not active or fits)
    words = (floor_pair(left, Q)[1], floor_pair(right, Q)[1]) if active and valid else (0, 0)
    return words, valid


def differential(record, name, inputs, active=1, rejected=0):
    poll()
    row = begin(name, "differential-case")
    started = time.perf_counter()
    circuit, outputs, _, _, _ = record
    witness = b"".join(x.to_bytes(8, "big", signed=True) for x in inputs)
    witness += bytes([(active << 7) | (rejected << 6)])
    first_words, first_valid = oracle(*inputs[:2], 4808194, active, rejected)
    expected_words, expected_flags = list(first_words), [int(first_valid)]
    if len(inputs) == 3:
        second_words, second_valid = oracle(
            first_words[0], inputs[2], 3765607, active, not first_valid
        )
        expected_words.extend(second_words)
        expected_flags.append(int(second_valid))
    result = evaluate(circuit, witness, max_seconds=2, max_wires=2_000_196)
    values, _, flags = observed(
        circuit,
        witness,
        words=tuple(
            word
            for core in outputs
            for node in core
            for word in (node.left.value, node.right.value)
        ),
        flags=tuple(node.valid for core in outputs for node in core),
    )
    assert values == tuple(expected_words * 2)
    assert flags == tuple(expected_flags * 2)
    assert result.output == expected_flags[-1]
    assert all(0 <= value < Q for value in values)
    row.update(
        status="pass",
        input_signed64=inputs,
        active=active,
        prior_rejected=rejected,
        expected_words=expected_words,
        expected_validity_by_node=expected_flags,
        baseline_words=list(values[: len(expected_words)]),
        candidate_words=list(values[len(expected_words) :]),
        baseline_validity=list(flags[: len(expected_flags)]),
        candidate_validity=list(flags[len(expected_flags) :]),
        expected_valid=bool(expected_flags[-1]),
        usable=bool(active and expected_flags[-1]),
        all_intermediate_and_final_outputs_canonical=True,
        seconds=time.perf_counter() - started,
        evaluator_seconds=result.seconds,
        **memory(),
    )
    save()
    poll()


def main():
    record = generate(False)
    cases = [
        ("D1-zero", (0, 0), 1, 0),
        ("D2-canonical-upper-wrap", (Q - 1, Q - 1), 1, 0),
        ("D3-negative-subtraction", (0, 1), 1, 0),
        ("D4-signed-negative-representatives", (-1, -1), 1, 0),
        ("D5-noncanonical-q-normalisation", (Q, Q), 1, 0),
        ("D6-signed-minimum-left", (MIN, 0), 1, 0),
        ("D7-product-upper-boundary", (0, MAX // 4808194), 1, 0),
        ("D8-product-overflow", (0, MAX // 4808194 + 1), 1, 0),
        ("D9-raw-addition-overflow", (MAX, 1), 1, 0),
        ("D10-inactive-invalid", (0, MAX // 4808194 + 1), 0, 0),
    ]
    for name, inputs, active, rejected in cases:
        differential(record, name, inputs, active, rejected)
    # Public refusal before any emission; reuse completed objects, no extra probe.
    _, _, scope, values, emitter = record
    for name, invalid in (("C1-negative-twiddle", -1), ("C2-noncanonical-twiddle", Q)):
        poll()
        row = begin(name, "invalid-constant-case")
        started = time.perf_counter()
        before = asdict(emitter.counts)
        refusals = []
        for function in (baseline, forward):
            try:
                function(scope, values[0], values[1], invalid)
            except ValueError as error:
                assert str(error) == "twiddle must be a public canonical integer modulo q"
                refusals.append(str(error))
            else:
                raise AssertionError("unsupported public constant accepted")
        assert asdict(emitter.counts) == before
        row.update(
            status="pass", refusals=refusals, gates_emitted=0, seconds=time.perf_counter() - started
        )
        save()
    # Release all first-probe references before constructing the second trace.
    del record, _, scope, values, emitter
    record = generate(True)
    differential(record, "D11-legal-schedule-composition", (Q - 1, 1, 4808195))
    differential(
        record, "D12-invalidity-propagates-to-next-stage", (0, MAX // 4808194 + 1, 4808195)
    )
    del record
    probes = [row for row in RECORD["invocations"] if row["kind"] == "generation-probe"]
    improved = all(
        p["components"][1]["total_gates"] < p["components"][0]["total_gates"]
        and p["components"][1]["counts"]["and_"] < p["components"][0]["counts"]["and_"]
        for p in probes
    )
    RECORD.update(
        passed=True,
        decision="supports-bounded-transform-experiment" if improved else "no-measured-improvement",
        total_invocations=16,
        generation_probes=2,
        differential_cases=12,
        invalid_constant_cases=2,
        circuit_generations=2,
        peak_retained_trace_bytes=max(p["aggregate_retained_trace_bytes"] for p in probes),
        traces_released_between_probes=True,
        total_seconds=time.monotonic() - STARTED,
        trace_retained_on_disk=False,
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
        if RECORD["invocations"] and RECORD["invocations"][-1]["status"] == "started":
            RECORD["invocations"][-1]["status"] = "failed"
        RECORD["passed"] = False
        save()
        raise
