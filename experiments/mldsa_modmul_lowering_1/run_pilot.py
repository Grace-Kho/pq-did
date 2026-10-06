"""Two paired generation probes, ten differential cases, four constant refusals.

Every input/factor/control combination is individually recorded. No hidden batch,
retry, native harness, proof or zkVM execution. Traces remain only in memory.
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
D = P / "docs/data/s3_mldsa_modmul_lowering_pilot_1"
sys.path.insert(0, str(P))

from experiments.mldsa_modmul_lowering_1.candidate import Q, baseline, ntt_mul_public_q
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import GATE, HEADER, Emitter, Limits, evaluate
from pqdid.circuits.scalar_ring import Domain, Scalar
from tests.reference.scalar_oracle import floor_pair
from tests.reference.signature_oracle import observed

STARTED = time.monotonic()
RECORD = {"profile": "experimental-public-modmul-q-v1", "passed": False, "invocations": []}
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


def generate(factor, retained):
    poll()
    row = begin(f"G-{factor}", "generation-probe")
    row.update(factor=factor, components=[])
    started = time.perf_counter()
    e = Emitter(
        66,
        limits=Limits(max_gates=2_000_000, max_output_bytes=8388608 - retained, max_seconds=10),
        public_data=f"S3-MLDSA-MODMUL-LOWERING-PILOT-1;paired;factor={factor};not-BC1".encode(),
    )
    value = Scalar(w.from_serialised(e, e.inputs[:64]), Domain.NTT)
    outputs = []
    for label, function in (("baseline", baseline), ("candidate", ntt_mul_public_q)):
        before = asdict(e.counts)
        first_gate = e.counts.gates
        phase = []
        component_started = time.perf_counter()
        scope = Scope(e, active=e.inputs[64])
        scope.rejected = e.inputs[65]
        output = function(scope, value, factor, phases=phase)
        seconds = time.perf_counter() - component_started
        after = asdict(e.counts)
        counts = {key: after[key] - before[key] for key in ("xor", "and_", "not_")}
        row["components"].append(
            {
                "name": label,
                "factor": factor,
                "private_input_bits": 66,
                "complete": True,
                "counts": counts,
                "total_gates": sum(counts.values()),
                "first_gate_offset": first_gate,
                "end_gate_offset": e.counts.gates,
                "generation_and_counting_seconds": seconds,
                "phases_global_gate_offsets": phase,
                "output_word_indices": [bit.index for bit in output.value.value],
                "validity_wire": output.valid.index,
                **memory(),
            }
        )
        outputs.append(output)
        save()
        poll()
    circuit = e.finish(e.and_(outputs[0].valid, outputs[1].valid))
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
        aggregate_retained_trace_bytes=retained + circuit.retained_trace_bytes,
        **memory(),
    )
    assert row["aggregate_retained_trace_bytes"] <= 8388608
    save()
    return circuit, outputs, scope, value, e


def main():
    records = {}
    retained = 0
    for factor in (4808194, 8347681):
        records[factor] = generate(factor, retained)
        retained += records[factor][0].retained_trace_bytes
    # No Cartesian product: these are ten individually counted input/factor cases.
    cases = [
        ("D1-zero", 4808194, 0, 1, 0),
        ("D2-unit", 4808194, 1, 1, 0),
        ("D3-upper", 4808194, Q - 1, 1, 0),
        ("D4-wrap", 4808194, 2, 1, 0),
        ("D5-inverse-unit", 8347681, 1, 1, 0),
        ("D6-inverse-upper", 8347681, Q - 1, 1, 0),
        ("D7-noncanonical-q", 4808194, Q, 1, 0),
        ("D8-negative", 4808194, -1, 1, 0),
        ("D9-inactive-invalid", 8347681, Q, 0, 0),
        ("D10-sticky-rejection", 8347681, 1, 1, 1),
    ]
    for name, factor, x, active, rejected in cases:
        poll()
        row = begin(name, "differential-case")
        started = time.perf_counter()
        circuit, outputs, _, _, _ = records[factor]
        witness = x.to_bytes(8, "big", signed=True) + bytes([(active << 7) | (rejected << 6)])
        expected_valid = not rejected and (not active or 0 <= x < Q)
        expected_word = floor_pair(factor * x, Q)[1] if active and expected_valid else 0
        result = evaluate(circuit, witness, max_seconds=2, max_wires=2_000_068)
        values, _, flags = observed(
            circuit,
            witness,
            words=tuple(output.value.value for output in outputs),
            flags=tuple(output.valid for output in outputs),
        )
        assert values == (expected_word, expected_word)
        assert flags == (int(expected_valid), int(expected_valid))
        assert result.output == int(expected_valid)
        row.update(
            status="pass",
            factor=factor,
            input_signed64=x,
            active=active,
            prior_rejected=rejected,
            expected_valid=expected_valid,
            baseline_valid=bool(flags[0]),
            candidate_valid=bool(flags[1]),
            expected_word=expected_word,
            baseline_word=values[0],
            candidate_word=values[1],
            usable=bool(active and expected_valid),
            seconds=time.perf_counter() - started,
            evaluator_seconds=result.seconds,
            **memory(),
        )
        save()
        poll()

    # Reuse a completed probe's objects. Argument rejection precedes any emission;
    # no third emitter or extra generation is hidden in these four named cases.
    _, _, scope, value, e = records[4808194]
    for name, invalid in (
        ("C1-negative-factor", -1),
        ("C2-factor-q", Q),
        ("C3-boolean-factor", True),
        ("C4-private-factor", e.inputs[0]),
    ):
        poll()
        row = begin(name, "invalid-constant-case")
        started = time.perf_counter()
        counts_before = asdict(e.counts)
        refusals = []
        for function in (baseline, ntt_mul_public_q):
            try:
                function(scope, value, invalid)
            except ValueError as error:
                assert str(error) == "factor must be a public canonical integer modulo q"
                refusals.append(str(error))
            else:
                raise AssertionError("unsupported public constant accepted")
        assert asdict(e.counts) == counts_before
        row.update(
            status="pass",
            refusals=refusals,
            gates_emitted=0,
            seconds=time.perf_counter() - started,
        )
        save()
    probes = RECORD["invocations"][:2]
    improved = all(
        p["components"][1]["total_gates"] < p["components"][0]["total_gates"]
        and p["components"][1]["counts"]["and_"] < p["components"][0]["counts"]["and_"]
        for p in probes
    )
    RECORD.update(
        passed=True,
        decision="merits-bounded-composition" if improved else "no-measured-improvement",
        total_invocations=16,
        generation_probes=2,
        differential_cases=10,
        invalid_constant_cases=4,
        circuit_generations=2,
        aggregate_retained_trace_bytes=retained,
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
