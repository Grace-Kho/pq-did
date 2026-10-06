"""One generation probe, eight named cases; no retries, proofs or guest runs."""

# ruff: noqa: E402

import hashlib
import json
import os
import resource
import sys
import time
from dataclasses import asdict
from pathlib import Path

P = Path(__file__).resolve().parents[2]
D = P / "docs/data/s3_private_hint_lowering_pilot_1"
sys.path.insert(0, str(P))

from experiments.private_hint_lowering_1.candidate import decode_hints
from pqdid import bounded_mldsa as reference
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, Limits, evaluate
from tests.reference.signature_oracle import hint_encoding, observed

STARTED = time.monotonic()
RECORD = {"profile": "experimental-private-hints-v1", "passed": False, "invocations": []}


def save():
    (D / "pilot-result.json").write_text(json.dumps(RECORD, indent=2) + "\n")


def begin(name, kind):
    if len(RECORD["invocations"]) >= 9:
        raise RuntimeError("nine-invocation ceiling")
    row = {"case": name, "kind": kind, "status": "started"}
    RECORD["invocations"].append(row)
    save()
    return row


def poll():
    if time.monotonic() - STARTED >= 12:
        raise TimeoutError("12-second inner pilot deadline; stop without retry")


def main():
    fixtures = json.loads((P / "tests/fixtures/relations_vectors.json").read_text())
    fixture = next(x for x in fixtures["authentication"] if x["name"] == "alpha-42-old-002c")
    original = bytes.fromhex(fixture["witness"])
    assert len(original) == 5329
    hints = original[4308:4369]
    baseline = json.loads((P / "docs/data/stage3_hint_prefix_audit.json").read_text())["results"][0]
    cg = Path("/sys/fs/cgroup") / next(
        row[3:].lstrip("/")
        for row in Path("/proc/self/cgroup").read_text().splitlines()
        if row.startswith("0::")
    )
    probe = begin("complete-candidate-generation", "generation-probe")
    started = time.perf_counter()
    phases = []
    e = Emitter(
        42632,
        limits=Limits(max_gates=2_000_000, max_output_bytes=8 * 1024 * 1024, max_seconds=8),
        public_data=b"S3-PRIVATE-HINT-LOWERING-PILOT-1;standalone-active;not-BC-1",
    )
    scope = Scope(e)
    decoded = decode_hints(scope, e.inputs[34464:34952], phases=phases)
    circuit = e.finish(scope.output(()))
    probe.update(
        status="pass",
        complete=True,
        seconds=time.perf_counter() - started,
        counts=asdict(circuit.counts),
        total_gates=circuit.counts.gates,
        wires=circuit.counts.wires,
        fingerprint=circuit.fingerprint,
        generation_seconds=circuit.generation_seconds,
        trace_bytes=circuit.serialised_bytes,
        folded_operations=list(circuit.folded_operations),
        python_process_high_water_RSS_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        * 1024,
        cgroup_memory_peak_at_generation_bytes=int((cg / "memory.peak").read_text()),
        phases=phases,
        output_signed64_rewiring_extra_gates=0,
        test_comparison_gates=0,
    )
    assert circuit.counts.and_ < baseline["counts"]["and_"]
    RECORD["comparison"] = {
        "baseline_complete": False,
        "baseline_gates": baseline["gates"],
        "baseline_and_gates": baseline["counts"]["and_"],
        "candidate_complete": True,
        "prefix_and_minus_complete_candidate": baseline["counts"]["and_"] - circuit.counts.and_,
        "scope": "Exact original source continuation has at least its recorded prefix cost; "
        "this difference is not a matched full-baseline measurement or auth reduction.",
    }
    save()
    poll()
    cases = [
        ("original-valid", hints, True),
        ("all-zero-valid", bytes(61), True),
        ("decreasing-endpoints", bytes(55) + bytes([1, 0, 0, 0, 0, 0]), False),
        ("endpoint-over-55", bytes(55) + bytes([56] * 6), False),
        ("duplicate-within-row", bytes([7, 7]) + bytes(53) + bytes([2] * 6), False),
        ("descending-within-row", bytes([9, 7]) + bytes(53) + bytes([2] * 6), False),
        ("nonzero-unused-padding", bytes([1]) + bytes(60), False),
        (
            "capacity55-position255-cross-row-repeat",
            hint_encoding((tuple(range(53)) + (255,), (), (), (), (), (255,))),
            True,
        ),
    ]
    words = tuple(word for row in decoded.hints for word in row)
    for name, encoded, expected_valid in cases:
        poll()
        row = begin(name, "differential-case")
        started = time.perf_counter()
        try:
            expected = reference._decode_hints(encoded)
            reference_valid = True
        except reference._InvalidSignature:
            expected, reference_valid = None, False
        witness = original[:4308] + encoded + original[4369:]
        result = evaluate(circuit, witness, max_seconds=1, max_wires=2_042_634)
        observed_words, _, flags = observed(circuit, witness, words=words, flags=(decoded.valid,))
        usable = bool(result.output)
        assert reference_valid == expected_valid == usable == bool(flags[0])
        assert all(value in (0, 1) for value in observed_words)
        if usable:
            assert observed_words == tuple(value for polynomial in expected for value in polynomial)
        else:
            assert not any(observed_words), "candidate promises unusable zeroed rejected output"
        row.update(
            status="pass",
            reference_valid=reference_valid,
            candidate_valid=usable,
            decoded_values_compared=1536 if usable else 0,
            unusable_outputs_zeroed=not usable,
            input_hint_sha256=hashlib.sha256(encoded).hexdigest(),
            output_values_sha256=hashlib.sha256(bytes(observed_words)).hexdigest(),
            seconds=time.perf_counter() - started,
            evaluator_seconds=result.seconds,
            wire_storage_bytes=result.wire_storage_bytes,
        )
        save()
        poll()
    RECORD.update(
        passed=True,
        fixture="alpha-42-old-002c",
        total_invocations=len(RECORD["invocations"]),
        probe_invocations=1,
        differential_invocations=8,
        total_seconds=time.monotonic() - STARTED,
        trace_retained_on_disk=False,
        available_cpus=sorted(os.sched_getaffinity(0)),
        proof=False,
        zkvm_execution=False,
    )
    save()
    print(json.dumps({"passed": True, "invocations": 9, "gates": circuit.counts.gates}))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        RECORD["failure"] = {"type": type(error).__name__, "message": str(error)[:2000]}
        if RECORD["invocations"] and RECORD["invocations"][-1]["status"] == "started":
            RECORD["invocations"][-1]["status"] = "failed"
        save()
        raise
