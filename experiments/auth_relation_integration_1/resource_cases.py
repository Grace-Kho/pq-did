"""Focused resource/completion cases on tiny fixtures, not actual ceiling breaches."""

import hashlib

from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit

from .coverage import validate_coverage
from .stream import R1CSSink, check_stream


def _fails(call, exception=ValueError):
    try:
        call()
    except exception:
        return
    raise AssertionError("required rejection was not observed")


def run_case(case_id, meter):
    parts = (("a", 0, 2, 0, 2), ("b", 2, 4, 2, 4))
    if case_id == "G-01":
        result = validate_coverage(parts, rows=4, variables=4)
        assert result["overlap"] == 0
    elif case_id == "G-02":
        _fails(lambda: validate_coverage((parts[1],), rows=4, variables=4))
    elif case_id == "G-03":
        _fails(lambda: validate_coverage((parts[0], parts[0]), rows=4, variables=4))
    elif case_id in {"G-04", "G-05", "G-06", "G-08"}:
        sink = R1CSSink(
            hashlib.sha256(b"resource-fixture").digest(),
            charge=lambda kind, count: meter(count),
            witness_bits=b"\x01",
            max_rows=10,
            max_assignment_wires=2 if case_id == "G-06" else 10,
        )
        emitter = Emitter(
            1,
            mode="stream",
            sink=sink,
            public_data=b"resource-fixture",
            limits=Limits(
                max_gates=1 if case_id == "G-05" else 5, max_output_bytes=4096, max_seconds=2
            ),
        )
        if case_id == "G-04":
            emitter.not_(emitter.inputs[0])
            _fails(lambda: sink.completed(), RuntimeError)
        elif case_id == "G-05":
            emitter.not_(emitter.inputs[0])
            _fails(lambda: emitter.not_(emitter.inputs[0]), ResourceLimit)
            _fails(lambda: sink.completed(), RuntimeError)
        elif case_id == "G-06":
            _fails(lambda: emitter.not_(emitter.inputs[0]), RuntimeError)
            _fails(lambda: check_stream(sink), RuntimeError)
        else:
            _fails(lambda: sink.write(b"truncated"), ValueError)
            _fails(lambda: sink.completed(), RuntimeError)
    elif case_id == "G-07":
        from . import run as guard

        assert guard.output_role(guard.D / "cases" / "fixture.json")[0] == "evidence"
        assert guard.output_role(guard.N / "scratch" / "compiler.o")[0] == "compiler-artifact"
        assert guard.output_role(guard.N / "scratch" / "compiler.log")[0] == "evidence"
        assert guard.output_role(guard.N / "build" / "unregistered.bin")[0] == "evidence"
    else:
        raise ValueError("unknown resource case")
    return {
        "coverage": "small isolated resource/stream metadata fixture",
        "expected": "pass",
        "actual_resource_exhaustion": False,
        "full_relation": False,
    }
