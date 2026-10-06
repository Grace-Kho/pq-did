"""Hand-audited traces, folding restrictions, modes and deterministic limits."""

import hashlib
import io
import struct
from dataclasses import replace

import pytest

from pqdid.circuits import emitter as module
from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate


def test_hand_audited_or_trace_and_truth_table():
    e = Emitter(2, limits=Limits(), public_data=b"hand-or")
    circuit = e.finish(e.or_(*e.inputs))
    # Independent literal byte rendering; output IDs 4,5,6 and AND ordinal 0.
    expected = struct.pack(
        ">16sQ32s", b"PQDID-BC1-DEV1".ljust(16, b"\0"), 2, hashlib.sha256(b"hand-or").digest()
    )
    expected += b"".join(struct.pack(">BQQ", *g) for g in ((1, 2, 3), (2, 2, 3), (1, 4, 5)))
    expected += struct.pack(">BQQQQ", 255, 6, 2, 1, 0)
    assert circuit.serialised == expected
    assert circuit.fingerprint == hashlib.sha256(expected).hexdigest()
    assert (circuit.counts.gates, circuit.counts.and_, circuit.counts.wires) == (3, 1, 7)
    for a in range(2):
        for b in range(2):
            assert evaluate(circuit, bytes([(a << 7) | (b << 6)])).output == (a | b)


@pytest.mark.parametrize(
    "selector,a,b", [(s, a, b) for s in range(2) for a in range(2) for b in range(2)]
)
def test_prescribed_mux_orientation(selector, a, b):
    e = Emitter(3, limits=Limits())
    circuit = e.finish(e.mux(*e.inputs))
    assert (circuit.counts.xor, circuit.counts.and_) == (2, 1)
    assert evaluate(circuit, bytes([(selector << 7) | (a << 6) | (b << 5)])).output == (
        b if selector else a
    )


def test_only_entirely_public_operations_fold_no_identities_or_cse():
    e = Emitter(1, limits=Limits())
    x = e.inputs[0]
    assert e.xor(e.one, e.one).index == 0
    assert e.and_(e.one, e.zero).index == 0
    assert e.not_(e.zero).index == 1
    a = e.xor(x, x)
    b = e.xor(x, x)
    zero = e.and_(x, e.zero)
    same = e.and_(x, e.one)
    inverted = e.xor(x, e.one)
    assert len({v.index for v in (a, b, zero, same, inverted)}) == 5
    assert all(v.public is None for v in (a, b, zero, same, inverted))
    circuit = e.finish(a)
    assert (circuit.counts.xor, circuit.counts.and_, circuit.counts.gates) == (3, 2, 5)
    assert circuit.folded_operations == (1, 1, 1)
    assert evaluate(circuit, b"\x80").output == 0
    assert evaluate(circuit, b"\0").output == 0


def build_example(mode, sink=None):
    e = Emitter(3, limits=Limits(), mode=mode, sink=sink, public_data=b"mode-equality")
    s, a, b = e.inputs
    result = e.mux(s, e.or_(a, b), e.and_(a, b))
    return e.finish(result)


def test_materialised_count_stream_identical_order_fingerprint_counts():
    sink = io.BytesIO()
    stored = build_example("materialised")
    counted = build_example("count")
    streamed = build_example("stream", sink)
    assert sink.getvalue() == stored.serialised
    for result in (counted, streamed):
        assert result.fingerprint == stored.fingerprint
        assert result.counts == stored.counts
        assert result.serialised_bytes == len(stored.serialised)
        assert result.folded_operations == stored.folded_operations
        assert result.serialised is None and result.retained_trace_bytes == 0
    assert counted.stored_bytes == 0
    assert streamed.stored_bytes == stored.stored_bytes == len(sink.getvalue())


def test_generation_signature_has_no_witness_argument_and_all_values_share_trace():
    import inspect

    assert "witness" not in inspect.signature(Emitter).parameters
    fingerprints = []
    outcomes = []
    for value in (0, 32, 64, 96, 128, 160, 192, 224):
        circuit = build_example("materialised")
        fingerprints.append(circuit.fingerprint)
        outcomes.append(evaluate(circuit, bytes([value])).output)
    assert len(set(fingerprints)) == 1 and set(outcomes) == {0, 1}


def test_public_description_and_single_output_are_in_development_identity():
    fingerprints = []
    for public, output in ((b"A", 0), (b"B", 0), (b"A", 1)):
        e = Emitter(1, limits=Limits(), public_data=public)
        fingerprints.append(e.finish(e.constant(output)).fingerprint)
    assert len(set(fingerprints)) == 3
    assert not hasattr(module.Circuit, "proof_commitment")


def test_symbolic_conditions_cannot_drive_host_branch_or_index():
    e = Emitter(1, limits=Limits())
    with pytest.raises(TypeError):
        bool(e.inputs[0])
    with pytest.raises(TypeError):
        (10, 20)[e.inputs[0]]
    other = Emitter(1, limits=Limits())
    with pytest.raises(ValueError):
        e.xor(e.inputs[0], other.inputs[0])


def test_gate_boundary_success_and_exhaustion_poison_emitter():
    e = Emitter(1, limits=Limits(max_gates=2))
    first = e.not_(e.inputs[0])
    second = e.not_(first)
    assert e.finish(second).counts.gates == 2
    e = Emitter(1, limits=Limits(max_gates=1))
    first = e.not_(e.inputs[0])
    with pytest.raises(ResourceLimit) as error:
        e.not_(first)
    assert error.value.progress["gates"] == 1
    assert error.value.progress["complete"] is False
    assert e.state == "aborted"
    with pytest.raises(RuntimeError):
        e.finish(first)


def test_storage_limit_including_footer_and_count_mode_retention():
    size = 16 + 8 + 32 + 17 + 33
    e = Emitter(1, limits=Limits(max_output_bytes=size))
    assert e.finish(e.not_(e.inputs[0])).serialised_bytes == size
    sink = io.BytesIO()
    e = Emitter(1, limits=Limits(max_output_bytes=size - 1), mode="stream", sink=sink)
    bit = e.not_(e.inputs[0])
    with pytest.raises(ResourceLimit) as error:
        e.finish(bit)
    assert error.value.reason == "output-storage limit"
    assert len(sink.getvalue()) == 73  # No completion footer and no over-limit write.
    assert e.state == "aborted"
    e = Emitter(1, limits=Limits(max_output_bytes=0), mode="count")
    result = e.finish(e.not_(e.inputs[0]))
    assert result.serialised_bytes == size and result.stored_bytes == 0


def test_limits_apply_before_input_allocation_and_to_public_only_work(monkeypatch):
    with pytest.raises(ResourceLimit, match="input-position"):
        Emitter(100, limits=Limits(max_inputs=99))
    clock = [0.0]
    monkeypatch.setattr(module.time, "perf_counter", lambda: clock[0])
    e = Emitter(0, limits=Limits(max_seconds=1))
    clock[0] = 1.0
    with pytest.raises(ResourceLimit, match="generation-time"):
        e.xor(e.zero, e.one)
    assert e.state == "aborted"
    with pytest.raises(RuntimeError):
        e.finish(e.one)


def test_short_io_write_is_terminal():
    class Sink:
        calls = 0

        def write(self, data):
            self.calls += 1
            return len(data) if self.calls == 1 else len(data) - 1

    sink = Sink()
    e = Emitter(1, limits=Limits(), mode="stream", sink=sink)
    with pytest.raises(OSError, match="short"):
        e.not_(e.inputs[0])
    assert e.state == "aborted"
    with pytest.raises(RuntimeError):
        e.finish(e.zero)


def test_evaluation_limits_padding_and_corrupt_artifacts():
    circuit = build_example("materialised")
    for raw in (b"", b"\0\0", b"\x01"):
        with pytest.raises(ValueError):
            evaluate(circuit, raw)
    with pytest.raises(ResourceLimit, match="wire-storage"):
        evaluate(circuit, b"\0", max_wires=circuit.counts.wires - 1)
    with pytest.raises(ResourceLimit, match="evaluation-time"):
        evaluate(circuit, b"\0", max_seconds=0)
    with pytest.raises(ValueError, match="materialised"):
        evaluate(build_example("count"), b"\0")
    with pytest.raises(ValueError, match="corrupt"):
        evaluate(replace(circuit, serialised=circuit.serialised[:-1]), b"\0")
    with pytest.raises(RuntimeError):
        e = Emitter(1, limits=Limits())
        e.finish(e.inputs[0])
        e.not_(e.inputs[0])


@pytest.mark.parametrize(
    "arguments",
    [
        {"max_gates": -1},
        {"max_inputs": True},
        {"max_seconds": float("inf")},
        {"max_seconds": float("nan")},
        {"max_output_bytes": 1.5},
    ],
)
def test_invalid_resource_configuration(arguments):
    with pytest.raises(ValueError):
        Limits(**arguments)
