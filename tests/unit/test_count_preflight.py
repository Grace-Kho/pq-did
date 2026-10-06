"""Count guards preserve canonical emission and never allocate a graph/values."""

import hashlib

import pytest

from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate
from scripts.preflight_signature_inputs import CountingEmitter, effective_profile


def emit(e, size):
    value = e.inputs[0]
    for _ in range(size):
        value = e.xor(value, e.one)
    return e.finish(value)


def test_count_identity_no_full_trace_or_graph(tmp_path):
    limit = Limits(max_gates=1000, max_output_bytes=20000)
    ordinary = emit(Emitter(1, limits=limit), 1000)
    e = CountingEmitter(1, limits=limit, checkpoint=tmp_path / "progress")
    counted = emit(e, 1000)
    assert counted.fingerprint == hashlib.sha256(ordinary.serialised).hexdigest()
    assert (
        counted.counts == ordinary.counts
        and counted.folded_operations == ordinary.folded_operations
    )
    assert counted.serialised_bytes == 17089 and counted.stored_bytes == 0
    assert counted.serialised is None and counted.retained_trace_bytes == 0
    assert e._buffer is None and e._sink is None and len(e.inputs) == 1
    assert max(len(v) for v in vars(e).values() if isinstance(v, (list, tuple))) == 3
    with pytest.raises(ValueError, match="materialised"):
        evaluate(counted, b"\0")


@pytest.mark.parametrize("size", [55, 72, 105])
def test_logical_header_gate_footer_limit_is_enforced_without_storage(size):
    with pytest.raises(ResourceLimit, match="logical trace-size limit") as failure:
        emit(CountingEmitter(1, limits=Limits(max_output_bytes=size)), 1)
    assert failure.value.progress["stored_bytes"] == 0
    assert failure.value.progress["complete"] is False


def test_exact_logical_limit_and_gate_limit():
    assert emit(CountingEmitter(1, limits=Limits(max_output_bytes=106)), 1).serialised_bytes == 106
    with pytest.raises(ResourceLimit, match="gate-count limit"):
        emit(CountingEmitter(1, limits=Limits(max_gates=1)), 2)


def test_count_profile_retains_stricter_memory_and_ordinary_limits():
    profile, _ = effective_profile()
    assert profile["max_gates"] == 32_000_000
    assert profile["max_logical_trace_bytes"] == 1024**3
    assert profile["rss_ceiling_bytes"] <= 128 * 1024**2
    assert profile["address_space_bytes"] <= 256 * 1024**2
    ordinary, _ = effective_profile(arithmetic=True)
    assert ordinary["max_gates"] == 2_000_000 and ordinary["evaluation_seconds"] == 5
