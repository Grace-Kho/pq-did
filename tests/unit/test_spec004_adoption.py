"""Audit the user-agreed wiring, independent arithmetic and historical trace delta."""

import io
import struct

import pytest

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import div64, divmod64, mod64
from pqdid.circuits.emitter import AND, NOT, Emitter, Limits, evaluate
from tests.reference.scalar_oracle import floor_pair
from tests.reference.signature_oracle import observed
from tests.reference.spec004_provisional import provisional_divmod


def test_named_intermediate_order_operands_reuse_and_narrowing(monkeypatch):
    records = {name: [] for name in ("_subtract", "mux_word", "equal", "_narrow")}
    events = []
    for name in records:
        original = getattr(w, name)

        def capture(e, *args, _name=name, _original=original):
            value = _original(e, *args)
            records[_name].append((args, value))
            events.append(_name)
            return value

        monkeypatch.setattr(w, name, capture)
    e = Emitter(64, limits=Limits())
    dividend = w.from_serialised(e, e.inputs)
    result = divmod64(e, dividend, 8380417)
    circuit = e.finish(result.valid)
    subtract, mux, equal, narrow = (records[name] for name in records)
    assert len(subtract) == 68 and len(mux) == 69 and len(equal) == 1 and len(narrow) == 2
    assert all(len(a) == len(b) == len(value) == 65 for (a, b), value in subtract)
    magnitude = mux[0][1][:64]
    for position, ((trial, denominator), difference), ((take, a, b), _) in zip(
        range(63, -1, -1), subtract[1:65], mux[1:65], strict=True
    ):
        assert trial[0] is magnitude[position]
        assert a is trial and b is difference
        assert denominator == tuple(e.one if (8380417 >> i) & 1 else e.zero for i in range(65))
        gate = struct.unpack_from(">BQQ", circuit.serialised, 56 + (take.index - 66) * 17)
        assert gate == (NOT, difference[64].index, 0)
    remainder = mux[64][1]
    (equal_left, zero), equality = equal[0]
    assert equal_left is remainder and zero == (e.zero,) * 65
    (neg_zero, q65), negative_q = subtract[-3]
    assert neg_zero is zero and q65[-1] is e.zero
    assert q65[:64] == tuple(mux[64 - i][0][0] for i in range(64))
    (same_negative_q, one), minus_one = subtract[-2]
    assert same_negative_q is negative_q and one == (e.one,) + (e.zero,) * 64
    (nz, a, b), corrected_q = mux[-4]
    assert a is negative_q and b is minus_one
    assert struct.unpack_from(">BQQ", circuit.serialised, 56 + (nz.index - 66) * 17) == (
        NOT,
        equality.index,
        0,
    )
    (_, same_r), b_minus_r = subtract[-1]
    assert same_r is remainder
    (same_nz, zero_arm, difference), corrected_r = mux[-3]
    assert same_nz is nz and zero_arm is zero and difference is b_minus_r
    (sign_q, positive_q, negative_q_arm), output_q = mux[-2]
    (sign_r, positive_r, negative_r_arm), output_r = mux[-1]
    assert sign_q is sign_r is dividend[-1]
    assert positive_q is q65 and negative_q_arm is corrected_q
    assert positive_r is remainder and negative_r_arm is corrected_r
    assert narrow[0][0] == (output_q, 64) and narrow[1][0] == (output_r, 64)
    assert events[-10:] == [
        "equal",
        "_subtract",
        "_subtract",
        "mux_word",
        "_subtract",
        "mux_word",
        "mux_word",
        "mux_word",
        "_narrow",
        "_narrow",
    ]
    gates = list(struct.iter_unpack(">BQQ", circuit.serialised[56:-33]))
    assert gates[-2] == (AND, narrow[0][1].valid.index, narrow[1][1].valid.index)
    assert gates[-1] == (AND, result.valid.index - 1, 1)


@pytest.mark.parametrize("divisor", [0, 1, 2, 16, 523776, 8380417, (1 << 63) - 1])
def test_adoption_preserves_values_and_counts_but_changes_trace(divisor):
    circuits = []
    for operation in (provisional_divmod, divmod64):
        e = Emitter(64, limits=Limits())
        value = operation(e, w.from_serialised(e, e.inputs), divisor)
        scope = Scope(e)
        scope.require(value.valid)
        circuits.append((e.finish(scope.output(())), value))
    old, new = circuits
    assert old[0].counts == new[0].counts
    assert old[0].fingerprint != new[0].fingerprint
    for a in (
        -(1 << 63),
        -(1 << 63) + 1,
        -8380417,
        -17,
        -16,
        -1,
        0,
        1,
        16,
        17,
        8380417,
        (1 << 63) - 1,
    ):
        raw = a.to_bytes(8, "big", signed=True)
        outputs = []
        for circuit, result in circuits:
            assert evaluate(circuit, raw).output == int(divisor > 0)
            values, _, _ = observed(circuit, raw, words=(result.quotient, result.remainder))
            outputs.append(values)
        assert outputs[0] == outputs[1]
        if divisor:
            q, r = outputs[1]
            assert (q, r) == floor_pair(a, divisor)
            assert a == divisor * q + r and 0 <= r < divisor


@pytest.mark.parametrize("operation", [div64, mod64])
def test_single_output_still_constructs_and_checks_both_outputs(operation, monkeypatch):
    calls = []
    original = w._narrow

    def capture(e, wide, width):
        calls.append((len(wide), width))
        return original(e, wide, width)

    monkeypatch.setattr(w, "_narrow", capture)
    e = Emitter(64, limits=Limits())
    operation(e, e.inputs, 1)
    assert calls == [(65, 64), (65, 64)]


def test_adopted_modes_identical_and_zero_divisor_rejects_only_active_path():
    sink = io.BytesIO()
    circuits = []
    for mode in ("materialised", "count", "stream"):
        e = Emitter(65, limits=Limits(), mode=mode, sink=sink if mode == "stream" else None)
        scope = Scope(e, active=e.inputs[64])
        result = divmod64(e, w.from_serialised(e, e.inputs[:64]), 0)
        scope.require(result.valid)
        circuits.append(e.finish(scope.output(())))
    assert len({c.fingerprint for c in circuits}) == 1
    assert sink.getvalue() == circuits[0].serialised
    for a in (-(1 << 63), 0, (1 << 63) - 1):
        for active in (0, 1):
            raw = a.to_bytes(8, "big", signed=True) + bytes((active << 7,))
            assert evaluate(circuits[0], raw).output == 1 - active
