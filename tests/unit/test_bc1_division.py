"""Real signed64 and exhaustive small-width checked floor/remainder contracts."""

import hashlib
import itertools
import json
import struct
from pathlib import Path

import pytest

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import _divmod_const, centred64, div64, divmod64, mod64
from pqdid.circuits.emitter import Emitter, Limits, evaluate
from tests.reference.scalar_oracle import floor_pair, trace_words

from .bc1_cases import integer_bits, packed

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/bc1_scalar_vectors.json").read_text()
)
DIVISORS = sorted({v["divisor"] for v in VECTORS["division"]})


def test_independent_fixture_provenance_and_coverage():
    root = Path(__file__).resolve().parents[2]
    for name, digest in VECTORS["source_sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
    assert len(VECTORS["division"]) == 96
    assert {v["value"] for v in VECTORS["decompose"]} >= {-(1 << 63), (1 << 63) - 1, 8380416}


def observed(circuit, witness, *words):
    return trace_words(
        circuit.serialised, witness, tuple(tuple(b.index for b in word) for word in words)
    )


@pytest.mark.parametrize("divisor", DIVISORS)
def test_real_signed64_division_vectors_and_identity(divisor):
    e = Emitter(64, limits=Limits())
    result = divmod64(e, w.from_serialised(e, e.inputs), divisor)
    circuit = e.finish(result.valid)
    identity = circuit.fingerprint
    assert len(result.quotient_wide) == len(result.remainder_wide) == 65
    for case in (v for v in VECTORS["division"] if v["divisor"] == divisor):
        a = case["dividend"]
        witness = a.to_bytes(8, "big", signed=True)
        assert evaluate(circuit, witness).output == 1
        q, r = observed(circuit, witness, result.quotient, result.remainder)
        assert (q, r) == (case["quotient"], case["remainder"]) == floor_pair(a, divisor)
        assert a == divisor * q + r and 0 <= r < divisor
        assert circuit.fingerprint == identity


@pytest.mark.parametrize("width", [2, 3, 4, 5])
def test_exhaustive_small_division(width):
    bound = 1 << (width - 1)
    for divisor in range(1, bound):
        e = Emitter(width, limits=Limits())
        result = _divmod_const(e, e.inputs, divisor)
        circuit = e.finish(result.valid)
        for a in range(-bound, bound):
            witness = packed(integer_bits(a, width))
            assert evaluate(circuit, witness).output == 1
            assert observed(circuit, witness, result.quotient, result.remainder) == floor_pair(
                a, divisor
            )


@pytest.mark.parametrize("modulus", [1, 2, 16, 523776, 8380417])
def test_centred_endpoints_real_width(modulus):
    e = Emitter(64, limits=Limits())
    result = centred64(e, w.from_serialised(e, e.inputs), modulus)
    assert result.value == result.wide[:64]
    circuit = e.finish(result.valid)
    for case in (v for v in VECTORS["centred"] if v["modulus"] == modulus):
        raw = case["value"].to_bytes(8, "big", signed=True)
        assert evaluate(circuit, raw).output == 1
        (value,) = observed(circuit, raw, result.value)
        assert value == case["expected"]
        assert -((modulus + 1) // 2) < value <= modulus // 2
        assert (case["value"] - value) % modulus == 0


@pytest.mark.parametrize("operation", [div64, mod64, centred64])
def test_zero_divisor_rejection_survives_tautological_comparison(operation):
    e = Emitter(64, limits=Limits())
    scope = Scope(e)
    value = scope.checked(operation(e, w.from_serialised(e, e.inputs), 0))
    # Even equality of a result with itself must not erase the sticky fault.
    circuit = e.finish(scope.output((w.equal(e, value, value),)))
    for a in (-(1 << 63), -1, 0, 1, (1 << 63) - 1):
        assert evaluate(circuit, a.to_bytes(8, "big", signed=True)).output == 0


@pytest.mark.parametrize("bad", [-1, -(1 << 63), 1 << 63, True, 1.5, (0,) * 64])
def test_non_profile_divisors_are_not_silently_given_other_semantics(bad):
    e = Emitter(64, limits=Limits())
    with pytest.raises(ValueError, match="public non-negative"):
        divmod64(e, e.inputs, bad)


def test_private_divisor_and_wrong_width_are_not_supported():
    e = Emitter(128, limits=Limits())
    with pytest.raises(ValueError):
        divmod64(e, e.inputs[:64], e.inputs[64:])
    with pytest.raises(ValueError):
        divmod64(e, e.inputs[:32], 3)


@pytest.mark.parametrize("a,b", list(itertools.product([-17, 0, 17], [1, 2, 8380417])))
def test_entirely_public_division_folds_without_changing_math(a, b):
    e = Emitter(0, limits=Limits())
    result = divmod64(e, w.constant(e, a, 64, signed=True), b)
    circuit = e.finish(result.valid)
    assert circuit.counts.gates == 0 and evaluate(circuit, b"").output == 1
    assert observed(circuit, b"", result.quotient, result.remainder) == floor_pair(a, b)


def test_proposed_two_bit_restoring_step_literal_trace():
    e = Emitter(2, limits=Limits())
    result = _divmod_const(e, e.inputs, 1)
    circuit = e.finish(result.valid)
    gates = list(struct.iter_unpack(">BQQ", circuit.serialised[56:-33]))
    # After the 27-gate signed2 magnitude, its high bit is wire 27. First
    # trial=(27,0,0), divisor=1, complemented divisor=(0,1,1), carry=1.
    # Retain the terminal carry at wire 41, sign NOT at 42, then all three muxes.
    assert gates[27:48] == [
        (1, 27, 0),
        (1, 31, 1),
        (2, 27, 0),
        (2, 31, 1),
        (1, 33, 34),
        (1, 1, 35),
        (2, 1, 35),
        (1, 0, 37),
        (1, 1, 38),
        (2, 1, 38),
        (1, 0, 40),
        (3, 39, 0),
        (1, 27, 32),
        (2, 42, 43),
        (1, 27, 44),
        (1, 0, 36),
        (2, 42, 46),
        (1, 0, 47),
        (1, 0, 39),
        (2, 42, 49),
        (1, 0, 50),
    ]
