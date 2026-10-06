"""Functional equivalence does not settle canonical circuit identity."""

import pytest

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import _divmod_const
from pqdid.circuits.emitter import Emitter, evaluate
from tests.reference.division_alternative import separate_compare_and_subtract
from tests.reference.scalar_oracle import floor_pair
from tests.reference.signature_oracle import observed

from .auth_arithmetic_cases import extended_limits
from .bc1_cases import integer_bits, packed


def build(width, divisor, alternative=False):
    e = Emitter(width, limits=extended_limits())
    scope = Scope(e)
    function = separate_compare_and_subtract if alternative else _divmod_const
    result = function(e, e.inputs, divisor)
    scope.require(result.valid)
    return e.finish(scope.output(())), result


@pytest.mark.parametrize("width", [2, 3, 4])
def test_exhaustive_reduced_width_agreement_with_different_traces(width):
    for divisor in range(1, 1 << (width - 1)):
        base, a = build(width, divisor)
        other, b = build(width, divisor, True)
        assert other.counts.gates > base.counts.gates and other.fingerprint != base.fingerprint
        for value in range(-(1 << (width - 1)), 1 << (width - 1)):
            raw = packed(integer_bits(value, width))
            expected = floor_pair(value, divisor)
            for circuit, result in ((base, a), (other, b)):
                actual, _, flags = observed(
                    circuit, raw, words=(result.quotient, result.remainder), flags=(result.valid,)
                )
                assert actual == expected and flags == (1,)
                assert evaluate(circuit, raw).output == 1


@pytest.mark.parametrize("divisor", [0, 1, 16, 8380417, (1 << 63) - 1])
def test_actual_width_endpoints_and_zero_rejection(divisor):
    base, a = build(64, divisor)
    other, b = build(64, divisor, True)
    assert other.fingerprint != base.fingerprint and other.counts.and_ > base.counts.and_
    for value in (-(1 << 63), -17, -1, 0, 1, (1 << 63) - 1):
        raw = packed(integer_bits(value, 64))
        outputs = []
        for circuit, result in ((base, a), (other, b)):
            actual, _, flags = observed(
                circuit, raw, words=(result.quotient, result.remainder), flags=(result.valid,)
            )
            assert flags == (int(divisor > 0),)
            assert evaluate(circuit, raw).output == int(divisor > 0)
            outputs.append(actual)
        assert outputs[0] == outputs[1]
        if divisor:
            assert outputs[0] == floor_pair(value, divisor)


def test_single_subtraction_recipe_has_exact_65_bit_round_schedule(monkeypatch):
    widths = []
    original = w._subtract

    def record(e, left, right):
        widths.append((len(left), len(right)))
        return original(e, left, right)

    monkeypatch.setattr(w, "_subtract", record)
    build(64, 8380417)
    # magnitude negate + 64 restoring differences + negative q + q-1 + b-r
    assert widths == [(65, 65)] * 68
