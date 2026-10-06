"""Independent arithmetic truth tables, actual widths and emission structure."""

import itertools
import struct

import pytest

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, Limits, evaluate

from .bc1_cases import integer_bits, packed

OPERATIONS = {
    "add": (w._add_checked, w.add64, lambda a, b: a + b),
    "sub": (w._sub_checked, w.sub64, lambda a, b: a - b),
    "mul": (w._mul_checked, w.mul64, lambda a, b: a * b),
}


def arithmetic_circuit(name, width):
    e = Emitter(3 * width + 1, limits=Limits())
    a, b, expected = e.inputs[:width], e.inputs[width : 2 * width], e.inputs[2 * width : 3 * width]
    operation = OPERATIONS[name][1 if width == 64 else 0]
    result = operation(e, a, b)
    matches_value = w.equal(e, result.value, expected)
    matches_valid = e.not_(e.xor(result.valid, e.inputs[-1]))
    return e.finish(e.and_(matches_value, matches_valid))


@pytest.mark.parametrize("name", OPERATIONS)
@pytest.mark.parametrize("width", [2, 3, 4])
def test_reduced_width_exhaustive_arithmetic(name, width):
    circuit = arithmetic_circuit(name, width)
    bound = 1 << (width - 1)
    for a, b in itertools.product(range(-bound, bound), repeat=2):
        expected = OPERATIONS[name][2](a, b)
        bits = (
            integer_bits(a, width)
            + integer_bits(b, width)
            + integer_bits(expected, width)
            + [int(-bound <= expected < bound)]
        )
        assert evaluate(circuit, packed(bits)).output == 1, (name, width, a, b)


BOUNDARY_PAIRS = [
    (0, 0),
    (0, 1),
    (-1, 1),
    (1, -1),
    (-1, -1),
    ((1 << 63) - 1, 1),
    (-(1 << 63), -1),
    (-(1 << 63), 1),
    (-(1 << 63), -(1 << 63)),
    ((1 << 63) - 1, (1 << 63) - 1),
    (-(1 << 63), (1 << 63) - 1),
    (1 << 32, 1 << 32),
    ((1 << 32) - 1, (1 << 32) - 1),
    (-(1 << 62), 2),
    (-(1 << 62), -2),
    (3037000499, 3037000499),
    (3037000500, 3037000500),
]


@pytest.fixture(scope="module", params=list(OPERATIONS))
def actual_arithmetic(request):
    return request.param, arithmetic_circuit(request.param, 64)


@pytest.mark.parametrize("a,b", BOUNDARY_PAIRS)
def test_actual_64_bit_boundaries(actual_arithmetic, a, b):
    name, circuit = actual_arithmetic
    expected = OPERATIONS[name][2](a, b)
    bits = (
        integer_bits(a, 64)
        + integer_bits(b, 64)
        + integer_bits(expected, 64)
        + [int(-(1 << 63) <= expected < (1 << 63))]
    )
    assert evaluate(circuit, packed(bits)).output == 1
    # Incorrect expected value/validity cannot accidentally satisfy the circuit.
    bits[-1] ^= 1
    assert evaluate(circuit, packed(bits)).output == 0


@pytest.mark.parametrize(
    "name,width,expected_counts",
    [
        ("add", 65, (196, 131, 1)),
        ("sub", 65, (196, 131, 66)),
        ("mul", 128, (25867, 21254, 322)),
    ],
)
def test_real_intermediate_widths_and_audited_counts(name, width, expected_counts):
    e = Emitter(128, limits=Limits())
    result = OPERATIONS[name][1](e, e.inputs[:64], e.inputs[64:])
    assert len(result.wide) == width and len(result.value) == 64
    circuit = e.finish(result.valid)
    assert (circuit.counts.xor, circuit.counts.and_, circuit.counts.not_) == expected_counts
    # These are component counts, not full authentication counts or lower bounds.


@pytest.mark.parametrize(
    "a,b",
    [(0, 0), (2, -3), (-(1 << 63), -1), (-(1 << 63), -(1 << 63)), ((1 << 63) - 1, (1 << 63) - 1)],
)
def test_full_signed_128_bit_product(a, b):
    e = Emitter(256, limits=Limits())
    result = w.mul64(e, e.inputs[:64], e.inputs[64:128])
    circuit = e.finish(w.equal(e, result.wide, e.inputs[128:]))
    assert (
        evaluate(
            circuit, packed(integer_bits(a, 64) + integer_bits(b, 64) + integer_bits(a * b, 128))
        ).output
        == 1
    )


def test_overflow_is_a_circuit_rejection_not_early_generator_termination():
    e = Emitter(128, limits=Limits())
    scope = Scope(e)
    value = scope.checked(w.add64(e, e.inputs[:64], e.inputs[64:]))
    # Retain operations following the private overflow condition.
    scope.checked(w.sub64(e, value, w.constant(e, 1, 64)))
    circuit = e.finish(scope.output(()))
    assert evaluate(circuit, packed(integer_bits(1, 64) + integer_bits(2, 64))).output == 1
    assert (
        evaluate(circuit, packed(integer_bits((1 << 63) - 1, 64) + integer_bits(1, 64))).output == 0
    )
    # The constant rhs contributes 65 allowed public NOT folds. The private
    # subtraction still emits all its ripple, narrowing and rejection gates.
    assert circuit.counts.gates == 668
    assert circuit.folded_operations == (0, 0, 65)


def test_two_bit_ripple_exact_gate_order_and_carry():
    e = Emitter(4, limits=Limits())
    _, carry = w._ripple(e, e.inputs[:2], e.inputs[2:], e.zero)
    circuit = e.finish(carry)
    expected = [
        (1, 2, 4),
        (1, 6, 0),
        (2, 2, 4),
        (2, 6, 0),
        (1, 8, 9),
        (1, 3, 5),
        (1, 11, 10),
        (2, 3, 5),
        (2, 11, 10),
        (1, 13, 14),
    ]
    assert circuit.serialised[56:-33] == b"".join(struct.pack(">BQQ", *gate) for gate in expected)
    for a, b in itertools.product(range(4), repeat=2):
        assert evaluate(circuit, packed(integer_bits(a, 2) + integer_bits(b, 2))).output == (
            (a + b) >> 2
        )


@pytest.mark.parametrize("width", [2, 3, 4, 64])
def test_signed_comparisons_and_equality(width):
    e = Emitter(2 * width + 2, limits=Limits())
    a, b = e.inputs[:width], e.inputs[width : 2 * width]
    less = w.less64(e, a, b) if width == 64 else w._less(e, a, b)
    eq = w.equal(e, a, b)
    circuit = e.finish(e.and_(e.not_(e.xor(less, e.inputs[-2])), e.not_(e.xor(eq, e.inputs[-1]))))
    pairs = (
        BOUNDARY_PAIRS
        if width == 64
        else itertools.product(range(-(1 << (width - 1)), 1 << (width - 1)), repeat=2)
    )
    for a, b in pairs:
        assert (
            evaluate(
                circuit,
                packed(integer_bits(a, width) + integer_bits(b, width) + [int(a < b), int(a == b)]),
            ).output
            == 1
        )


def test_less_equal_64_and_word_selection():
    e = Emitter(193, limits=Limits())
    a, b = e.inputs[:64], e.inputs[64:128]
    selected = w.mux_word(e, w.less_equal64(e, a, b), b, a)
    circuit = e.finish(e.and_(w.equal(e, selected, e.inputs[128:192]), e.inputs[-1]))
    for a, b in BOUNDARY_PAIRS:
        assert (
            evaluate(
                circuit,
                packed(
                    integer_bits(a, 64) + integer_bits(b, 64) + integer_bits(min(a, b), 64) + [1]
                ),
            ).output
            == 1
        )


@pytest.mark.parametrize("order,expected", [("big", 0x8102), ("little", 0x0281)])
def test_msb_bytes_to_arithmetic_and_inverse_are_wiring_only(order, expected):
    e = Emitter(16, limits=Limits())
    word = w.from_serialised(e, e.inputs, byte_order=order)
    assert w.to_serialised(e, word, byte_order=order) == e.inputs
    assert e.counts.gates == 0
    circuit = e.finish(w.equal(e, word, w.constant(e, expected, 16)))
    assert evaluate(circuit, b"\x81\x02").output == 1


@pytest.mark.parametrize("amount", [-65, -8, -1, 0, 1, 8, 65])
def test_bitstring_shift_rotate_rewire_without_integer_shortcut(amount):
    e = Emitter(64, limits=Limits())
    word = w.from_serialised(e, e.inputs)
    shifted = w.bit_shift(e, word, amount)
    rotated = w.rotate_left(e, word, amount)
    assert e.counts.gates == 0
    x = 0x8000000000000003
    expected_shift = ((x << amount) & ((1 << 64) - 1)) if amount >= 0 else x >> (-amount)
    n = amount % 64
    expected_rotate = ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)
    circuit = e.finish(
        e.and_(
            w.equal(e, shifted, w.constant(e, expected_shift, 64)),
            w.equal(e, rotated, w.constant(e, expected_rotate, 64)),
        )
    )
    assert evaluate(circuit, x.to_bytes(8, "big")).output == 1


def test_actual_integer_entry_points_reject_reduced_widths():
    e = Emitter(16, limits=Limits())
    for operation in (w.add64, w.sub64, w.mul64, w.less64):
        with pytest.raises(ValueError, match="width"):
            operation(e, e.inputs[:8], e.inputs[8:])
