"""Two literal fold interpretations; no alternate production profile is selected."""

import itertools

import pytest

from pqdid.circuits import words as w
from pqdid.circuits.emitter import Emitter, Limits, evaluate

from .bc1_cases import integer_bits, packed


def first_xnor(e, a, b):
    result = e.not_(e.xor(a[0], b[0]))
    for left, right in zip(a[1:], b[1:], strict=True):
        result = e.and_(result, e.not_(e.xor(left, right)))
    return result


def first_partial(e, a, b):
    width = len(a)
    left, right = w._magnitude(e, a), w._magnitude(e, b)
    total = None
    for i in range(width):
        raw = tuple(e.and_(left[j], right[i]) for j in range(width))
        partial = (e.zero,) * i + raw + (e.zero,) * (width - i)
        total = partial if i == 0 else w._ripple(e, total, partial, e.zero)[0]
    sign = e.xor(a[-1], b[-1])
    negative = w._subtract(e, (e.zero,) * len(total), total)
    return w._narrow(e, w.mux_word(e, sign, total, negative), width)


def alternative_circuit(kind, width, alternative):
    n = 2 * width if kind == "equality" else 3 * width + 1
    e = Emitter(n, limits=Limits())
    a, b = e.inputs[:width], e.inputs[width : 2 * width]
    if kind == "equality":
        result = (first_xnor if alternative else w.equal)(e, a, b)
    else:
        checked = (first_partial if alternative else w._mul_checked)(e, a, b)
        value_ok = w.equal(e, checked.value, e.inputs[2 * width : 3 * width])
        valid_ok = e.not_(e.xor(checked.valid, e.inputs[-1]))
        result = e.and_(value_ok, valid_ok)
    return e.finish(result)


@pytest.mark.parametrize("width", [1, 2, 3, 4])
def test_equality_initialiser_changes_structure_not_acceptance(width):
    seeded = alternative_circuit("equality", width, False)
    first = alternative_circuit("equality", width, True)
    assert seeded.counts.and_ == first.counts.and_ + 1
    assert seeded.counts.gates == first.counts.gates + 1
    assert seeded.fingerprint != first.fingerprint
    for a, b in itertools.product(range(1 << width), repeat=2):
        witness = packed(integer_bits(a, width) + integer_bits(b, width))
        assert evaluate(seeded, witness).output == evaluate(first, witness).output == int(a == b)


@pytest.mark.parametrize("width", [2, 3, 64])
def test_partial_product_initialiser_including_overflow_boundaries(width):
    seeded = alternative_circuit("multiply", width, False)
    first = alternative_circuit("multiply", width, True)
    # Omitting the first ripple also leaves high bits public in the second sum,
    # enabling another 2*(n-1) entirely-public folds, without identity rewrites.
    assert seeded.counts.gates == first.counts.gates + 10 * width - 2
    assert seeded.counts.and_ == first.counts.and_ + 4 * width - 1
    assert seeded.fingerprint != first.fingerprint
    bound = 1 << (width - 1)
    pairs = (
        [(0, 0), (-bound, -1), (bound - 1, 1), (bound - 1, 2), (-bound, -bound)]
        if width == 64
        else itertools.product(range(-bound, bound), repeat=2)
    )
    for a, b in pairs:
        product = a * b
        bits = integer_bits(a, width) + integer_bits(b, width) + integer_bits(product, width)
        witness = packed(bits + [int(-bound <= product < bound)])
        assert evaluate(seeded, witness).output == evaluate(first, witness).output == 1
        wrong_validity = packed(bits + [int(not -bound <= product < bound)])
        assert (
            evaluate(seeded, wrong_validity).output == evaluate(first, wrong_validity).output == 0
        )
