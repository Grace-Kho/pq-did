"""Independent selector/state expectations, active faults and fixed control flow."""

import itertools

import pytest

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, Limits, evaluate

from .bc1_cases import integer_bits, packed


@pytest.mark.parametrize("write", [False, True])
def test_scanned_access_boundaries_and_inactive_faults(write):
    # Inputs are symbolic positions; expected results are supplied only later.
    e = Emitter(64 + 1 + 24 + 8 + 24 + 1, limits=Limits())
    index, active = e.inputs[:64], e.inputs[64]
    cells = tuple(e.inputs[65 + i * 8 : 73 + i * 8] for i in range(3))
    value = e.inputs[89:97]
    expected = tuple(e.inputs[97 + i * 8 : 105 + i * 8] for i in range(3))
    scope = Scope(e, active=active)
    if write:  # Public choice of the component being constructed.
        result = scope.write(cells, index, value)
    else:
        result = (scope.read(cells, index), cells[1], cells[2])
    checks = [w.equal(e, a, b) for a, b in zip(result, expected, strict=True)]
    checks.append(e.not_(e.xor(scope.rejected, e.inputs[-1])))
    output = e.one
    for check in checks:
        output = e.and_(output, check)
    circuit = e.finish(output)
    for position, enabled in itertools.product([-(2**63), -1, 0, 1, 2, 3, 2**63 - 1], [0, 1]):
        original = [0x81, 0x36, 0xFA]
        valid = 0 <= position < 3
        want = original.copy()
        if write:
            if enabled and valid:
                want[position] = 0x5C
        else:
            want[0] = original[position] if enabled and valid else 0
        bits = integer_bits(position, 64) + [enabled]
        for cell in original + [0x5C] + want:
            bits += integer_bits(cell, 8)
        bits += [int(enabled and not valid)]
        assert evaluate(circuit, packed(bits)).output == 1, (position, enabled)


def test_snapshot_writes_and_sequential_assignments():
    e = Emitter(128, limits=Limits())
    scope = Scope(e)
    cells = (w.constant(e, 10, 8), w.constant(e, 20, 8))
    # Parallel swap reads the old tuple; subsequent writes see the previous result.
    swapped = (cells[1], cells[0])
    first = scope.write(swapped, e.inputs[:64], w.constant(e, 30, 8))
    second = scope.write(first, e.inputs[64:], w.constant(e, 40, 8))
    read = scope.read(second, e.inputs[:64])
    same_index = w.equal(e, e.inputs[:64], e.inputs[64:])
    expected = w.mux_word(e, same_index, w.constant(e, 30, 8), w.constant(e, 40, 8))
    circuit = e.finish(scope.output((w.equal(e, read, expected),)))
    assert cells[0][1].public == 1  # Original constants/tuple were not mutated.
    for a, b in itertools.product(range(2), repeat=2):
        assert evaluate(circuit, packed(integer_bits(a, 64) + integer_bits(b, 64))).output == 1
    assert evaluate(circuit, packed(integer_bits(2, 64) + integer_bits(0, 64))).output == 0


def test_both_branches_true_first_and_only_active_overflow_rejects():
    e = Emitter(65, limits=Limits())
    scope = Scope(e)
    order = []

    def when_true(child):
        order.append("true")
        return child.checked(w.add64(e, e.inputs[1:], w.constant(e, 1, 64)))

    def when_false(child):
        order.append("false")
        return child.checked(w.sub64(e, e.inputs[1:], w.constant(e, 1, 64)))

    scope.branch(e.inputs[0], when_true, when_false)
    circuit = e.finish(scope.output(()))
    assert order == ["true", "false"]
    for selector, value in itertools.product([0, 1], [-(2**63), 0, 2**63 - 1]):
        expected = value + (1 if selector else -1)
        assert evaluate(circuit, packed([selector] + integer_bits(value, 64))).output == int(
            -(2**63) <= expected < 2**63
        )


def test_public_inactive_branch_is_still_constructed_with_private_operations():
    e = Emitter(1, limits=Limits())
    scope = Scope(e)
    order = []

    def bad(child):
        order.append("true")
        child.require(e.zero)
        return (e.not_(e.inputs[0]),)

    def good(child):
        order.append("false")
        return (e.inputs[0],)

    value = scope.branch(e.zero, bad, good)
    circuit = e.finish(scope.output((e.not_(e.xor(value[0], e.inputs[0])),)))
    assert order == ["true", "false"] and circuit.counts.not_ >= 1
    assert evaluate(circuit, b"\x00").output == evaluate(circuit, b"\x80").output == 1


def test_fixed_iteration_mask_and_sticky_rejection():
    # This demonstrates the mask primitive, not a complete sampler-loop lowerer.
    e = Emitter(6, limits=Limits())
    live = e.one
    rejected = e.zero
    for i in range(3):
        iteration = Scope(e, active=live)
        iteration.require(e.inputs[2 * i])
        rejected = e.or_(rejected, iteration.rejected)
        live = e.and_(live, e.not_(e.inputs[2 * i + 1]))
    circuit = e.finish(e.not_(rejected))
    for bits in itertools.product([0, 1], repeat=6):
        live_value, accepted = True, True
        for i in range(3):
            if live_value:
                accepted &= bool(bits[2 * i])
                live_value = not bits[2 * i + 1]
        assert evaluate(circuit, packed(list(bits))).output == int(accepted)


def test_branch_merge_orientation():
    e = Emitter(17, limits=Limits())
    scope = Scope(e)
    result = scope.branch(e.inputs[0], lambda _: e.inputs[1:9], lambda _: e.inputs[9:17])
    circuit = e.finish(w.equal(e, result, w.constant(e, 0xA5, 8)))
    for selector, a, b in [(1, 0xA5, 0), (0, 0, 0xA5), (0, 0xA5, 0), (1, 0, 0xA5)]:
        expected = int((a if selector else b) == 0xA5)
        assert (
            evaluate(circuit, packed([selector] + integer_bits(a, 8) + integer_bits(b, 8))).output
            == expected
        )
