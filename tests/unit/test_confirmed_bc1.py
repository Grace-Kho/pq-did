"""Independent literal traces and actual-width schedule for agreed SPEC-003."""

import struct

from pqdid.circuits import words
from pqdid.circuits.emitter import Emitter, Limits


def records(circuit):
    return list(struct.iter_unpack(">BQQ", circuit.serialised[56:-33]))


def test_equality_keeps_public_one_initial_and():
    e = Emitter(4, limits=Limits())
    circuit = e.finish(words.equal(e, e.inputs[:2], e.inputs[2:]))
    # Inputs 2..5, outputs 6..11. Neither AND(1, private) may disappear.
    assert records(circuit) == [
        (1, 2, 4),
        (3, 6, 0),
        (2, 1, 7),
        (1, 3, 5),
        (3, 9, 0),
        (2, 8, 10),
    ]


def test_first_magnitude_product_keeps_zero_ripple_and_terminal_carry():
    e = Emitter(4, limits=Limits())
    result = words._mul_checked(e, e.inputs[:2], e.inputs[2:])
    circuit = e.finish(result.valid)
    # Two independently expanded signed2 magnitudes consume 27 gates each;
    # selected low bits are (26,29) and (53,56). First raw partial is (60,61).
    # Four-bit addition starts with zero. All-public operations alone fold;
    # the high terminal carry is still XOR(0,76), output 77, even if unused.
    assert records(circuit)[54:72] == [
        (2, 26, 53),
        (2, 29, 53),
        (1, 0, 60),
        (1, 62, 0),
        (2, 0, 60),
        (2, 62, 0),
        (1, 64, 65),
        (1, 0, 61),
        (1, 67, 66),
        (2, 0, 61),
        (2, 67, 66),
        (1, 69, 70),
        (1, 0, 71),
        (2, 0, 71),
        (1, 0, 73),
        (1, 0, 74),
        (2, 0, 74),
        (1, 0, 76),
    ]


def test_all_64_shifted_partials_use_full_128_bit_ripple(monkeypatch):
    original = words._ripple
    calls = []

    def observe(e, a, b, carry):
        calls.append((a, b, carry))
        return original(e, a, b, carry)

    monkeypatch.setattr(words, "_ripple", observe)
    e = Emitter(128, limits=Limits())
    words.mul64(e, e.inputs[:64], e.inputs[64:])
    # Two signed65 magnitude preparations, all 64 accumulation steps, sign negation.
    assert [len(a) for a, _, _ in calls] == [65, 65] + [128] * 65
    partials = calls[2:66]
    assert partials[0][0] == (e.zero,) * 128
    for shift, (a, partial, carry) in enumerate(partials):
        assert len(a) == len(partial) == 128
        assert carry == e.zero
        assert partial[:shift] == (e.zero,) * shift
        assert partial[shift + 64 :] == (e.zero,) * (64 - shift)
        assert all(bit.public is None for bit in partial[shift : shift + 64])
