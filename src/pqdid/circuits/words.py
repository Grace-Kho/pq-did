"""BC-1 Boolean/bitstring and checked signed-word foundation.

All word tuples are LSB-first. Public signed operations require 64 bits; private
computation consists only of emitted gates. Underscored width helpers support
exhaustive reduced-width tests, not alternative protocol integer profiles.
"""

from dataclasses import dataclass

from pqdid.circuits.emitter import Bit, Emitter

type Word = tuple[Bit, ...]


def check_word(e: Emitter, word: Word, width: int | None = None):
    e.poll()
    if (
        type(word) is not tuple
        or not 1 <= len(word) <= 128
        or (width is not None and len(word) != width)
    ):
        raise ValueError("invalid bitstring width")
    for bit in word:
        e.check_bit(bit)


def constant(e: Emitter, value: int, width: int, *, signed: bool = False) -> Word:
    if type(width) is not int or not 1 <= width <= 128 or type(value) is not int:
        raise ValueError("invalid public word")
    low, high = (-(1 << (width - 1)), 1 << (width - 1)) if signed else (0, 1 << width)
    if not low <= value < high:
        raise ValueError("public word is out of range")
    return tuple(e.constant((value >> i) & 1) for i in range(width))


def from_serialised(e: Emitter, bits: Word, *, byte_order: str = "big") -> Word:
    """MSB-first byte-input positions to arithmetic bit order by rewiring only."""
    check_word(e, bits)
    if len(bits) % 8 or byte_order not in ("big", "little"):
        raise ValueError("expected whole bytes and explicit byte order")
    if byte_order == "big":
        return tuple(reversed(bits))
    return tuple(
        bit for start in range(0, len(bits), 8) for bit in reversed(bits[start : start + 8])
    )


def to_serialised(e: Emitter, word: Word, *, byte_order: str = "big") -> Word:
    # Both permutations are their own inverse.
    return from_serialised(e, word, byte_order=byte_order)


def bit_shift(e: Emitter, word: Word, amount: int) -> Word:
    """Logical bitstring shift; positive left, negative right. Not integer shift."""
    check_word(e, word)
    if type(amount) is not int:
        raise ValueError("bitstring shift must be public")
    return tuple(
        word[i - amount] if 0 <= i - amount < len(word) else e.zero for i in range(len(word))
    )


def rotate_left(e: Emitter, word: Word, amount: int) -> Word:
    check_word(e, word)
    if type(amount) is not int:
        raise ValueError("bitstring rotation must be public")
    return tuple(word[(i - amount) % len(word)] for i in range(len(word)))


def mux_word(e: Emitter, selector: Bit, a: Word, b: Word) -> Word:
    check_word(e, a)
    check_word(e, b, len(a))
    return tuple(e.mux(selector, left, right) for left, right in zip(a, b, strict=True))


def equal(e: Emitter, a: Word, b: Word) -> Bit:
    check_word(e, a)
    check_word(e, b, len(a))
    result = e.one
    for left, right in zip(a, b, strict=True):
        xnor = e.not_(e.xor(left, right))
        result = e.and_(result, xnor)
    return result


def _extend(word: Word) -> Word:
    return (*word, word[-1])


def _ripple(e: Emitter, a: Word, b: Word, carry: Bit) -> tuple[Word, Bit]:
    check_word(e, a)
    check_word(e, b, len(a))
    result = []
    for left, right in zip(a, b, strict=True):
        t = e.xor(left, right)
        result.append(e.xor(t, carry))
        ab = e.and_(left, right)
        tc = e.and_(t, carry)
        carry = e.xor(ab, tc)
    return tuple(result), carry


def _subtract(e: Emitter, a: Word, b: Word) -> Word:
    inverted = tuple(e.not_(bit) for bit in b)
    return _ripple(e, a, inverted, e.one)[0]


@dataclass(frozen=True)
class Checked:
    value: Word
    valid: Bit
    wide: Word


def _narrow(e: Emitter, wide: Word, width: int) -> Checked:
    # Compute representability before exposing low bits. Consumers must require
    # valid (through Scope.checked) before using this as an accepted integer.
    valid = e.one
    for bit in wide[width:]:
        valid = e.and_(valid, e.not_(e.xor(bit, wide[width - 1])))
    return Checked(wide[:width], valid, wide)


def _add_checked(e: Emitter, a: Word, b: Word) -> Checked:
    check_word(e, a)
    check_word(e, b, len(a))
    wide, _ = _ripple(e, _extend(a), _extend(b), e.zero)
    return _narrow(e, wide, len(a))


def _sub_checked(e: Emitter, a: Word, b: Word) -> Checked:
    check_word(e, a)
    check_word(e, b, len(a))
    wide = _subtract(e, _extend(a), _extend(b))
    return _narrow(e, wide, len(a))


def _less(e: Emitter, a: Word, b: Word) -> Bit:
    check_word(e, a)
    check_word(e, b, len(a))
    return _subtract(e, _extend(a), _extend(b))[-1]


def _magnitude(e: Emitter, word: Word) -> Word:
    extended = _extend(word)
    negative = _subtract(e, (e.zero,) * len(extended), extended)
    # |signed n-bit value| fits an UNSIGNED n-bit magnitude, including MIN.
    return mux_word(e, word[-1], extended, negative)[: len(word)]


def _mul_checked(e: Emitter, a: Word, b: Word) -> Checked:
    check_word(e, a)
    check_word(e, b, len(a))
    width = len(a)
    if width > 64:
        raise ValueError("multiplication exceeds 128-bit intermediate")
    left = _magnitude(e, a)
    right = _magnitude(e, b)
    total = (e.zero,) * (2 * width)
    for i in range(width):
        raw = tuple(e.and_(left[j], right[i]) for j in range(width))
        partial = (e.zero,) * i + raw + (e.zero,) * (width - i)
        total, _ = _ripple(e, total, partial, e.zero)
    sign = e.xor(a[-1], b[-1])
    negative = _subtract(e, (e.zero,) * len(total), total)
    signed = mux_word(e, sign, total, negative)
    return _narrow(e, signed, width)


def add64(e: Emitter, a: Word, b: Word) -> Checked:
    check_word(e, a, 64)
    check_word(e, b, 64)
    return _add_checked(e, a, b)


def sub64(e: Emitter, a: Word, b: Word) -> Checked:
    check_word(e, a, 64)
    check_word(e, b, 64)
    return _sub_checked(e, a, b)


def mul64(e: Emitter, a: Word, b: Word) -> Checked:
    check_word(e, a, 64)
    check_word(e, b, 64)
    return _mul_checked(e, a, b)


def less64(e: Emitter, a: Word, b: Word) -> Bit:
    check_word(e, a, 64)
    check_word(e, b, 64)
    return _less(e, a, b)


def less_equal64(e: Emitter, a: Word, b: Word) -> Bit:
    # Derived predicate: a < b OR a == b, preserving argument order.
    less = less64(e, a, b)
    same = equal(e, a, b)
    return e.or_(less, same)
