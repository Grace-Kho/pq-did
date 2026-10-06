"""Checked signed64 division by a public non-negative constant.

BC-1 prescribes a high-to-low magnitude scan and signed floor correction. The
explicit restoring schedule below adopts the user-agreed SPEC-004 clarification;
full BC-1 conformance is not claimed. Zero produces invalidity, never
acceptance. Negative/private divisors are outside the positive-constant profile.
"""

from dataclasses import dataclass

from pqdid.circuits import words as w
from pqdid.circuits.emitter import Bit, Emitter


@dataclass(frozen=True)
class DivMod:
    quotient: w.Word
    remainder: w.Word
    valid: Bit
    quotient_wide: w.Word
    remainder_wide: w.Word


def _divmod_const(e: Emitter, dividend: w.Word, divisor: int) -> DivMod:
    """Reduced widths are for exhaustive tests; public entry points require 64.

    Internal magnitude remainder/difference and signed correction use n+1 bits.
    Each of n rounds computes trial=(remainder<<1)|input_bit by rewiring, one
    full-width subtraction, its sign test, then the prescribed mux. Retain carries.
    No private bit controls a host branch; zero uses this same fixed schedule.
    """
    w.check_word(e, dividend)
    width = len(dividend)
    if width > 64 or type(divisor) is not int or not 0 <= divisor < 1 << (width - 1):
        raise ValueError("division requires a public non-negative signed-word constant")
    magnitude = w._magnitude(e, dividend)
    denominator = w.constant(e, divisor, width + 1)
    remainder = (e.zero,) * (width + 1)
    quotient = [e.zero] * width
    for position in range(width - 1, -1, -1):
        # For a valid divisor, the prefix is at most 2**(n-1). The extra bit
        # keeps MIN's unsigned magnitude and the signed difference representable.
        trial = (magnitude[position], *remainder[:-1])
        difference = w._subtract(e, trial, denominator)
        take = e.not_(difference[-1])
        remainder = w.mux_word(e, take, trial, difference)
        quotient[position] = take
    q65 = (*quotient, e.zero)
    zero = (e.zero,) * (width + 1)
    nz = e.not_(w.equal(e, remainder, zero))
    negative_q = w._subtract(e, zero, q65)
    negative_q_minus_one = w._subtract(e, negative_q, w.constant(e, 1, width + 1))
    corrected_negative_q = w.mux_word(e, nz, negative_q, negative_q_minus_one)
    b_minus_r = w._subtract(e, denominator, remainder)
    # SPEC-004 explicitly fixes this false arm to public zero, not R. Do not
    # substitute an equivalent private expression: that changes trace identity.
    corrected_negative_r = w.mux_word(e, nz, zero, b_minus_r)
    output_q = w.mux_word(e, dividend[-1], q65, corrected_negative_q)
    output_r = w.mux_word(e, dividend[-1], remainder, corrected_negative_r)
    q = w._narrow(e, output_q, width)
    r = w._narrow(e, output_r, width)
    representable = e.and_(q.valid, r.valid)
    valid = e.and_(representable, e.constant(int(divisor > 0)))
    return DivMod(q.value, r.value, valid, q.wide, r.wide)


def divmod64(e: Emitter, dividend: w.Word, divisor: int) -> DivMod:
    """a=b*q+r with q=floor(a/b), 0<=r<b; b is public, 1..2**63-1.

    b=0 returns valid=0 with unusable result wires. Callers must retain validity
    in Scope; equality/reduction of those result wires cannot discharge that fault.
    No quotient/remainder witness or narrower integer profile is introduced.
    """
    w.check_word(e, dividend, 64)
    return _divmod_const(e, dividend, divisor)


def div64(e: Emitter, dividend: w.Word, divisor: int) -> w.Checked:
    result = divmod64(e, dividend, divisor)
    return w.Checked(result.quotient, result.valid, result.quotient_wide)


def mod64(e: Emitter, dividend: w.Word, modulus: int) -> w.Checked:
    result = divmod64(e, dividend, modulus)
    return w.Checked(result.remainder, result.valid, result.remainder_wide)


def centred64(e: Emitter, dividend: w.Word, modulus: int) -> w.Checked:
    """FIPS 204 §2.3: -ceil(b/2) < r <= floor(b/2), including even ties."""
    result = mod64(e, dividend, modulus)
    high = w.less64(e, w.constant(e, modulus // 2, 64), result.value)
    shifted = w.sub64(e, result.value, w.constant(e, modulus, 64))
    wide = w.mux_word(e, high, result.wide, shifted.wide)
    # Narrowing/copying reuses the selected wires; do not emit a second low-word mux.
    value = wide[:64]
    # A speculative inactive subtraction cannot reject the selected branch.
    valid = e.and_(result.valid, e.mux(high, e.one, shifted.valid))
    return w.Checked(value, valid, wide)
