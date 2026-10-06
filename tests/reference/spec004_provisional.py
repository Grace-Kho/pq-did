"""Frozen pre-adoption construction, for trace comparison only.

This is not an independent mathematical oracle or a production alternative.
Original division.py SHA-256: c530930c04f91bcdf4bceaf5d052f940cc935e87cca6562baf119ad41b8574a8
"""

from pqdid.circuits import words as w
from pqdid.circuits.division import DivMod
from pqdid.circuits.emitter import Emitter


def provisional_divmod(e: Emitter, dividend: w.Word, divisor: int) -> DivMod:
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
    positive_q = (*quotient, e.zero)
    zero = (e.zero,) * (width + 1)
    nonzero_r = e.not_(w.equal(e, remainder, zero))
    negative_q = w._subtract(e, zero, positive_q)
    rounded_q = w._subtract(e, negative_q, w.constant(e, 1, width + 1))
    corrected_q = w.mux_word(e, nonzero_r, negative_q, rounded_q)
    complemented_r = w._subtract(e, denominator, remainder)
    corrected_r = w.mux_word(e, nonzero_r, remainder, complemented_r)
    signed_q = w.mux_word(e, dividend[-1], positive_q, corrected_q)
    signed_r = w.mux_word(e, dividend[-1], remainder, corrected_r)
    q = w._narrow(e, signed_q, width)
    r = w._narrow(e, signed_r, width)
    valid = e.and_(e.constant(int(divisor > 0)), e.and_(q.valid, r.valid))
    return DivMod(q.value, r.value, valid, q.wide, r.wide)
