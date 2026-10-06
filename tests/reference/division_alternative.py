"""Diagnostic compare-then-subtract recipe, NEVER a production compilation path.

This intentionally imports BC-1 primitives to isolate SPEC-004's emission choice;
it is not the independent mathematical oracle (scalar_oracle.py provides that).
"""

from pqdid.circuits import words as w
from pqdid.circuits.division import DivMod


def separate_compare_and_subtract(e, dividend, divisor):
    width = len(dividend)
    magnitude = w._magnitude(e, dividend)
    denominator = w.constant(e, divisor, width + 1)
    remainder = (e.zero,) * (width + 1)
    quotient = [e.zero] * width
    for position in range(width - 1, -1, -1):
        trial = (magnitude[position], *remainder[:-1])
        comparison_difference = w._subtract(e, trial, denominator)
        take = e.not_(comparison_difference[-1])
        # Distinct written operation; no reuse/CSE of comparison's subtraction.
        difference = w._subtract(e, trial, denominator)
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
