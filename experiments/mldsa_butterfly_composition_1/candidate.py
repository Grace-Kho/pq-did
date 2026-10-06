"""Experimental full-signed-domain forward butterfly; NOT canonical BC-1.

Preserve the original checked integer acceptance, then compute canonical outputs.
No implicit range restriction, trusted-input variant or Montgomery scaling.
"""

from dataclasses import dataclass

from experiments.mldsa_modmul_lowering_1.candidate import ntt_mul_public_q
from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import mod64
from pqdid.circuits.emitter import Bit

Q = 8380417
MIN = -(1 << 63)
MAX = (1 << 63) - 1


@dataclass(frozen=True)
class ButterflyResult:
    left: ring.Scalar
    right: ring.Scalar
    valid: Bit


def _entry(scope, left, right, zeta):
    if type(zeta) is not int or not 0 <= zeta < Q:
        raise ValueError("twiddle must be a public canonical integer modulo q")
    ring._check(scope, left)
    ring._check(scope, right)
    if left.domain is not ring.Domain.NTT or right.domain is not ring.Domain.NTT:
        raise ValueError("forward butterfly requires NTT-domain scalars")


def _mark(scope, phases, name):
    if phases is not None:
        phases.append(
            {"phase": name, "gates": scope.e.counts.gates, "and_gates": scope.e.counts.and_}
        )


def _finish(scope, left, right):
    e = scope.e
    usable = e.and_(scope.active, e.not_(scope.rejected))
    return ButterflyResult(
        ring.Scalar(tuple(e.and_(usable, bit) for bit in left), ring.Domain.NTT),
        ring.Scalar(tuple(e.and_(usable, bit) for bit in right), ring.Domain.NTT),
        scope.output(()),
    )


def baseline(scope: Scope, left, right, zeta, *, phases=None):
    _entry(scope, left, right, zeta)
    a, b = ring.ntt_butterfly(scope, left, right, zeta)
    _mark(scope, phases, "original_checked_butterfly")
    result = _finish(scope, a.value, b.value)
    _mark(scope, phases, "full64_output_masks_and_validity")
    return result


def forward(scope: Scope, left, right, zeta, *, phases=None):
    """Same active acceptance as ring.ntt_butterfly for every signed64 pair.

    Positive public zeta: MIN <= zeta*b <= MAX iff ceil(MIN/zeta) <= b
    <= floor(MAX/zeta). Retain raw-left +/- canonical-product overflow checks.
    Invalid/inactive outputs are masked zero; sticky Scope rejection is retained.
    """
    _entry(scope, left, right, zeta)
    e = scope.e
    if zeta == 0:  # Public construction choice only; no division by zero.
        product_fits = e.one
    else:
        low = w.constant(e, -((1 << 63) // zeta), 64, signed=True)
        high = w.constant(e, MAX // zeta, 64, signed=True)
        product_fits = e.and_(
            e.not_(w.less64(e, right.value, low)),
            e.not_(w.less64(e, high, right.value)),
        )
    scope.require(product_fits)
    _mark(scope, phases, "exact_original_product_overflow_condition")

    # All signed64 representatives remain admitted subject to original overflow.
    # These complete SPEC-004 conversions are included, even at later stages.
    a = scope.checked(mod64(e, left.value, Q))
    b = scope.checked(mod64(e, right.value, Q))
    _mark(scope, phases, "two_complete_signed64_to_canonical_conversions")
    product = ntt_mul_public_q(scope, ring.Scalar(b, ring.Domain.NTT), zeta)
    p = product.value.value
    _mark(scope, phases, "guarded_scalar_modmul_including_its_output_boundary")

    # Original right update precedes left update. The checked raw results are
    # deliberately not replaced by unchecked modular congruence.
    scope.checked(w.sub64(e, left.value, p))
    a25, p25 = (*a[:23], e.zero, e.zero), (*p[:23], e.zero, e.zero)
    difference = w._subtract(e, a25, p25)
    corrected, _carry = w._ripple(e, difference, w.constant(e, Q, 25), e.zero)
    new_right = w.mux_word(e, difference[-1], difference, corrected)[:23]
    _mark(scope, phases, "checked_raw_subtraction_and_canonical_negative_correction")

    scope.checked(w.add64(e, left.value, p))
    total, _carry = w._ripple(e, (*a[:23], e.zero), (*p[:23], e.zero), e.zero)
    trial = (*total, e.zero)
    difference = w._subtract(e, trial, w.constant(e, Q, 25))
    new_left = w.mux_word(e, e.not_(difference[-1]), trial, difference)[:23]
    _mark(scope, phases, "checked_raw_addition_and_canonical_q_correction")
    result = _finish(scope, (*new_left, *((e.zero,) * 41)), (*new_right, *((e.zero,) * 41)))
    _mark(scope, phases, "full64_output_masks_and_validity")
    return result


def schedule_fragment(scope, values, kernel, *, phases=None):
    """Two connected nodes of the real forward schedule, not two complete layers.

    Inputs: initial slots0/128 and the already updated stage1 slot64. The producer
    of that third frontier input is outside this fragment and is not proved here.
    First node: len128,start0,j0,m1. Second: len64,start0,j0,m2.
    """
    first = kernel(scope, values[0], values[1], 4808194, phases=phases)
    second = kernel(scope, first.left, values[2], 3765607, phases=phases)
    return first, second
