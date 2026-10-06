"""Experimental public-constant mod-q multiplication; NOT canonical BC-1.

No private-by-private API or whole-transform lowering. The production signed64
gadgets are unchanged. All private computations emit fixed XOR/AND/NOT schedules.
"""

from dataclasses import dataclass

from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Bit

Q = 8380417


@dataclass(frozen=True)
class KernelResult:
    value: ring.Scalar
    valid: Bit


def _entry(scope: Scope, value: ring.Scalar, factor: int):
    # Reject before emitting anything, including when factor is a symbolic Bit.
    if type(factor) is not int or not 0 <= factor < Q:
        raise ValueError("factor must be a public canonical integer modulo q")
    ring._check(scope, value)
    if value.domain is not ring.Domain.NTT:
        raise ValueError("kernel requires an NTT-domain scalar")
    e = scope.e
    high_zero = e.one
    for bit in value.value[23:]:
        high_zero = e.and_(high_zero, e.not_(bit))
    low = value.value[:23]
    difference = w._subtract(e, (*low, e.zero, e.zero), w.constant(e, Q, 25))
    scope.require(e.and_(high_zero, difference[-1]))
    return low


def _finish(scope: Scope, value: w.Word) -> KernelResult:
    e = scope.e
    usable = e.and_(scope.active, e.not_(scope.rejected))
    # Identical full64 output-mask schedule for candidate and matched baseline.
    masked = tuple(e.and_(usable, bit) for bit in value)
    return KernelResult(ring.Scalar(masked, ring.Domain.NTT), scope.output(()))


def _mark(scope, phases, name):
    if phases is not None:
        phases.append(
            {"phase": name, "gates": scope.e.counts.gates, "and_gates": scope.e.counts.and_}
        )


def ntt_mul_public_q(scope: Scope, value: ring.Scalar, factor: int, *, phases=None):
    """Accept active signed64 input iff canonical; return masked64 and sticky valid.

    The upper41 bits must be zero and low23 < q. An inactive fault does not reject;
    previous rejection never clears. Inactive/rejected values are unusable zeroes.
    Constants and domain/word structure are checked at construction, not in-circuit.
    """
    low = _entry(scope, value, factor)
    e = scope.e
    _mark(scope, phases, "canonical_guard")
    public = w.constant(e, factor, 23)
    product = (e.zero,) * 46
    for i in range(23):
        raw = tuple(e.and_(public[j], low[i]) for j in range(23))
        partial = (e.zero,) * i + raw + (e.zero,) * (23 - i)
        product, _carry = w._ripple(e, product, partial, e.zero)
    _mark(scope, phases, "exact46_product")

    # Each partial sum <= final product < 2**46, even on speculative low23.
    # Prefix invariant: remainder < q and equals the consumed prefix modulo q.
    remainder = (e.zero,) * 23
    denominator = w.constant(e, Q, 25)
    for i in range(45, -1, -1):
        trial = (product[i], *remainder, e.zero)
        difference = w._subtract(e, trial, denominator)
        take = e.not_(difference[-1])
        remainder = w.mux_word(e, take, trial, difference)[:23]
    _mark(scope, phases, "complete46_restoring_steps")
    result = _finish(scope, (*remainder, *((e.zero,) * 41)))
    _mark(scope, phases, "output_mask_and_final_validity")
    return result


def baseline(scope: Scope, value: ring.Scalar, factor: int, *, phases=None):
    """Fully matched guarded interface over the unchanged signed64 core."""
    _entry(scope, value, factor)
    _mark(scope, phases, "canonical_guard")
    public = ring.Scalar(w.constant(scope.e, factor, 64), ring.Domain.NTT)
    product = ring.ntt_pointwise_multiply(scope, public, value)
    _mark(scope, phases, "checked_signed64_product_and_SPEC004_mod")
    result = _finish(scope, product.value)
    _mark(scope, phases, "output_mask_and_final_validity")
    return result
