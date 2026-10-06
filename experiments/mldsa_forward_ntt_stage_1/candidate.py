"""Isolated four-lane/two-stage forward fragment, NOT canonical BC-1.

Only C/D consume certified producer outputs without repeating mod64. A/B retain
all generic signed64 conversions/checks. No full transform or inverse operation.
"""

from dataclasses import dataclass

from experiments.mldsa_butterfly_composition_1.candidate import (
    MAX,
    Q,
    _entry,
    _finish,
    _mark,
    baseline,
    forward,
)
from experiments.mldsa_modmul_lowering_1.candidate import ntt_mul_public_q
from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Bit

LANES = (0, 64, 128, 192)
# (name, left/right positions within LANES, ordinary twiddle, twiddle index)
FIRST = (("A", 0, 2, 4808194, 1), ("B", 1, 3, 4808194, 1))
SECOND = (("C", 0, 1, 3765607, 2), ("D", 2, 3, 3761513, 3))


@dataclass(frozen=True)
class FragmentResult:
    words: tuple[w.Word, ...]
    valid: Bit
    nodes: tuple


def _from_canonical_producers(scope: Scope, left, right, zeta, *, phases=None):
    """Internal only: both inputs are masked canonical outputs of this fragment.

    Reuse the earlier lowering verbatim except its two redundant mod64 calls.
    The only call sites are C/D below, wired from A/B. No raw-input entry flag.
    All original overflow checks, scalar guards and output masks are retained.
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

    # A/B establish canonicality even on rejected/inactive paths (masked zero).
    # This is an internal graph edge, never a caller-provided canonicality claim.
    a, b = left.value, right.value
    _mark(scope, phases, "producer_canonical_representation_reused_no_mod64")
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


def _inputs(scope, values):
    if type(values) is not tuple or len(values) != 4:
        raise ValueError("exactly four signed64 NTT Scalar inputs required")
    for value in values:
        ring._check(scope, value)
        if value.domain is not ring.Domain.NTT:
            raise ValueError("forward fragment requires NTT-domain slots")


def _stage(scope, state, entries, kernel, phases):
    nodes = []
    for name, left, right, zeta, index in entries:
        local = [] if phases is not None else None
        result = kernel(scope, state[left], state[right], zeta, phases=local)
        state[left], state[right] = result.left, result.right
        nodes.append(result)
        if phases is not None:
            phases.append({"node": name, "twiddle_index": index, "steps": local})
    return nodes


def _boundary(scope, state, nodes, phases):
    # Re-mask ALL final lanes with the final predicate. A later failure cannot
    # expose an earlier node's otherwise valid result as a partial fragment.
    e = scope.e
    usable = e.and_(scope.active, e.not_(scope.rejected))
    words = tuple(tuple(e.and_(usable, bit) for bit in value.value) for value in state)
    result = FragmentResult(words, scope.output(()), tuple(nodes))
    _mark(scope, phases, "all_four_final_lanes_masked_by_final_scope")
    return result


def fragment(scope, values, profile, *, phases=None):
    """External full signed64 contract, with fixed A/B/C/D dependencies.

    baseline: unchanged production butterfly via prior masked wrapper.
    fully-guarded: prior experimental forward butterfly at all four nodes.
    candidate: same A/B, with internal canonical reuse at C/D only.
    """
    if profile not in {"baseline", "fully-guarded", "candidate"}:
        raise ValueError("unknown fixed experimental fragment profile")
    _inputs(scope, values)
    state = list(values)
    first_kernel = baseline if profile == "baseline" else forward
    nodes = _stage(scope, state, FIRST, first_kernel, phases)
    second_kernel = _from_canonical_producers if profile == "candidate" else first_kernel
    nodes.extend(_stage(scope, state, SECOND, second_kernel, phases))
    return _boundary(scope, state, nodes, phases)


def reference_partition(scope, values, *, second, phases=None):
    """Test-only reference partition; whole-graph costs are counted separately.

    First partition exposes internal snapshots plus the carried scope predicate.
    Second receives those exact snapshots and predicate from the first partition.
    Neither partition is a standalone authentication/verification endpoint.
    """
    _inputs(scope, values)
    state = list(values)
    nodes = _stage(scope, state, SECOND if second else FIRST, baseline, phases)
    if second:
        return _boundary(scope, state, nodes, phases)
    return FragmentResult(tuple(value.value for value in state), nodes[-1].valid, tuple(nodes))
