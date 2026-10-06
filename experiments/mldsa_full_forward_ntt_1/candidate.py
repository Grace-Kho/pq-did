"""Isolated forward-only partition wrappers; NOT canonical BC-1 or a proof.

Entry establishes canonicality for all witnesses. Subsequent uses of the pinned
internal stage kernel are justified only by these connected producer boundaries.
No fixture value or caller canonicality flag participates in construction.
"""

from dataclasses import dataclass

from experiments.mldsa_forward_ntt_stage_1.candidate import _from_canonical_producers
from pqdid.bounded_mldsa import _ZETAS
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import mod64
from pqdid.circuits.scalar_ring import Domain, Q, Scalar, _check

INPUTS = 16_386
MIN, MAX = -(1 << 63), (1 << 63) - 1


def admit_polynomial(values):
    if type(values) is not tuple or len(values) != 256:
        raise ValueError("exactly 256 signed64 coefficients required")
    if any(type(v) is not int or not MIN <= v <= MAX for v in values):
        raise ValueError("exact signed64 integer coefficients required")
    return values


@dataclass(frozen=True)
class Boundary:
    words: tuple
    active: object
    rejected: object
    output: object
    work: tuple
    entry_counts: tuple


def build(e, ordinal):
    """One public partition of the approved 32+64+1 schedule."""
    if type(ordinal) is not int or not 0 <= ordinal < 97 or len(e.inputs) != INPUTS:
        raise ValueError("fixed partition/input contract")
    state = [w.from_serialised(e, e.inputs[64 * i : 64 * (i + 1)]) for i in range(256)]
    scope = Scope(e, active=e.inputs[-2])
    scope.rejected = e.inputs[-1]
    domain = Domain.COEFFICIENT if ordinal < 32 else Domain.NTT
    for word in state:
        _check(scope, Scalar(word, domain))
    work, entry_counts = [], []
    if ordinal < 32:
        for lane in range(8 * ordinal, 8 * ordinal + 8):
            before = e.counts
            value = scope.checked(mod64(e, state[lane], Q))
            after = e.counts
            usable = e.and_(scope.active, e.not_(scope.rejected))
            state[lane] = tuple(e.and_(usable, bit) for bit in value)
            end = e.counts
            entry_counts.append(
                (
                    after.gates - before.gates,
                    after.and_ - before.and_,
                    end.gates - after.gates,
                    end.and_ - after.and_,
                )
            )
            work.append((lane,))
    elif ordinal < 96:
        stage, batch = divmod(ordinal - 32, 8)
        length = 128 >> stage
        for t in range(16 * batch, 16 * batch + 16):
            group, offset = divmod(t, length)
            left = 2 * length * group + offset
            right = left + length
            m = (1 << stage) + group
            zeta = _ZETAS[m]
            result = _from_canonical_producers(
                scope, Scalar(state[left], Domain.NTT), Scalar(state[right], Domain.NTT), zeta
            )
            state[right], state[left] = result.right.value, result.left.value
            work.append((stage, group, offset, left, right, m, zeta))
    else:
        usable = e.and_(scope.active, e.not_(scope.rejected))
        state = [tuple(e.and_(usable, bit) for bit in word) for word in state]
    output = scope.output(()) if ordinal == 96 else scope.rejected
    return Boundary(
        tuple(state), scope.active, scope.rejected, output, tuple(work), tuple(entry_counts)
    )
