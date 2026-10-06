"""Checked scalar FIPS ring operations and verifier decomposition/hint helpers.

All integer words remain signed64. Every arithmetic result is checked BEFORE
mod-q reduction. Domains distinguish coefficient scalars from NTT slots; no API
here implements polynomial multiplication, a full transform or ML-DSA verification.
"""

from dataclasses import dataclass
from enum import Enum

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import centred64, div64, mod64
from pqdid.circuits.emitter import Bit

Q = 8380417
GAMMA2 = (Q - 1) // 32
GAMMA1_MINUS_BETA = (1 << 19) - 196


class Domain(Enum):
    COEFFICIENT = "coefficient"
    NTT = "ntt"


@dataclass(frozen=True)
class Scalar:
    value: w.Word
    domain: Domain


def _check(scope: Scope, scalar: Scalar):
    if type(scalar) is not Scalar or type(scalar.domain) is not Domain:
        raise ValueError("expected a scalar with explicit coefficient/NTT domain")
    w.check_word(scope.e, scalar.value, 64)


def reduce_scalar(scope: Scope, scalar: Scalar) -> Scalar:
    _check(scope, scalar)
    return Scalar(scope.checked(mod64(scope.e, scalar.value, Q)), scalar.domain)


def _binary(scope: Scope, a: Scalar, b: Scalar, operation) -> Scalar:
    _check(scope, a)
    _check(scope, b)
    if a.domain is not b.domain:
        raise ValueError("scalar domains must agree")
    raw = scope.checked(operation(scope.e, a.value, b.value))
    return Scalar(scope.checked(mod64(scope.e, raw, Q)), a.domain)


def add(scope: Scope, a: Scalar, b: Scalar) -> Scalar:
    return _binary(scope, a, b, w.add64)


def subtract(scope: Scope, a: Scalar, b: Scalar) -> Scalar:
    return _binary(scope, a, b, w.sub64)


def multiply(scope: Scope, a: Scalar, b: Scalar) -> Scalar:
    """Scalar product, with a full checked 128-bit intermediate; not polynomial mul."""
    return _binary(scope, a, b, w.mul64)


def ntt_pointwise_multiply(scope: Scope, a: Scalar, b: Scalar) -> Scalar:
    _check(scope, a)
    _check(scope, b)
    if a.domain is not Domain.NTT or b.domain is not Domain.NTT:
        raise ValueError("pointwise product requires NTT-domain slots")
    return multiply(scope, a, b)


def ntt_butterfly(scope: Scope, left: Scalar, right: Scalar, zeta: int) -> tuple[Scalar, Scalar]:
    """One Algorithm 41 lines 12..14 update, product/right/left order, old left.

    Domain annotation does not itself perform a transform. The twiddle is public;
    supplied slots are private or public signed64 representatives. Reduce at each
    prescribed operation, using neither narrowed coefficients nor Montgomery form.
    """
    _check(scope, left)
    _check(scope, right)
    if left.domain is not Domain.NTT or right.domain is not Domain.NTT:
        raise ValueError("butterfly requires NTT-domain slots")
    if type(zeta) is not int or not 0 <= zeta < Q:
        raise ValueError("forward NTT twiddle must be a public canonical residue")
    twiddle = Scalar(w.constant(scope.e, zeta, 64), Domain.NTT)
    product = ntt_pointwise_multiply(scope, twiddle, right)
    new_right = subtract(scope, left, product)
    new_left = add(scope, left, product)
    return new_left, new_right


def decompose(scope: Scope, value: w.Word) -> tuple[w.Word, w.Word]:
    """FIPS 204 Algorithm 36, including the q-1 exceptional pair and both branches."""
    e = scope.e
    positive = scope.checked(mod64(e, value, Q))
    low = scope.checked(centred64(e, positive, 2 * GAMMA2))
    difference = scope.checked(w.sub64(e, positive, low))
    special = w.equal(e, difference, w.constant(e, Q - 1, 64))

    def when_true(active):
        high = w.constant(e, 0, 64)
        corrected_low = active.checked(w.sub64(e, low, w.constant(e, 1, 64)))
        return (*high, *corrected_low)

    def when_false(active):
        # FIPS line 6 repeats this expression; do not reuse the condition's result.
        numerator = active.checked(w.sub64(e, positive, low))
        high = active.checked(div64(e, numerator, 2 * GAMMA2))
        return (*high, *low)

    combined = scope.branch(special, when_true, when_false)
    return combined[:64], combined[64:]


def high_bits(scope: Scope, value: w.Word) -> w.Word:
    return decompose(scope, value)[0]


def low_bits(scope: Scope, value: w.Word) -> w.Word:
    return decompose(scope, value)[1]


def use_hint(scope: Scope, hint: Bit, value: w.Word) -> w.Word:
    """Algorithm 40, sequential return conditions with active-path rejection.

    hint is one Boolean wire from the eventual hint decoder, not an unchecked byte.
    All branches are constructed; outputs are 64-bit integers in 0..15.
    """
    e = scope.e
    e.check_bit(hint)
    high, low = decompose(scope, value)
    first = e.and_(hint, w.less64(e, w.constant(e, 0, 64), low))

    def when_true(active):
        raised = active.checked(w.add64(e, high, w.constant(e, 1, 64)))
        return active.checked(mod64(e, raised, 16))

    def when_false(active):
        second = e.and_(hint, w.less_equal64(e, low, w.constant(e, 0, 64)))

        def lowered(second_scope):
            changed = second_scope.checked(w.sub64(e, high, w.constant(e, 1, 64)))
            return second_scope.checked(mod64(e, changed, 16))

        return active.branch(second, lowered, lambda _: high)

    return scope.branch(first, when_true, when_false)


def norm_ok(scope: Scope, value: w.Word) -> Bit:
    """Algorithm 8 final scalar |z|<gamma1-beta; no early verification shortcut."""
    e = scope.e
    w.check_word(e, value, 64)
    magnitude = scope.branch(
        value[-1],
        lambda active: active.checked(w.sub64(e, w.constant(e, 0, 64), value)),
        lambda _: value,
    )
    return w.less64(e, magnitude, w.constant(e, GAMMA1_MINUS_BETA, 64))
