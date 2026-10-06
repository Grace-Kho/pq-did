"""Private FIPS 204 Algorithms 19/21/27 input decoding, never verification.

All loop bounds and slices below are public. Hint reads/writes retain BC-1's
signed64 selectors and complete cell scans, including masked iterations. The full
decoder can exceed operational limits; a ResourceLimit is not a decoded result.
"""

from dataclasses import dataclass

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Bit, Emitter
from pqdid.circuits.parsing import Bytes, check_bytes, reverse_byte_bits
from pqdid.circuits.scalar_ring import norm_ok

N, K, L, OMEGA, GAMMA1 = 256, 6, 5, 55, 1 << 19
type Polynomial = tuple[w.Word, ...]


@dataclass(frozen=True, repr=False)
class ResponseDecoding:
    challenge_hash: Bytes
    responses: tuple[Polynomial, ...]
    encoded_hints: Bytes
    valid: Bit


@dataclass(frozen=True, repr=False)
class HintDecoding:
    hints: tuple[Polynomial, ...]
    valid: Bit


@dataclass(frozen=True, repr=False)
class SignatureDecoding:
    challenge_hash: Bytes
    responses: tuple[Polynomial, ...]
    hints: tuple[Polynomial, ...]
    valid: Bit


@dataclass(frozen=True, repr=False)
class ResponseNorm:
    within_bound: Bit
    arithmetic_valid: Bit


def _unsigned(e: Emitter, bits: w.Word) -> w.Word:
    return bits + (e.zero,) * (64 - len(bits))


def unpack_unsigned(e: Emitter, encoded: Bytes, width: int) -> Polynomial:
    """Algorithms 12/18: public-size FIPS bit conversion is purely rewiring."""
    if type(width) is not int or width not in (10, 20):
        raise ValueError("only the ML-DSA-65 public-key/response widths are supported")
    check_bytes(e, encoded, length=32 * width)
    bits = reverse_byte_bits(e, encoded)
    return tuple(_unsigned(e, bits[i * width : (i + 1) * width]) for i in range(N))


def decode_responses(scope: Scope, signature: Bytes) -> ResponseDecoding:
    """Algorithm 27 lines 1–4; all 20-bit strings decode, including norm failures."""
    e = scope.e
    check_bytes(e, signature, length=3309)
    responses = []
    for row in range(L):
        encoded = signature[8 * (48 + row * 640) : 8 * (48 + (row + 1) * 640)]
        unsigned = unpack_unsigned(e, encoded, 20)
        responses.append(
            tuple(scope.checked(w.sub64(e, w.constant(e, GAMMA1, 64), x)) for x in unsigned)
        )
    return ResponseDecoding(
        signature[:384], tuple(responses), signature[8 * 3248 :], e.not_(scope.rejected)
    )


def _hint_cells(e: Emitter, encoded: Bytes) -> tuple[w.Word, ...]:
    check_bytes(e, encoded, length=OMEGA + K)
    return tuple(w.from_serialised(e, encoded[i * 8 : (i + 1) * 8]) for i in range(OMEGA + K))


def _live(scope: Scope) -> Bit:
    return scope.e.and_(scope.active, scope.e.not_(scope.rejected))


def _merge(parent: Scope, child: Scope) -> None:
    parent.rejected = parent.e.or_(parent.rejected, child.rejected)


def _hint_boundary(scope: Scope, cells: tuple[w.Word, ...], index: w.Word, row: int) -> w.Word:
    """Algorithm 21 line 4; row is a public unrolled position."""
    if type(row) is not int or not 0 <= row < K:
        raise ValueError("invalid public hint row")
    e = scope.e
    end = _unsigned(e, cells[OMEGA + row])
    active = Scope(e, active=_live(scope))
    backwards = w.less64(e, end, index)
    over_capacity = w.less64(e, w.constant(e, OMEGA, 64), end)
    active.require(e.not_(e.or_(backwards, over_capacity)))
    _merge(scope, active)
    return end


def _hint_iteration(
    scope: Scope,
    cells: tuple[w.Word, ...],
    index: w.Word,
    first: w.Word,
    end: w.Word,
    polynomial: Polynomial,
) -> tuple[w.Word, Polynomial]:
    """One of the 55 masked iterations per row, Algorithms 21 lines 7–13.

    Test boundaries can exercise this exact step in isolation. Production always
    emits all 55 steps, for all six rows, with the source counter carried forward.
    Integer hint coefficients remain signed64 (0/1), not narrowed array cells.
    """
    e = scope.e
    step = Scope(e, active=e.and_(_live(scope), w.less64(e, index, end)))
    order = Scope(e, active=e.and_(step.active, w.less64(e, first, index)))
    previous_index = order.checked(w.sub64(e, index, w.constant(e, 1, 64)))
    previous = _unsigned(e, order.read(cells, previous_index))
    current = _unsigned(e, order.read(cells, index))
    # The source >= test, with BC-1's derived <=, then its rejecting return.
    order.require(e.not_(w.less_equal64(e, current, previous)))
    _merge(step, order)
    body = Scope(e, active=_live(step))
    # Re-read the written source expression; do not reuse the ordering read.
    position = _unsigned(e, body.read(cells, index))
    polynomial = body.write(polynomial, position, w.constant(e, 1, 64))
    incremented = body.checked(w.add64(e, index, w.constant(e, 1, 64)))
    index = w.mux_word(e, body.active, index, incremented)
    _merge(step, body)
    _merge(scope, step)
    return index, polynomial


def _hint_padding(scope: Scope, cells: tuple[w.Word, ...], index: w.Word) -> None:
    """Algorithm 21 lines 16–19: private initial i, 55 bounded masked scans."""
    e = scope.e
    position = index
    for _ in range(OMEGA):
        active = e.and_(_live(scope), w.less64(e, position, w.constant(e, OMEGA, 64)))
        step = Scope(e, active=active)
        value = step.read(cells, position)
        step.require(w.equal(e, value, w.constant(e, 0, 8)))
        increment = Scope(e, active=_live(step))
        next_position = increment.checked(w.add64(e, position, w.constant(e, 1, 64)))
        position = w.mux_word(e, increment.active, position, next_position)
        _merge(step, increment)
        _merge(scope, step)


def decode_hints(scope: Scope, encoded: Bytes) -> HintDecoding:
    """Complete literal bounded Algorithm 21; no private host control or advice."""
    e = scope.e
    cells = _hint_cells(e, encoded)
    hints = tuple(tuple(w.constant(e, 0, 64) for _ in range(N)) for _ in range(K))
    index = w.constant(e, 0, 64)
    result = []
    for row in range(K):
        end = _hint_boundary(scope, cells, index, row)
        first = index
        polynomial = hints[row]
        for _ in range(OMEGA):
            index, polynomial = _hint_iteration(scope, cells, index, first, end, polynomial)
        result.append(polynomial)
    _hint_padding(scope, cells, index)
    return HintDecoding(tuple(result), e.not_(scope.rejected))


def decode_signature(scope: Scope, signature: Bytes) -> SignatureDecoding:
    decoded = decode_responses(scope, signature)
    hints = decode_hints(scope, decoded.encoded_hints)
    return SignatureDecoding(decoded.challenge_hash, decoded.responses, hints.hints, hints.valid)


def response_norm(scope: Scope, responses: tuple[Polynomial, ...]) -> ResponseNorm:
    """Separate Algorithm 8 final bound; never an extra Algorithm 27 decode rule."""
    if type(responses) is not tuple or len(responses) != L or any(len(p) != N for p in responses):
        raise ValueError("expected all five 256-coefficient response polynomials")
    e = scope.e
    within = e.one
    for polynomial in responses:
        for coefficient in polynomial:
            within = e.and_(within, norm_ok(scope, coefficient))
    return ResponseNorm(within, e.not_(scope.rejected))
