"""Experimental byte/bit hint decoder; deliberately NOT canonical BC-1.

Only symbolic private bits enter construction. Narrowing, shared expressions and
fixed-position membership replace the original source-order scanned writes.
The ordinary emitter and its public-only folding rule are unchanged.
"""

from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter
from pqdid.circuits.parsing import Bytes, check_bytes
from pqdid.circuits.signature import HintDecoding


def _constant(e: Emitter, value: int):
    return tuple(e.one if (value >> i) & 1 else e.zero for i in range(8))


def _less(e: Emitter, left, right):
    """Unsigned eight-bit order: the most significant differing bit decides."""
    result = e.zero
    for a, b in zip(left, right, strict=True):
        result = e.mux(e.xor(a, b), result, b)
    return result


def _one_hot(e: Emitter, cell):
    """All 256 exact byte equalities through shared binary prefixes."""
    result = (e.one,)
    for bit in reversed(cell):
        complement = e.not_(bit)
        result = tuple(
            child
            for parent in result
            for child in (e.and_(parent, complement), e.and_(parent, bit))
        )
    return result


def decode_hints(scope: Scope, encoded: Bytes, *, phases=None) -> HintDecoding:
    """Complete six-row/55-slot decoder; rejected outputs are unusable zeroes.

    Endpoint bytes in [0,55] are monotone; adjacent positions inside each row
    strictly increase; every unused coefficient byte is zero. Byte positions
    already lie in [0,255], so no unchecked narrowing or index advice occurs.
    """
    e = scope.e
    check_bytes(e, encoded, length=61)
    cells = tuple(tuple(reversed(encoded[8 * i : 8 * (i + 1)])) for i in range(61))

    def mark(name):
        if phases is not None:
            phases.append({"phase": name, "gates": e.counts.gates, "and_gates": e.counts.and_})

    valid = e.one
    start = _constant(e, 0)
    for end in cells[55:]:
        valid = e.and_(valid, e.not_(_less(e, end, start)))
        valid = e.and_(valid, e.not_(_less(e, _constant(e, 55), end)))
        start = end
    mark("endpoint_bounds_and_order")

    # These comparisons are shared by membership, row adjacency and padding.
    before_end = tuple(
        tuple(_less(e, _constant(e, j), end) for j in range(55)) for end in cells[55:]
    )
    inside = tuple(
        tuple(
            e.and_(before_end[row][j], e.not_(before_end[row - 1][j]) if row else e.one)
            for j in range(55)
        )
        for row in range(6)
    )
    increasing = (e.one,) + tuple(_less(e, cells[j - 1], cells[j]) for j in range(1, 55))
    for row in range(6):
        for j in range(1, 55):
            pair = e.and_(inside[row][j - 1], inside[row][j])
            valid = e.and_(valid, e.or_(e.not_(pair), increasing[j]))
    mark("membership_and_active_order_checks")

    decoded = tuple(_one_hot(e, cell) for cell in cells[:55])
    for j in range(55):
        valid = e.and_(valid, e.or_(before_end[-1][j], decoded[j][0]))
    mark("shared_byte_decoding_and_unused_padding")

    polynomials = []
    for row in range(6):
        polynomial = []
        for position in range(256):
            present = e.zero
            for j in range(55):
                present = e.or_(present, e.and_(inside[row][j], decoded[j][position]))
            polynomial.append(present)
        polynomials.append(polynomial)
    mark("complete_six_row_bitmap")

    # Reuse existing active-path sticky rejection. Invalid partial values never
    # become usable output; inactive scopes return the original zero initialiser.
    scope.require(valid)
    usable = e.and_(scope.active, e.not_(scope.rejected))
    result = tuple(
        tuple((e.and_(usable, bit),) + (e.zero,) * 63 for bit in row) for row in polynomials
    )
    mark("sticky_rejection_output_mask_and_signed64_rewiring")
    return HintDecoding(result, e.not_(scope.rejected))
