"""Fixed byte wiring/comparison and enrolment's public parsing boundary.

No variable private fields exist in enrolment. This is not an authentication parser.
Byte tuples are flattened MSB-first symbolic positions; all lengths are public.
"""

from pqdid.circuits.emitter import Bit, Emitter
from pqdid.codec import encode_length_prefixed, encode_uint
from pqdid.hash_domain import HashDomain, encode_metadata, require_domain
from pqdid.parameters import PublicParameters
from pqdid.statements import EnrolmentStatement, decode_enrol_statement, encode_enrol_statement

type Bytes = tuple[Bit, ...]
MAX_DEVELOPMENT_BYTES = 65536


def check_bytes(e: Emitter, bits: Bytes, *, length: int | None = None) -> None:
    e.poll()
    if type(bits) is not tuple or len(bits) % 8 or len(bits) > 8 * MAX_DEVELOPMENT_BYTES:
        raise ValueError("expected bounded whole-byte symbolic input")
    if length is not None and (type(length) is not int or len(bits) != 8 * length):
        raise ValueError("incorrect fixed byte width")
    for bit in bits:
        e.check_bit(bit)


def public_bytes(e: Emitter, data: bytes) -> Bytes:
    if type(data) is not bytes or len(data) > MAX_DEVELOPMENT_BYTES:
        raise ValueError("expected bounded public bytes")
    return tuple(e.constant((byte >> bit) & 1) for byte in data for bit in range(7, -1, -1))


def reverse_byte_bits(e: Emitter, bits: Bytes) -> Bytes:
    """MSB serialised <-> FIPS 202 LSB bit order; this permutation is its own inverse."""
    check_bytes(e, bits)
    return tuple(
        bit for start in range(0, len(bits), 8) for bit in reversed(bits[start : start + 8])
    )


def equal_bytes(e: Emitter, left: Bytes, right: Bytes) -> Bit:
    """SPEC-003 provisional 1-seeded fold: bytes increasing, bits low to high."""
    check_bytes(e, left)
    check_bytes(e, right, length=len(left) // 8)
    result = e.one
    for offset in range(0, len(left), 8):
        for bit in range(7, -1, -1):
            xnor = e.not_(e.xor(left[offset + bit], right[offset + bit]))
            result = e.and_(result, xnor)
    return result


def holder_message(e: Emitter, domain: HashDomain, secret: Bytes) -> Bytes:
    """Exact holder framing with only xH private; no placeholder native hash."""
    require_domain(domain)
    check_bytes(e, secret, length=32)
    prefix = (
        encode_length_prefixed(b"holder")
        + encode_uint(3, 4)
        + encode_length_prefixed(domain.suite)
        + encode_length_prefixed(encode_metadata(domain))
        + encode_uint(32, 4)
    )
    return public_bytes(e, prefix) + secret


def parse_enrolment_public(
    pp: PublicParameters, encoded: bytes
) -> tuple[EnrolmentStatement, bytes]:
    """Host validation of public framing, lengths, schema/ranges and instance agreement.

    Parsing/domain errors raise EncodingError before a circuit is created; callers
    compare this rejection plus circuit evaluation with the local reference.
    """
    statement = decode_enrol_statement(pp, encoded)
    canonical = encode_enrol_statement(pp, statement)
    # Existing decoders reject noncanonical inputs, without normalising them.
    if canonical != encoded:
        from pqdid.codec import EncodingError

        raise EncodingError("noncanonical public enrolment statement")
    return statement, canonical
