"""Holder-local raw witnesses, VII-A.5/.6; never presentation wire formats.

Byte order is the displayed field order, protocol integers are big-endian, and
later BC-1 input bits run MSB-first within each byte. There are no LP fields here.
"""

from dataclasses import dataclass

from pqdid.binding import HOLDER_SECRET_BYTES
from pqdid.codec import (
    PATH_BYTES,
    EncodingError,
    decode_uint,
    encode_uint,
    require_bytes,
    require_uint,
    unpack_sibling_path,
)
from pqdid.credentials import SIGNATURE_BYTES
from pqdid.merkle import TREE_DEPTH
from pqdid.schema import ATTRIBUTE_VECTOR_BYTES, Schema, decode_attributes

IDENTIFIER_BYTES = 4
ENROL_WITNESS_BYTES = HOLDER_SECRET_BYTES
ENROL_WITNESS_BITS = 8 * ENROL_WITNESS_BYTES
AUTH_FIELD_WIDTHS = (
    HOLDER_SECRET_BYTES,
    ATTRIBUTE_VECTOR_BYTES,
    IDENTIFIER_BYTES,
    SIGNATURE_BYTES,
    PATH_BYTES,
)
AUTH_WITNESS_BYTES = sum(AUTH_FIELD_WIDTHS)
AUTH_WITNESS_BITS = 8 * AUTH_WITNESS_BYTES


@dataclass(frozen=True, repr=False)
class EnrolmentWitness:
    holder_secret: bytes


@dataclass(frozen=True, repr=False)
class AuthenticationWitness:
    holder_secret: bytes
    attributes: bytes
    revocation_identifier: int
    signature: bytes
    path: bytes


def encode_enrol_witness(witness: EnrolmentWitness) -> bytes:
    if type(witness) is not EnrolmentWitness:
        raise EncodingError("expected enrolment witness")
    if len(require_bytes(witness.holder_secret)) != ENROL_WITNESS_BYTES:
        raise EncodingError("enrolment witness must contain exactly 32 bytes")
    return witness.holder_secret


def decode_enrol_witness(encoded: bytes) -> EnrolmentWitness:
    result = EnrolmentWitness(encoded)
    encode_enrol_witness(result)
    return result


def validate_auth_witness(schema: Schema, witness: AuthenticationWitness) -> None:
    if type(witness) is not AuthenticationWitness:
        raise EncodingError("expected authentication witness")
    encode_enrol_witness(EnrolmentWitness(witness.holder_secret))
    decode_attributes(schema, witness.attributes)
    require_uint(witness.revocation_identifier, TREE_DEPTH)
    if len(require_bytes(witness.signature)) != SIGNATURE_BYTES:
        raise EncodingError("credential signature must contain exactly 3309 bytes")
    unpack_sibling_path(witness.path)


def encode_auth_witness(schema: Schema, witness: AuthenticationWitness) -> bytes:
    validate_auth_witness(schema, witness)
    return b"".join(
        (
            witness.holder_secret,
            witness.attributes,
            encode_uint(witness.revocation_identifier, IDENTIFIER_BYTES),
            witness.signature,
            witness.path,
        )
    )


def decode_auth_witness(schema: Schema, encoded: bytes) -> AuthenticationWitness:
    if len(require_bytes(encoded)) != AUTH_WITNESS_BYTES:
        raise EncodingError("authentication witness must contain exactly 5329 bytes")
    offset = 0
    fields = []
    for width in AUTH_FIELD_WIDTHS:
        fields.append(encoded[offset : offset + width])
        offset += width
    secret, attributes, identifier, signature, path = fields
    result = AuthenticationWitness(
        secret, attributes, decode_uint(identifier, IDENTIFIER_BYTES), signature, path
    )
    validate_auth_witness(schema, result)
    return result


def witness_bits(encoded: bytes) -> tuple[int, ...]:
    """Serialised witness bytes to MSB-first input bits; not circuit synthesis."""
    if len(require_bytes(encoded)) not in (ENROL_WITNESS_BYTES, AUTH_WITNESS_BYTES):
        raise EncodingError("unsupported witness byte length")
    return tuple((byte >> shift) & 1 for byte in encoded for shift in range(7, -1, -1))
