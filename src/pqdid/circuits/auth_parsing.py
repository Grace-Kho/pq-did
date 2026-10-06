"""Protocol-level authentication witness parsing, not authentication verification.

VII-A.1/.6: exactly 5329 bytes/42632 symbolic input positions. Signature bytes are
returned unchanged for the future FIPS verifier. No holder hash, signature check,
Merkle traversal, public state/policy evaluation or proof is performed here.
"""

from dataclasses import dataclass
from typing import BinaryIO

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Circuit, Emitter, Limits
from pqdid.circuits.parsing import Bytes, check_bytes, equal_bytes, public_bytes
from pqdid.codec import EncodingError
from pqdid.parameters import PublicParameters
from pqdid.schema import (
    BOOLEAN,
    BYTES,
    Schema,
    decode_disclosed_attributes,
    encode_disclosure_mask,
)
from pqdid.statements import AuthenticationStatement, encode_auth_statement
from pqdid.witnesses import AUTH_WITNESS_BITS


@dataclass(frozen=True, repr=False)
class ParsedAuthentication:
    holder_secret: Bytes
    attributes: Bytes
    fields: tuple[Bytes, ...]
    identifier_bytes: Bytes
    identifier: w.Word
    signature: Bytes
    siblings: tuple[Bytes, ...]


def _unsigned64(e: Emitter, serialised: Bytes) -> w.Word:
    word = w.from_serialised(e, serialised)
    return (*word, *((e.zero,) * (64 - len(word))))


def parse_attributes(scope: Scope, schema: Schema, attributes: Bytes) -> tuple[Bytes, ...]:
    """Public field offsets; all private length/type/padding checks emit gates.

    Payload bytes are never interpreted as host values. In particular UINT64
    attributes stay eight-byte strings, including their full unsigned endpoint.
    Every payload position is visited, with private length masking padding checks.
    """
    if type(schema) is not Schema:
        raise EncodingError("expected validated public schema")
    e = scope.e
    check_bytes(e, attributes, length=1024)
    offset = 0
    fields = []
    for field in schema.fields:
        end = offset + 8 * (2 + field.capacity)
        encoded = attributes[offset:end]
        fields.append(encoded)
        length = _unsigned64(e, encoded[:16])
        if field.type_code == BYTES:
            scope.require(w.less_equal64(e, length, w.constant(e, field.capacity, 64)))
        else:
            expected = 1 if field.type_code == BOOLEAN else 8
            scope.require(w.equal(e, length, w.constant(e, expected, 64)))
            if field.type_code == BOOLEAN:
                first = encoded[16:24]
                is_zero = equal_bytes(e, first, public_bytes(e, b"\0"))
                is_one = equal_bytes(e, first, public_bytes(e, b"\1"))
                scope.require(e.or_(is_zero, is_one))
        for position in range(field.capacity):
            payload = encoded[16 + position * 8 : 24 + position * 8]
            in_payload = w.less64(e, w.constant(e, position, 64), length)
            is_zero = equal_bytes(e, payload, public_bytes(e, b"\0"))
            scope.require(e.or_(in_payload, is_zero))
        offset = end
    scope.require(equal_bytes(e, attributes[offset:], public_bytes(e, bytes(1024 - offset // 8))))
    return tuple(fields)


def parse_auth_witness(scope: Scope, schema: Schema, bits: Bytes) -> ParsedAuthentication:
    e = scope.e
    check_bytes(e, bits, length=5329)
    secret = bits[:256]
    attributes = bits[256:8448]
    identifier_bytes = bits[8448:8480]
    signature = bits[8480:34952]
    path = bits[34952:]
    fields = parse_attributes(scope, schema, attributes)
    identifier = _unsigned64(e, identifier_bytes)
    scope.require(w.less64(e, identifier, w.constant(e, 1 << 20, 64)))
    # All fixed-length holder-secret, signature and sibling strings are valid at
    # this protocol parsing layer. Signature decoding is a later private circuit.
    return ParsedAuthentication(
        secret,
        attributes,
        fields,
        identifier_bytes,
        identifier,
        signature,
        tuple(path[i * 384 : (i + 1) * 384] for i in range(20)),
    )


def link_disclosure(
    scope: Scope,
    schema: Schema,
    parsed: ParsedAuthentication,
    disclosed: tuple[int, ...],
    public_disclosed: bytes,
) -> None:
    """Compare complete padded fields from the same raw attributes used by Mcred."""
    encode_disclosure_mask(disclosed, len(schema.fields))
    decode_disclosed_attributes(schema, disclosed, public_disclosed)
    selected = tuple(bit for index in disclosed for bit in parsed.fields[index - 1])
    scope.require(equal_bytes(scope.e, selected, public_bytes(scope.e, public_disclosed)))


def compile_auth_parsing(
    pp: PublicParameters,
    statement: AuthenticationStatement,
    *,
    limits: Limits,
    mode: str = "materialised",
    sink: BinaryIO | None = None,
) -> Circuit:
    """Development parsing/disclosure predicate ONLY; not CGen(auth) or a proof.

    Public structural validation is permitted here. PubOK/Ppub, FIPS signature
    decoding/verification, holder hashing and non-revocation are separate work.
    Construction receives no private value or auxiliary private input.
    """
    encoded = encode_auth_statement(pp, statement)
    e = Emitter(AUTH_WITNESS_BITS, limits=limits, mode=mode, sink=sink, public_data=encoded)
    scope = Scope(e)
    parsed = parse_auth_witness(scope, pp.schema, e.inputs)
    link_disclosure(scope, pp.schema, parsed, statement.disclosed, statement.disclosed_attributes)
    return e.finish(scope.output(()))
