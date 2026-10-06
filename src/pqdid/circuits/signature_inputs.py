"""Same-witness credential message and FIPS verifier input preparation ONLY.

This is not ML-DSA verification, CGen(auth), or a proof. Component composition is
bounded and may fail to finish. Never accept a caller-supplied B, Mcred or FIPS mu.
"""

from dataclasses import dataclass
from typing import BinaryIO

from pqdid.circuits.auth_parsing import ParsedAuthentication, link_disclosure, parse_auth_witness
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Bit, Circuit, Emitter, Limits
from pqdid.circuits.keccak import sha3_384, shake256
from pqdid.circuits.parsing import Bytes, holder_message, public_bytes
from pqdid.circuits.signature import (
    Polynomial,
    SignatureDecoding,
    decode_signature,
    unpack_unsigned,
)
from pqdid.codec import encode_length_prefixed, encode_uint
from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT
from pqdid.parameters import (
    InstanceMetadata,
    PublicParameters,
    encode_instance_metadata,
    validate_parameters_structure,
)
from pqdid.statements import AuthenticationStatement, encode_auth_statement
from pqdid.witnesses import AUTH_WITNESS_BITS


@dataclass(frozen=True, repr=False)
class CertifiedMessage:
    holder_preimage: Bytes
    holder_value: Bytes
    encoded_binding: Bytes
    certified_message: Bytes
    formatted_message: Bytes
    valid: Bit


@dataclass(frozen=True, repr=False)
class PublicKeyDecoding:
    rho: Bytes
    t1: tuple[Polynomial, ...]
    valid: Bit


@dataclass(frozen=True, repr=False)
class MessageRepresentative:
    public_key_hash: Bytes
    representative_preimage: Bytes
    fips_message_representative: Bytes
    valid: Bit


@dataclass(frozen=True, repr=False)
class VerifierInputPreparation:
    parsed_witness: ParsedAuthentication
    message: CertifiedMessage
    public_key: PublicKeyDecoding
    signature: SignatureDecoding
    representative: MessageRepresentative
    preparation_valid: Bit


def _record(e: Emitter, tag: bytes, fields: tuple[Bytes, ...]) -> Bytes:
    """All lengths are public; concatenate existing symbolic bytes verbatim."""
    result = public_bytes(e, encode_length_prefixed(tag) + encode_uint(len(fields), 4))
    for field in fields:
        result += public_bytes(e, encode_uint(len(field) // 8, 4)) + field
    return result


def certified_message(
    scope: Scope,
    pp: PublicParameters,
    protocol_metadata: InstanceMetadata,
    parsed: ParsedAuthentication,
) -> CertifiedMessage:
    e = scope.e
    metadata_bytes = encode_instance_metadata(pp, protocol_metadata)
    preimage = holder_message(e, pp.domain, parsed.holder_secret)
    holder_value = sha3_384(e, preimage)
    binding = _record(e, b"binding", (holder_value, parsed.attributes))
    message = _record(
        e,
        b"cred",
        (
            public_bytes(e, pp.suite),
            public_bytes(e, metadata_bytes),
            binding,
            parsed.identifier_bytes,
        ),
    )
    # FIPS Algorithm 3 pure ML-DSA framing, once. Presentation ctx is absent.
    formatted = (
        public_bytes(e, bytes((0, len(CREDENTIAL_SIGNING_CONTEXT))) + CREDENTIAL_SIGNING_CONTEXT)
        + message
    )
    return CertifiedMessage(
        preimage, holder_value, binding, message, formatted, e.not_(scope.rejected)
    )


def decode_expected_public_key(e: Emitter, pp: PublicParameters) -> PublicKeyDecoding:
    """Algorithm 23. Every correctly sized key string has a valid 10-bit decode.

    Structural instance validation is public; key trust remains outside this layer.
    """
    validate_parameters_structure(pp)
    key = public_bytes(e, pp.issuer_public_key)
    t1 = tuple(
        unpack_unsigned(e, key[8 * (32 + i * 320) : 8 * (352 + i * 320)], 10) for i in range(6)
    )
    return PublicKeyDecoding(key[:256], t1, e.one)


def message_representative(
    scope: Scope, pp: PublicParameters, message: CertifiedMessage
) -> MessageRepresentative:
    """Algorithm 8 lines 6–7 via full SHAKE gadgets, including public tr folding.

    ExpandA belongs before these lines in the later complete verifier; it is not
    implemented by this preparation-only composition. No externally supplied mu.
    """
    validate_parameters_structure(pp)
    e = scope.e
    public_key_hash = shake256(e, public_bytes(e, pp.issuer_public_key), 64)
    preimage = public_key_hash + message.formatted_message
    representative = shake256(e, preimage, 64)
    return MessageRepresentative(public_key_hash, preimage, representative, e.not_(scope.rejected))


def prepare_verifier_inputs(
    scope: Scope, pp: PublicParameters, statement: AuthenticationStatement, witness: Bytes
) -> VerifierInputPreparation:
    """Named partial-layer result; no Boolean signature/authentication success API."""
    encode_auth_statement(pp, statement)
    parsed = parse_auth_witness(scope, pp.schema, witness)
    link_disclosure(scope, pp.schema, parsed, statement.disclosed, statement.disclosed_attributes)
    message = certified_message(scope, pp, statement.metadata, parsed)
    public_key = decode_expected_public_key(scope.e, pp)
    signature = decode_signature(scope, parsed.signature)
    representative = message_representative(scope, pp, message)
    return VerifierInputPreparation(
        parsed, message, public_key, signature, representative, scope.e.not_(scope.rejected)
    )


def compile_input_preparation(
    pp: PublicParameters,
    statement: AuthenticationStatement,
    *,
    limits: Limits,
    mode: str = "materialised",
    sink: BinaryIO | None = None,
) -> tuple[Circuit, VerifierInputPreparation]:
    """Development preparation predicate; resource failure returns no partial result."""
    encoded = encode_auth_statement(pp, statement)
    e = Emitter(AUTH_WITNESS_BITS, limits=limits, mode=mode, sink=sink, public_data=encoded)
    scope = Scope(e)
    prepared = prepare_verifier_inputs(scope, pp, statement, e.inputs)
    return e.finish(scope.output(())), prepared
