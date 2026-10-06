"""Typed public relation inputs and canonical E(X), VII-A.1/.5/.6.

Frozen records are data, not evidence of validity. Every codec/evaluator revalidates
them against externally expected parameters. No authenticity, time or session state
is inferred by these structural validators. Enrolment data are participant-public,
not public directory data. Encodings prepare, but do not implement, proof binding.
"""

from dataclasses import dataclass

from pqdid.binding import BindingRepresentation, decode_binding, encode_binding
from pqdid.codec import (
    MAX_FIELD_BYTES,
    EncodingError,
    decode_record,
    decode_uint,
    encode_record,
    encode_uint,
    require_bytes,
    require_uint,
)
from pqdid.credentials import SIGNATURE_BYTES
from pqdid.expiry import decode_timestamp, encode_timestamp
from pqdid.hash_domain import require_hash
from pqdid.merkle import TREE_DEPTH
from pqdid.parameters import (
    InstanceMetadata,
    PublicParameters,
    decode_instance_metadata,
    decode_parameters,
    encode_instance_metadata,
    encode_parameters,
    validate_metadata_structure,
    validate_parameters_structure,
)
from pqdid.policy import Policy, decode_policy, encode_policy
from pqdid.schema import (
    decode_attributes,
    decode_disclosed_attributes,
    decode_disclosure_mask,
    encode_disclosure_mask,
)


@dataclass(frozen=True)
class StateReference:
    namespace: bytes
    epoch: int
    root: bytes


@dataclass(frozen=True)
class RevocationState:
    namespace: bytes
    epoch: int
    root: bytes
    signature: bytes

    @property
    def reference(self) -> StateReference:
        return StateReference(self.namespace, self.epoch, self.root)


@dataclass(frozen=True)
class Context:
    suite: bytes
    audience: bytes
    session: bytes
    nonce: bytes
    policy: Policy
    issuer_reference: bytes
    state_reference: StateReference
    expires_at: int


@dataclass(frozen=True, repr=False)
class EnrolmentStatement:
    parameters: PublicParameters
    metadata: InstanceMetadata
    approved_attributes: bytes
    revocation_identifier: int
    binding: BindingRepresentation
    issuer_nonce: bytes
    state: RevocationState


@dataclass(frozen=True)
class AuthenticationStatement:
    parameters: PublicParameters
    metadata: InstanceMetadata
    context: Context
    state: RevocationState
    disclosed: tuple[int, ...]
    disclosed_attributes: bytes


def _record(value: object, expected_type: type) -> None:
    if type(value) is not expected_type:
        raise EncodingError("incorrect public record type")


def _length(value: bytes, length: int) -> None:
    if len(require_bytes(value)) != length:
        raise EncodingError("incorrect public byte length")


def validate_state_reference(pp: PublicParameters, reference: StateReference) -> None:
    validate_parameters_structure(pp)
    _record(reference, StateReference)
    _length(reference.namespace, 32)
    if reference.namespace != pp.namespace:
        raise EncodingError("state namespace disagrees with expected instance")
    require_uint(reference.epoch, 64)
    require_hash(reference.root)


def encode_state_reference(pp: PublicParameters, reference: StateReference) -> bytes:
    validate_state_reference(pp, reference)
    return encode_record(
        "rref", (reference.namespace, encode_uint(reference.epoch, 8), reference.root)
    )


def decode_state_reference(pp: PublicParameters, encoded: bytes) -> StateReference:
    namespace, epoch, root = decode_record(encoded, "rref")
    result = StateReference(namespace, decode_uint(epoch, 8), root)
    validate_state_reference(pp, result)
    return result


def validate_state_structure(pp: PublicParameters, state: RevocationState) -> None:
    _record(state, RevocationState)
    validate_state_reference(pp, state.reference)
    _length(state.signature, SIGNATURE_BYTES)


def encode_state(pp: PublicParameters, state: RevocationState) -> bytes:
    validate_state_structure(pp, state)
    return encode_record(
        "rstate", (state.namespace, encode_uint(state.epoch, 8), state.root, state.signature)
    )


def decode_state(pp: PublicParameters, encoded: bytes) -> RevocationState:
    namespace, epoch, root, signature = decode_record(encoded, "rstate")
    result = RevocationState(namespace, decode_uint(epoch, 8), root, signature)
    validate_state_structure(pp, result)
    return result


def build_state_message(pp: PublicParameters, state: RevocationState) -> bytes:
    """Exact enc_state(suite,E(mu),[e]8,Ae); excludes the state signature."""
    validate_state_structure(pp, state)
    return encode_record(
        "state",
        (
            pp.suite,
            encode_instance_metadata(pp, pp.metadata),
            encode_uint(state.epoch, 8),
            state.root,
        ),
    )


def validate_context_structure(pp: PublicParameters, context: Context) -> None:
    validate_parameters_structure(pp)
    _record(context, Context)
    require_bytes(context.suite)
    require_bytes(context.issuer_reference)
    if context.suite != pp.suite or context.issuer_reference != pp.issuer_reference:
        raise EncodingError("context disagrees with expected instance")
    for identifier in (context.audience, context.session):
        if not 1 <= len(require_bytes(identifier)) <= 256:
            raise EncodingError("audience/session must contain 1 to 256 bytes")
    _length(context.nonce, 32)
    encode_policy(pp.schema, context.policy)
    validate_state_reference(pp, context.state_reference)
    encode_timestamp(context.expires_at)


def encode_context(pp: PublicParameters, context: Context) -> bytes:
    validate_context_structure(pp, context)
    return encode_record(
        "context",
        (
            context.suite,
            context.audience,
            context.session,
            context.nonce,
            encode_policy(pp.schema, context.policy),
            context.issuer_reference,
            encode_state_reference(pp, context.state_reference),
            encode_timestamp(context.expires_at),
        ),
    )


def decode_context(pp: PublicParameters, encoded: bytes) -> Context:
    validate_parameters_structure(pp)
    suite, audience, session, nonce, policy, reference, state_ref, expiry = decode_record(
        encoded, "context"
    )
    result = Context(
        suite,
        audience,
        session,
        nonce,
        decode_policy(pp.schema, policy),
        reference,
        decode_state_reference(pp, state_ref),
        decode_timestamp(expiry),
    )
    validate_context_structure(pp, result)
    return result


def validate_enrol_statement(pp: PublicParameters, statement: EnrolmentStatement) -> None:
    _record(statement, EnrolmentStatement)
    validate_parameters_structure(statement.parameters, expected=pp)
    validate_metadata_structure(pp, statement.metadata)
    decode_attributes(pp.schema, statement.approved_attributes)
    require_uint(statement.revocation_identifier, TREE_DEPTH)
    encode_binding(pp.domain, statement.binding)
    # Recheck Y even if a caller bypassed the binding record's constructor.
    require_hash(statement.binding.holder_value)
    _length(statement.issuer_nonce, 32)
    validate_state_structure(pp, statement.state)


def validate_auth_statement(pp: PublicParameters, statement: AuthenticationStatement) -> None:
    _record(statement, AuthenticationStatement)
    validate_parameters_structure(statement.parameters, expected=pp)
    validate_metadata_structure(pp, statement.metadata)
    validate_context_structure(pp, statement.context)
    validate_state_structure(pp, statement.state)
    if type(statement.disclosed) is not tuple:
        raise EncodingError("disclosure indices require an immutable tuple")
    encode_disclosure_mask(statement.disclosed, len(pp.schema.fields))
    decode_disclosed_attributes(pp.schema, statement.disclosed, statement.disclosed_attributes)
    if statement.disclosed != statement.context.policy.disclosed:
        raise EncodingError("disclosures disagree with context policy")
    if statement.context.state_reference != statement.state.reference:
        raise EncodingError("context reference disagrees with supplied state")


def _statement_bytes(tag: str, fields: tuple[bytes, ...]) -> bytes:
    result = encode_record(tag, fields)
    if len(result) > MAX_FIELD_BYTES:
        raise EncodingError("statement exceeds L")
    return result


def encode_enrol_statement(pp: PublicParameters, statement: EnrolmentStatement) -> bytes:
    validate_enrol_statement(pp, statement)
    return _statement_bytes(
        "enrol-statement",
        (
            encode_parameters(statement.parameters),
            encode_instance_metadata(pp, statement.metadata),
            statement.approved_attributes,
            encode_uint(statement.revocation_identifier, 4),
            encode_binding(pp.domain, statement.binding),
            statement.issuer_nonce,
            encode_state(pp, statement.state),
        ),
    )


def decode_enrol_statement(pp: PublicParameters, encoded: bytes) -> EnrolmentStatement:
    if len(require_bytes(encoded)) > MAX_FIELD_BYTES:
        raise EncodingError("statement exceeds L")
    parameters, metadata, attributes, rid, binding, nonce, state = decode_record(
        encoded, "enrol-statement"
    )
    result = EnrolmentStatement(
        decode_parameters(parameters, expected=pp),
        decode_instance_metadata(pp, metadata),
        attributes,
        decode_uint(rid, 4),
        decode_binding(pp.domain, binding),
        nonce,
        decode_state(pp, state),
    )
    validate_enrol_statement(pp, result)
    return result


def encode_auth_statement(pp: PublicParameters, statement: AuthenticationStatement) -> bytes:
    validate_auth_statement(pp, statement)
    return _statement_bytes(
        "auth-statement",
        (
            encode_parameters(statement.parameters),
            encode_instance_metadata(pp, statement.metadata),
            encode_context(pp, statement.context),
            encode_state(pp, statement.state),
            encode_disclosure_mask(statement.disclosed, len(pp.schema.fields)),
            statement.disclosed_attributes,
        ),
    )


def decode_auth_statement(pp: PublicParameters, encoded: bytes) -> AuthenticationStatement:
    validate_parameters_structure(pp)
    if len(require_bytes(encoded)) > MAX_FIELD_BYTES:
        raise EncodingError("statement exceeds L")
    parameters, metadata, context, state, mask, disclosed = decode_record(encoded, "auth-statement")
    result = AuthenticationStatement(
        decode_parameters(parameters, expected=pp),
        decode_instance_metadata(pp, metadata),
        decode_context(pp, context),
        decode_state(pp, state),
        decode_disclosure_mask(mask, len(pp.schema.fields)),
        disclosed,
    )
    validate_auth_statement(pp, result)
    return result
