"""Isolated bounded signing adapters, never production key custody or live services.

Public operations take typed protocol inputs. Trusted construction pins role,
instance, key reference/public identity and authority dependency. No request may
select another context/key. The private compatibility bridge admits only the
fixed operation grammar, reconstructs typed inputs and re-encodes them before
using the same typed operations. It is not a remotely exposed signing endpoint.
Existing lifecycle engines still own authorisation, ordering and publication.
"""

from dataclasses import dataclass, field, replace
from typing import Protocol

from pqdid import bounded_mldsa_sign as core
from pqdid.binding import BindingRepresentation, decode_binding
from pqdid.codec import EncodingError, decode_record, decode_uint, encode_record
from pqdid.credentials import build_mcred, encode_credential
from pqdid.did_state import (
    MAX_READ_BYTES,
    ZERO_DIGEST,
    DIDBody,
    DIDConfiguration,
    DIDError,
    DIDRecord,
    DIDStatus,
    decode_did_record,
    encode_body,
    encode_did_record,
    make_did,
    validate_did,
)
from pqdid.did_state import (
    _key as _validate_did_public_key,
)
from pqdid.parameters import (
    PublicParameters,
    decode_instance_metadata,
    validate_parameters_structure,
)
from pqdid.persistence.codec import Unavailable, require
from pqdid.persistence.lifecycle import DurableIssuer
from pqdid.recovery import _issuer
from pqdid.recovery_records import IssuedRecord, Role, WitnessRecord
from pqdid.revocation_state import (
    MAX_HISTORY,
    RevocationRequest,
    SigningResult,
    SigningStatus,
    build_revocation_request_message,
)
from pqdid.statements import (
    Context,
    EnrolmentStatement,
    RevocationState,
    build_state_message,
    decode_context,
    decode_enrol_statement,
    decode_state,
    decode_state_reference,
    encode_context,
    encode_enrol_statement,
    encode_state,
)
from pqdid.verifier_state import build_current_message
from pqdid.witness_updates import PublicUpdate, build_update_message

_ZERO_SIGNATURE = bytes(3309)  # Internal unsigned constructor slot, never a released signature.
_OPERATIONS = {
    Role.ISSUER: frozenset({"credential", "revreq"}),
    Role.MANAGER: frozenset({"state", "update", "current"}),
    Role.CONTROLLER: frozenset({"did-record", "control"}),
    Role.REGISTRY: frozenset({"did-read"}),
    Role.VERIFIER: frozenset({"request"}),
}


@dataclass(frozen=True, repr=False)
class TrustedSigningKey:
    """Owner-supplied handle/secret, never decoded from requests or recovery records."""

    parameters: PublicParameters
    service_id: bytes
    authority_role: Role
    reference: bytes
    public_key: bytes
    secret_key: bytes = field(repr=False)


class SigningAuthorisation(Protocol):
    def allow(self, key: TrustedSigningKey, operation: str, typed_inputs: tuple) -> bool:
        """Trusted current admission/operation policy; called before AND after signing.

        Must bind the configured handle and instance to the live authorised owner.
        This is a dependency contract, not caller-supplied proof of authorisation.
        Lifecycle evidence/controller/proof and commit checks remain mandatory.
        """
        ...


class _Deny:
    def allow(self, key, operation, typed_inputs):
        return False


class _Adapter:
    authority_role = None

    def __init__(self, key, expected_public_key, authorisation=None):
        if type(key) is not TrustedSigningKey or key.authority_role is not self.authority_role:
            raise EncodingError("wrong configured signing role")
        validate_parameters_structure(key.parameters)
        if (
            type(key.reference) is not bytes
            or not 1 <= len(key.reference) <= 64
            or type(key.service_id) is not bytes
            or len(key.service_id) != 32
            or key.public_key != expected_public_key
        ):
            raise EncodingError("wrong configured signing identity")
        core.reference_public_key_mldsa65(key.secret_key, expected_public_key=expected_public_key)
        self._key = key
        self._authorisation = _Deny() if authorisation is None else authorisation

    @property
    def parameters(self):
        return self._key.parameters

    def _signed(self, pp, operation, inputs, build):
        try:
            validate_parameters_structure(pp, expected=self.parameters)
            if operation not in _OPERATIONS[self.authority_role]:
                return SigningResult(SigningStatus.FAILED)
            if self._authorisation.allow(self._key, operation, inputs) is not True:
                return SigningResult(SigningStatus.FAILED)
            message = build()
            signature = core.bounded_sign_mldsa65(self._key.secret_key, message, role=operation)
            if self._authorisation.allow(self._key, operation, inputs) is not True:
                return SigningResult(SigningStatus.FAILED)
            return SigningResult(SigningStatus.SIGNED, signature)
        except core.BoundedMLDSAError as error:
            status = (
                SigningStatus.EXHAUSTED
                if error.reason
                in {
                    core.Failure.SAMPLER_EXHAUSTED,
                    core.Failure.ATTEMPTS_EXHAUSTED,
                }
                else SigningStatus.FAILED
            )
            return SigningResult(status)
        except DIDError as error:
            return SigningResult(
                SigningStatus.EXHAUSTED
                if error.status is DIDStatus.EXHAUSTED
                else SigningStatus.FAILED
            )
        except EncodingError, Unavailable, ValueError, TypeError:
            return SigningResult(SigningStatus.FAILED)
        # Memory/resource/unexpected runtime errors propagate, never release/fallback.

    def _bridge(self):
        return _Bridge(self)


class IssuerSigningAdapter(_Adapter):
    authority_role = Role.ISSUER

    def __init__(self, key: TrustedSigningKey, *, authorisation=None):
        super().__init__(key, key.parameters.issuer_public_key, authorisation)

    def credential(self, pp: PublicParameters, binding: BindingRepresentation, identifier: int):
        return self._signed(
            pp,
            "credential",
            (binding, identifier),
            lambda: build_mcred(pp, pp.metadata, binding, identifier),
        )

    def revocation_request(self, pp: PublicParameters, request: RevocationRequest):
        return self._signed(
            pp, "revreq", (request,), lambda: build_revocation_request_message(pp, request)
        )


class ManagerSigningAdapter(_Adapter):
    authority_role = Role.MANAGER

    def __init__(self, key: TrustedSigningKey, *, authorisation=None):
        super().__init__(key, key.parameters.revocation_public_key, authorisation)

    def state(self, pp: PublicParameters, state: RevocationState):
        return self._signed(pp, "state", (state,), lambda: build_state_message(pp, state))

    def update(self, pp: PublicParameters, update: PublicUpdate):
        return self._signed(pp, "update", (update,), lambda: build_update_message(pp, update))

    def current(self, pp: PublicParameters, nonce: bytes, state: RevocationState):
        return self._signed(
            pp, "current", (nonce, state), lambda: build_current_message(pp, nonce, state)
        )


def _record_key(config, body, previous):
    # The original DID transition checks, before a signature exists. No new wire fields.
    encode_body(body)
    validate_did(config, body.did)
    _validate_did_public_key(body.controller_key)
    if body.registry_id != config.registry_id:
        raise EncodingError("registry mismatch")
    if previous is None:
        if (
            body.index != 0
            or body.predecessor != ZERO_DIGEST
            or body.active != 1
            or make_did(config, body.controller_key, body.salt) != body.did
        ):
            raise EncodingError("invalid genesis")
        return body.controller_key
    if type(previous) is not DIDRecord:
        raise EncodingError("invalid trusted predecessor")
    old = previous.body
    if (
        old.active != 1
        or body.index != old.index + 1
        or body.did != old.did
        or body.salt != old.salt
        or body.predecessor != previous.version[8:]
        or (body.active == 0 and body.controller_key != old.controller_key)
    ):
        raise EncodingError("invalid or deactivated successor")
    return old.controller_key


class ControllerSigningAdapter(_Adapter):
    authority_role = Role.CONTROLLER

    def __init__(
        self,
        key,
        *,
        config: DIDConfiguration,
        expected_public_key: bytes,
        current_record,
        authorisation=None,
    ):
        validate_parameters_structure(config.parameters, expected=key.parameters)
        self._config, self._current = config, current_record
        super().__init__(key, expected_public_key, authorisation)

    def record(self, body: DIDBody):
        def build():
            if _record_key(self._config, body, self._current(body.did)) != self._key.public_key:
                raise EncodingError("wrong current controller")
            return encode_body(body)

        return self._signed(self.parameters, "did-record", (body,), build)

    def control(self, pp: PublicParameters, statement: EnrolmentStatement):
        def build():
            from pqdid.schema import decode_attributes

            encoded = encode_enrol_statement(pp, statement)
            values = decode_attributes(pp.schema, statement.approved_attributes)
            did, version = values[pp.schema.did_index - 1], values[pp.schema.version_index - 1]
            record = self._current(did)
            if (
                record is None
                or record.body.active != 1
                or record.version != version
                or record.body.controller_key != self._key.public_key
            ):
                raise EncodingError("stale or deactivated controller")
            return encoded

        return self._signed(pp, "control", (statement,), build)


def _read_message(config, did, selector, nonce, chain):
    from pqdid.did_state import _selector

    validate_did(config, did)
    _selector(selector)
    if (
        type(nonce) is not bytes
        or len(nonce) != 32
        or type(chain) is not tuple
        or len(chain) > MAX_HISTORY
    ):
        raise EncodingError("invalid bounded read")
    if any(type(record) is not DIDRecord or record.body.did != did for record in chain):
        raise EncodingError("read chain identity mismatch")
    # Exact existing ReferenceDIDRegistry.read constructor; signatures are already
    # checked on append. An ordered trusted snapshot, not requester-supplied history.
    return encode_record(
        "did-read",
        (
            config.registry_id,
            did,
            selector,
            nonce,
            bytes((0 if chain else 1,)),
            encode_record("did-chain", tuple(encode_did_record(r) for r in chain)),
        ),
    )


class RegistrySigningAdapter(_Adapter):
    authority_role = Role.REGISTRY

    def __init__(self, key, *, config: DIDConfiguration, authorisation=None):
        validate_parameters_structure(config.parameters, expected=key.parameters)
        self._config = config
        super().__init__(key, config.registry_public_key, authorisation)

    def read(self, did: bytes, selector: bytes, nonce: bytes, chain: tuple[DIDRecord, ...]):
        return self._signed(
            self.parameters,
            "did-read",
            (did, selector, nonce, chain),
            lambda: _read_message(self._config, did, selector, nonce, chain),
        )


class RequestSigningAdapter(_Adapter):
    authority_role = Role.VERIFIER

    def __init__(self, key, *, audience: bytes, expected_public_key: bytes, authorisation=None):
        if type(audience) is not bytes or not 1 <= len(audience) <= 256:
            raise EncodingError("invalid trusted audience")
        self._audience = audience
        super().__init__(key, expected_public_key, authorisation)

    def request(self, pp: PublicParameters, context: Context):
        def build():
            message = encode_context(pp, context)
            if context.audience != self._audience:
                raise EncodingError("wrong audience")
            return message

        return self._signed(pp, "request", (context,), build)


class _Bridge:
    """Private compatibility with unchanged lifecycle sign protocols; closed grammar.

    Decoding never selects a key/instance. Re-encoding MUST equal the entire input.
    Foreign contexts, malformed fields, trailers and alternate formats fail closed.
    Only configured operations are admitted. No native/raw-message fallback exists.
    """

    def __init__(self, adapter):
        self._adapter = adapter

    def sign(self, message, context):
        adapter = self._adapter
        try:
            if (
                type(message) is not bytes
                or len(message) > MAX_READ_BYTES
                or type(context) is not bytes
            ):
                raise EncodingError("invalid bridge input")
            roles = _OPERATIONS[adapter.authority_role]
            operation = next(
                (r for r in roles if context == ("PQ-DID/" + r + "/v1").encode()), None
            )
            if operation is None:
                raise EncodingError("wrong context")
            inputs, expected, method = self._decode(operation, message)
            if expected != message:
                raise EncodingError("noncanonical or foreign message")
            result = method(*inputs)
        except EncodingError, Unavailable, ValueError, TypeError, StopIteration:
            result = SigningResult(SigningStatus.FAILED)
        if adapter.authority_role is Role.VERIFIER:
            if result.status is SigningStatus.EXHAUSTED:
                raise MemoryError("bounded request signing exhausted")
            if result.status is not SigningStatus.SIGNED:
                raise EncodingError("request signing failed")
            return result.signature
        return result

    def _decode(self, operation, message):
        a, pp = self._adapter, self._adapter.parameters
        if operation in {"credential", "state", "update", "current", "revreq"}:
            tag = "cred" if operation == "credential" else operation
            suite, metadata, *fields = decode_record(message, tag)
            if suite != pp.suite:
                raise EncodingError("suite mismatch")
            decode_instance_metadata(pp, metadata)
            if operation == "credential":
                binding, rid = fields
                inputs = (pp, decode_binding(pp.domain, binding), decode_uint(rid, 4))
                return inputs, build_mcred(pp, pp.metadata, inputs[1], inputs[2]), a.credential
            if operation == "state":
                epoch, root = fields
                state = RevocationState(pp.namespace, decode_uint(epoch, 8), root, _ZERO_SIGNATURE)
                return (pp, state), build_state_message(pp, state), a.state
            if operation == "current":
                nonce, state = fields
                state = decode_state(pp, state)
                return (pp, nonce, state), build_current_message(pp, nonce, state), a.current
            if operation == "revreq":
                rid, reference, nonce = fields
                request = RevocationRequest(
                    decode_uint(rid, 4),
                    decode_state_reference(pp, reference),
                    nonce,
                    _ZERO_SIGNATURE,
                )
                return (
                    (pp, request),
                    build_revocation_request_message(pp, request),
                    a.revocation_request,
                )
            old, new, rid, path = fields

            def state(reference):
                value = decode_state_reference(pp, reference)
                return RevocationState(value.namespace, value.epoch, value.root, _ZERO_SIGNATURE)

            update = PublicUpdate(
                state(old), state(new), decode_uint(rid, 4), path, _ZERO_SIGNATURE
            )
            return (pp, update), build_update_message(pp, update), a.update
        if operation == "control":
            statement = decode_enrol_statement(pp, message)
            return (pp, statement), encode_enrol_statement(pp, statement), a.control
        if operation == "request":
            context = decode_context(pp, message)
            return (pp, context), encode_context(pp, context), a.request
        if operation == "did-record":
            gamma, did, index, predecessor, key, active, salt = decode_record(message, "did-body")
            body = DIDBody(
                gamma, did, decode_uint(index, 8), predecessor, key, decode_uint(active, 1), salt
            )
            return (body,), encode_body(body), a.record
        gamma, did, selector, nonce, status, encoded = decode_record(message, "did-read")
        if gamma != a._config.registry_id:
            raise EncodingError("registry mismatch")
        # Check count before variable decoding allocates a tuple.
        if len(encoded) < 17 or int.from_bytes(encoded[13:17], "big") > MAX_HISTORY:
            raise EncodingError("chain cap")
        chain = tuple(
            decode_did_record(x)
            for x in decode_record(
                encoded, "did-chain", expected_count=int.from_bytes(encoded[13:17], "big")
            )
        )
        if status != bytes((0 if chain else 1,)):
            raise EncodingError("invalid read status")
        inputs = (did, selector, nonce, chain)
        return inputs, _read_message(a._config, *inputs), a.read


class _DurableAccess:
    """Existing role-scoped policy, writer generation and exact independently held head."""

    def __init__(self, owner):
        self._owner = owner

    def allow(self, key, operation, typed_inputs):
        owner, store = self._owner, self._owner._store
        if (
            key.authority_role is not store.key.role
            or key.service_id != store.key.service_id
            or key.parameters != store.key.parameters
            or operation != "credential"
        ):
            return False
        store._authorise(owner._permit.principal, "sign-issue")
        store.admit(owner._permit, owner.ticket)
        return True


class BoundedDurableIssuer:
    """Opt-in local reference adapter; no secret in records, response or IPC API.

    Validate the existing enrolment contract on a private in-memory candidate,
    then persist its exact response through the existing certification journal.
    A failed/uncertain signing claim stays SIGNING until explicit reconciliation;
    no retry or credential publication occurs here. Production deployment is open.
    """

    def __init__(self, store, permit, ticket, *, signing_key: TrustedSigningKey):
        self._owner = DurableIssuer(store, permit, ticket)
        require(signing_key.service_id == store.key.service_id, "wrong-signing-service")
        validate_parameters_structure(signing_key.parameters, expected=store.key.parameters)
        self._signer = IssuerSigningAdapter(signing_key, authorisation=_DurableAccess(self._owner))

    @property
    def ticket(self):
        return self._owner.ticket

    def __getattr__(self, name):
        if name not in {
            "intent",
            "attach",
            "pending",
            "reconcile",
            "snapshot",
            "retrieve_committed",
        }:
            raise AttributeError(name)
        return getattr(self._owner, name)

    def certify(self, claim_operation, certificate_operation, issue_operation, submission):
        from pqdid.issuance import IssueStatus

        # Claim is durably single-use before any actual signing. Replayed claims fail.
        owner = self._owner
        ticket = owner.claim_signing(claim_operation, issue_operation)
        _, checkpoint, entries = self.snapshot()
        row = entries[issue_operation]
        deps = replace(owner._store._deps, signer=self._signer._bridge())
        candidate = _issuer(owner._store.key.parameters, checkpoint.state, deps)
        result = candidate.finish(row[1][0], submission)
        require(
            result.status is IssueStatus.CERTIFIED and result.issued is not None,
            "certification-failed",
        )
        issued, pp = result.issued, owner._store.key.parameters
        value = IssuedRecord(
            encode_credential(pp, issued.credential),
            WitnessRecord(
                issued.checkpoint.identifier,
                issued.checkpoint.path,
                encode_state(pp, issued.checkpoint.state),
            ),
        )
        return owner.log_certificate(
            certificate_operation, issue_operation, value, row[1][1], ticket
        )
