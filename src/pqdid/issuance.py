"""Bounded issuer/enrolment and holder acceptance reference (IV-B, V-C, VII-A.5).

No proof implementation, production signer or DID registry is supplied. The issuer
never accepts a holder secret. Its authenticated confidential session and trusted
ordered method/manager adapters are deployment assumptions, not new signed fields.
"""

import re
from dataclasses import dataclass
from enum import Enum
from threading import BoundedSemaphore, Lock
from typing import Protocol

from pqdid import bounded_mldsa
from pqdid.binding import BindingRepresentation, check_binding_consistency
from pqdid.codec import EncodingError, require_bytes, require_uint, unpack_sibling_path
from pqdid.credentials import (
    CREDENTIAL_SIGNING_CONTEXT,
    SIGNATURE_BYTES,
    Certificate,
    Credential,
    build_mcred,
    validate_credential_structure,
)
from pqdid.merkle import TREE_DEPTH, path_root
from pqdid.parameters import PublicParameters, validate_parameters_structure
from pqdid.public_checks import STATE_SIGNING_CONTEXT
from pqdid.revocation_state import (
    MAX_INFLIGHT,
    MAX_NONCES,
    AllocationResult,
    ManagerStatus,
    SigningResult,
    SigningStatus,
)
from pqdid.schema import ATTRIBUTE_VECTOR_BYTES, decode_attributes
from pqdid.statements import (
    EnrolmentStatement,
    RevocationState,
    StateReference,
    build_state_message,
    encode_enrol_statement,
    validate_enrol_statement,
)
from pqdid.verifier_state import NonceSource, ProofVerdict, ResolvedDID, SystemNonces
from pqdid.witness_updates import WitnessCheckpoint

CONTROL_CONTEXT = b"PQ-DID/control/v1"
MAX_PROOF_BYTES = 10 * 1024**2  # Same reference admission ceiling as the verifier.
MAX_EVIDENCE_BYTES = 64 * 1024  # Lower local channel admission, not a suite parameter.


class IssueStatus(Enum):
    PENDING = "pending-enrolment"
    CERTIFIED = "recorded-reference-certification"
    ACCEPTED = "holder-reference-accepted"
    ABORTED = "aborted-nonce-retired"
    INVALID_INPUT = "invalid-input"
    UNAUTHORISED = "invalid-evidence-or-controller-authorisation"
    MISMATCH = "different-approved-statement-or-holder-intent"
    STATE = "invalid-or-superseded-state-or-registration"
    PROOF = "invalid-enrolment-proof-verdict"
    UNSUPPORTED = "unsupported-signing-or-proof-backend"
    REPLAY = "session-or-challenge-no-longer-pending"
    BUSY = "local-concurrency-admission"
    RESOURCE_EXHAUSTED = "resource-exhausted"
    FAILURE = "dependency-or-processing-failure"


class IssueError(Exception):
    def __init__(self, status):
        super().__init__(status.value)
        self.status = status


@dataclass(frozen=True)
class IssueLimits:
    sessions: int = MAX_NONCES
    proof_bytes: int = MAX_PROOF_BYTES
    evidence_bytes: int = MAX_EVIDENCE_BYTES
    nonce_draws: int = 8

    def __post_init__(self):
        for value, ceiling in (
            (self.sessions, MAX_NONCES),
            (self.proof_bytes, MAX_PROOF_BYTES),
            (self.evidence_bytes, MAX_EVIDENCE_BYTES),
            (self.nonce_draws, 100),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise EncodingError("unsupported issuance admission limit")


DEFAULT_ISSUE_LIMITS = IssueLimits()


@dataclass(frozen=True, repr=False)
class IssueRequest:
    """Authenticated channel arguments, not a new wire/signature format.

    Authorisation validates evidence and proposes its own complete approved vector;
    holder_approval records the exact vector approved over that trusted channel.
    The local session identifier is not a holder identity or credential quota.
    """

    session: bytes
    did: bytes
    version: bytes
    attributes: bytes
    evidence: bytes
    holder_approval: bytes


@dataclass(frozen=True, repr=False)
class ControllerResolution:
    did: bytes
    resolution: ResolvedDID
    controller_public_key: bytes


class IssuanceResolver(Protocol):
    def current(self, parameters: PublicParameters, did: bytes) -> ControllerResolution | None:
        """Authenticated ordered CURRENT active method record/key, not a DID JSON key.

        Validate registry, chain, current-read nonce/signature, active endpoint and
        key binding. Reuse existing DID encodings; this typed answer has no new wire form.
        """
        ...


class IssuanceAuthorisation(Protocol):
    def approve(
        self, parameters: PublicParameters, request: IssueRequest, controller: ControllerResolution
    ) -> bytes | None:
        """Validate evidence/claims and session controller authority; return own mapp.

        The exact Xen controller signature is independently checked later. No holder
        secret, witness evaluator or proof substitute is part of this interface.
        """
        ...


class IssuanceRevocationAccess(Protocol):
    @property
    def parameters(self) -> PublicParameters: ...

    def reserve_identifier(self, reference: StateReference) -> AllocationResult:
        """Permanent next-ID reservation in the manager's SAME allocation state."""
        ...

    def registered_witness(self, identifier: int, reference: StateReference) -> AllocationResult:
        """Authenticated ordered current read; require registered and still zero.

        Remote adapters must preserve manager ordering/authentication. A valid signed
        root/path alone is insufficient to implement this trusted service contract.
        """
        ...


class EnrolmentVerifier(Protocol):
    def verify(self, statement: EnrolmentStatement, proof: bytes) -> ProofVerdict:
        """Verify the real enrolment argument and exact Xen. No private witness input.

        Exhaustion raises MemoryError; it is not an INVALID cryptographic verdict.
        """
        ...


class UnsupportedEnrolmentVerifier:
    def verify(self, statement: EnrolmentStatement, proof: bytes) -> ProofVerdict:
        return ProofVerdict.UNSUPPORTED


class IssuerSigner(Protocol):
    def sign(self, message: bytes, context: bytes) -> SigningResult:
        """Sign exact Mcred. Real bounded keygen/signing remain separate obligations."""
        ...


class UnsupportedIssuerSigner:
    def sign(self, message: bytes, context: bytes) -> SigningResult:
        return SigningResult(SigningStatus.UNSUPPORTED)


@dataclass(frozen=True, repr=False)
class EnrolmentChallenge:
    parameters: PublicParameters
    approved_attributes: bytes
    identifier: int
    nonce: bytes
    state: RevocationState

    def statement(self, binding: BindingRepresentation) -> EnrolmentStatement:
        value = EnrolmentStatement(
            self.parameters,
            self.parameters.metadata,
            self.approved_attributes,
            self.identifier,
            binding,
            self.nonce,
            self.state,
        )
        validate_enrol_statement(self.parameters, value)
        if binding.attributes != self.approved_attributes:
            raise EncodingError("binding differs from approved vector")
        return value


@dataclass(frozen=True, repr=False)
class EnrolmentSubmission:
    statement: EnrolmentStatement
    proof: bytes
    controller_signature: bytes


@dataclass(frozen=True, repr=False)
class IssuedCredential:
    credential: Credential
    checkpoint: WitnessCheckpoint


@dataclass(frozen=True, repr=False)
class IssueResult:
    status: IssueStatus
    challenge: EnrolmentChallenge | None = None
    issued: IssuedCredential | None = None


class SessionPhase(Enum):
    PREPARING = "preparing"
    PENDING = "pending"
    CLAIMED = "claimed-by-one-finish-call"
    ABORTED = "aborted-nonce-retired"
    CERTIFIED = "recorded-before-release"


@dataclass(repr=False)
class _Session:
    phase: SessionPhase = SessionPhase.PREPARING
    identifier: int | None = None
    nonce: bytes | None = None
    challenge: EnrolmentChallenge | None = None
    controller: ControllerResolution | None = None


@dataclass(frozen=True, repr=False)
class IssuerSnapshot:
    """Local authority inspection only; not a remote/public transcript."""

    sessions: tuple[tuple[bytes, SessionPhase, int | None, bytes | None], ...]
    used_nonces: frozenset[bytes]
    certifications: tuple[IssuedCredential, ...]


def _bytes(value, size):
    if len(require_bytes(value)) != size:
        raise EncodingError("incorrect immutable byte length")
    return value


def _session_name(value):
    if not 1 <= len(require_bytes(value)) <= 256:
        raise EncodingError("invalid authenticated session identifier")


def _verify(key, message, signature, context, failure):
    result = bounded_mldsa._verify_diagnostic(key, message, signature, context=context)
    if result.status is bounded_mldsa._Status.EXHAUSTED:
        raise IssueError(IssueStatus.RESOURCE_EXHAUSTED)
    if result.status is not bounded_mldsa._Status.VALID:
        raise IssueError(failure)


def _state_auth(pp, state):
    _verify(
        pp.revocation_public_key,
        build_state_message(pp, state),
        state.signature,
        STATE_SIGNING_CONTEXT,
        IssueStatus.STATE,
    )


def _controller(value, did, version):
    if (
        type(value) is not ControllerResolution
        or type(value.did) is not bytes
        or value.did != did
        or type(value.resolution) is not ResolvedDID
        or type(value.resolution.document) is not bytes
        or type(value.resolution.version) is not bytes
        or value.resolution.authenticated is not True
        or value.resolution.version != version
        or value.resolution.media_type != "application/did+json"
        or value.resolution.document != b'{"id":"' + did + b'"}'
    ):
        raise IssueError(IssueStatus.UNAUTHORISED)
    _bytes(value.controller_public_key, 1952)
    return value


def _allocation(pp, value, status, reference, identifier=None):
    if type(value) is not AllocationResult:
        raise IssueError(IssueStatus.STATE)
    if value.status is ManagerStatus.RESOURCE_EXHAUSTED:
        raise IssueError(IssueStatus.RESOURCE_EXHAUSTED)
    if value.status is ManagerStatus.BUSY:
        raise IssueError(IssueStatus.BUSY)
    if value.status in {ManagerStatus.FAILURE, ManagerStatus.UNAVAILABLE}:
        raise IssueError(IssueStatus.FAILURE)
    if value.status is not status:
        raise IssueError(IssueStatus.STATE)
    require_uint(value.identifier, TREE_DEPTH)
    if identifier is not None and value.identifier != identifier:
        raise IssueError(IssueStatus.STATE)
    _state_auth(pp, value.state)
    unpack_sibling_path(value.path)
    if (
        value.state.reference != reference
        or path_root(pp.domain, value.identifier, 0, value.path) != value.state.root
    ):
        raise IssueError(IssueStatus.STATE)
    return value


class ReferenceIssuer:
    """Finite in-process issuer, separate from holder private acceptance.

    One instance/store per pinned issuer namespace; replicas need a shared durable
    equivalent. Keep all nonce/session tombstones and recorded certifications.
    No eviction, recovery, implicit retry or request-per-holder restriction.
    """

    def __init__(
        self,
        parameters: PublicParameters,
        *,
        resolver: IssuanceResolver,
        authorisation: IssuanceAuthorisation,
        manager: IssuanceRevocationAccess,
        signer: IssuerSigner | None = None,
        proof_verifier: EnrolmentVerifier | None = None,
        nonces: NonceSource | None = None,
        limits: IssueLimits = DEFAULT_ISSUE_LIMITS,
    ):
        validate_parameters_structure(parameters)
        validate_parameters_structure(manager.parameters, expected=parameters)
        if type(limits) is not IssueLimits:
            raise EncodingError("expected issuance limits")
        limits.__post_init__()
        self.parameters, self.limits = parameters, limits
        self.resolver, self.authorisation, self.manager = resolver, authorisation, manager
        self.signer = signer if signer is not None else UnsupportedIssuerSigner()
        self.proof_verifier = (
            proof_verifier if proof_verifier is not None else UnsupportedEnrolmentVerifier()
        )
        self.nonces = nonces if nonces is not None else SystemNonces()
        self._lock, self._operations = Lock(), BoundedSemaphore(MAX_INFLIGHT)
        self._sessions: dict[bytes, _Session] = {}
        self._used_nonces: set[bytes] = set()
        self._certifications: tuple[IssuedCredential, ...] = ()

    def snapshot(self) -> IssuerSnapshot:
        with self._lock:
            return IssuerSnapshot(
                tuple(
                    (name, item.phase, item.identifier, item.nonce)
                    for name, item in self._sessions.items()
                ),
                frozenset(self._used_nonces),
                self._certifications,
            )

    def _request(self, request):
        if type(request) is not IssueRequest:
            raise EncodingError("expected issuance request")
        _session_name(request.session)
        if (
            re.fullmatch(rb"did:pqdid:[0-9a-f]{64}:[0-9a-f]{96}", require_bytes(request.did))
            is None
        ):
            raise EncodingError("invalid canonical DID")
        _bytes(request.version, 56)
        if int.from_bytes(request.version[:8], "big") >= 1 << 16:
            raise EncodingError("unsupported DID state index")
        decode_attributes(self.parameters.schema, request.attributes)
        _bytes(request.holder_approval, ATTRIBUTE_VECTOR_BYTES)
        if len(require_bytes(request.evidence)) > self.limits.evidence_bytes:
            raise IssueError(IssueStatus.RESOURCE_EXHAUSTED)

    def _fresh_nonce(self, entry):
        for _ in range(self.limits.nonce_draws):
            nonce = _bytes(self.nonces.nonce(), 32)
            with self._lock:
                if nonce not in self._used_nonces:
                    if len(self._used_nonces) >= self.limits.sessions:
                        raise IssueError(IssueStatus.RESOURCE_EXHAUSTED)
                    self._used_nonces.add(nonce)
                    entry.nonce = nonce
                    return nonce
        raise IssueError(IssueStatus.RESOURCE_EXHAUSTED)

    def begin(self, request: IssueRequest, state: RevocationState) -> IssueResult:
        if not self._operations.acquire(blocking=False):
            return IssueResult(IssueStatus.BUSY)
        entry = None
        try:
            self._request(request)
            with self._lock:
                if request.session in self._sessions:
                    raise IssueError(IssueStatus.REPLAY)
                if len(self._sessions) >= self.limits.sessions:
                    raise IssueError(IssueStatus.RESOURCE_EXHAUSTED)
                candidate = _Session()
                self._sessions[request.session] = candidate
                entry = candidate
            pp = self.parameters
            controller = _controller(
                self.resolver.current(pp, request.did), request.did, request.version
            )
            approved = self.authorisation.approve(pp, request, controller)
            if type(approved) is not bytes:
                raise IssueError(IssueStatus.UNAUTHORISED)
            values = decode_attributes(pp.schema, approved)
            if (
                approved != request.holder_approval
                or values[pp.schema.did_index - 1] != request.did
                or values[pp.schema.version_index - 1] != request.version
            ):
                raise IssueError(IssueStatus.MISMATCH)
            _state_auth(pp, state)
            reservation = self.manager.reserve_identifier(state.reference)
            # The manager's committed counter survives even a malformed/lost reply.
            reservation = _allocation(pp, reservation, ManagerStatus.ALLOCATED, state.reference)
            entry.identifier = reservation.identifier
            nonce = self._fresh_nonce(entry)
            challenge = EnrolmentChallenge(
                pp, approved, reservation.identifier, nonce, reservation.state
            )
            result = IssueResult(IssueStatus.PENDING, challenge=challenge)
            with self._lock:
                entry.challenge, entry.controller = challenge, controller
                entry.phase = SessionPhase.PENDING
            return result
        except IssueError as error:
            return IssueResult(error.status)
        except EncodingError:
            return IssueResult(IssueStatus.INVALID_INPUT)
        except MemoryError:
            return IssueResult(IssueStatus.RESOURCE_EXHAUSTED)
        except Exception:
            return IssueResult(IssueStatus.FAILURE)
        finally:
            with self._lock:
                if entry is not None and entry.phase is SessionPhase.PREPARING:
                    entry.phase = SessionPhase.ABORTED
            self._operations.release()

    def abort(self, session: bytes) -> IssueResult:
        try:
            _session_name(session)
            with self._lock:
                entry = self._sessions.get(session)
                if entry is None or entry.phase in {SessionPhase.ABORTED, SessionPhase.CERTIFIED}:
                    return IssueResult(IssueStatus.REPLAY)
                if entry.phase is not SessionPhase.PENDING:
                    return IssueResult(IssueStatus.BUSY)
                result = IssueResult(IssueStatus.ABORTED)
                entry.phase = SessionPhase.ABORTED
                return result
        except EncodingError:
            return IssueResult(IssueStatus.INVALID_INPUT)

    def _sign(self, message):
        result = self.signer.sign(message, CREDENTIAL_SIGNING_CONTEXT)
        if type(result) is not SigningResult:
            raise IssueError(IssueStatus.FAILURE)
        if result.status is SigningStatus.UNSUPPORTED:
            raise IssueError(IssueStatus.UNSUPPORTED)
        if result.status is SigningStatus.EXHAUSTED:
            raise IssueError(IssueStatus.RESOURCE_EXHAUSTED)
        if result.status is not SigningStatus.SIGNED:
            raise IssueError(IssueStatus.FAILURE)
        _bytes(result.signature, SIGNATURE_BYTES)
        _verify(
            self.parameters.issuer_public_key,
            message,
            result.signature,
            CREDENTIAL_SIGNING_CONTEXT,
            IssueStatus.UNAUTHORISED,
        )
        return result.signature

    def _commit(self, entry, issued):
        result = IssueResult(IssueStatus.CERTIFIED, issued=issued)
        with self._lock:
            if entry.phase is not SessionPhase.CLAIMED:
                raise IssueError(IssueStatus.REPLAY)
            candidate = (*self._certifications, issued)
            # Log contains (mu,mapp,rid,B) in the existing credential, and the exact
            # releasable response. No fallible dependency/allocation after this point.
            self._certifications = candidate
            entry.phase = SessionPhase.CERTIFIED
        return result

    def finish(self, session: bytes, submission: EnrolmentSubmission) -> IssueResult:
        if not self._operations.acquire(blocking=False):
            return IssueResult(IssueStatus.BUSY)
        entry = None
        try:
            _session_name(session)
            with self._lock:
                candidate = self._sessions.get(session)
                if candidate is None or candidate.phase is not SessionPhase.PENDING:
                    raise IssueError(IssueStatus.REPLAY)
                candidate.phase = SessionPhase.CLAIMED
                entry = candidate
            if type(submission) is not EnrolmentSubmission:
                raise EncodingError("expected public enrolment submission")
            proof = require_bytes(submission.proof)
            if not 1 <= len(proof) <= self.limits.proof_bytes:
                raise IssueError(IssueStatus.RESOURCE_EXHAUSTED if proof else IssueStatus.PROOF)
            _bytes(submission.controller_signature, SIGNATURE_BYTES)
            pp, challenge = self.parameters, entry.challenge
            statement = submission.statement
            validate_enrol_statement(pp, statement)
            expected = challenge.statement(statement.binding)
            if statement != expected:
                raise IssueError(IssueStatus.MISMATCH)
            _state_auth(pp, statement.state)
            _verify(
                entry.controller.controller_public_key,
                encode_enrol_statement(pp, statement),
                submission.controller_signature,
                CONTROL_CONTEXT,
                IssueStatus.UNAUTHORISED,
            )
            verdict = self.proof_verifier.verify(statement, proof)
            if verdict is ProofVerdict.UNSUPPORTED:
                raise IssueError(IssueStatus.UNSUPPORTED)
            if verdict is not ProofVerdict.VALID:
                raise IssueError(IssueStatus.PROOF)
            old = entry.controller
            current = _controller(
                self.resolver.current(pp, old.did), old.did, old.resolution.version
            )
            if current != old:
                raise IssueError(IssueStatus.UNAUTHORISED)
            witness = _allocation(
                pp,
                self.manager.registered_witness(challenge.identifier, challenge.state.reference),
                ManagerStatus.WITNESS,
                challenge.state.reference,
                challenge.identifier,
            )
            # Final ordered DID/state reads immediately precede certification; an
            # update after these read points is handled by later witness/freshness work.
            message = build_mcred(pp, pp.metadata, statement.binding, challenge.identifier)
            signature = self._sign(message)
            credential = Credential(
                Certificate(statement.binding, signature),
                challenge.approved_attributes,
                challenge.identifier,
                b"",
                pp.metadata,
            )
            validate_credential_structure(pp, credential)
            issued = IssuedCredential(
                credential, WitnessCheckpoint(challenge.identifier, witness.path, challenge.state)
            )
            return self._commit(entry, issued)
        except IssueError as error:
            return IssueResult(error.status)
        except EncodingError:
            return IssueResult(IssueStatus.INVALID_INPUT)
        except MemoryError:
            return IssueResult(IssueStatus.RESOURCE_EXHAUSTED)
        except Exception:
            return IssueResult(IssueStatus.FAILURE)
        finally:
            with self._lock:
                if entry is not None and entry.phase is SessionPhase.CLAIMED:
                    entry.phase = SessionPhase.ABORTED
            self._operations.release()


class HolderAcceptance:
    """One locally approved enrolment intent; instantiate again for another credential.

    The secret remains holder-local. Acceptance commits the existing credential and
    separate witness/state in one pointer assignment; no freshness/current-DID claim.
    """

    def __init__(
        self,
        parameters: PublicParameters,
        holder_secret: bytes,
        intended_attributes: bytes,
        statement: EnrolmentStatement,
    ):
        validate_enrol_statement(parameters, statement)
        decode_attributes(parameters.schema, intended_attributes)
        if statement.approved_attributes != intended_attributes or not check_binding_consistency(
            parameters.domain, statement.binding, holder_secret, intended_attributes
        ):
            raise EncodingError("enrolment statement differs from holder intent")
        self._parameters, self._secret = parameters, holder_secret
        self._statement, self._attributes = statement, intended_attributes
        self._accepted: IssuedCredential | None = None
        self._lock = Lock()

    def snapshot(self) -> IssuedCredential | None:
        with self._lock:
            return self._accepted

    def accept(self, issued: IssuedCredential) -> IssueResult:
        try:
            if (
                type(issued) is not IssuedCredential
                or type(issued.checkpoint) is not WitnessCheckpoint
            ):
                raise EncodingError("expected credential and separate witness/state")
            pp, expected = self._parameters, self._statement
            credential, checkpoint = issued.credential, issued.checkpoint
            validate_credential_structure(pp, credential)
            if (
                credential.attributes != self._attributes
                or credential.certificate.binding != expected.binding
                or credential.revocation_identifier != expected.revocation_identifier
                or checkpoint.identifier != credential.revocation_identifier
                or checkpoint.state != expected.state
            ):
                raise IssueError(IssueStatus.MISMATCH)
            if not check_binding_consistency(
                pp.domain, credential.certificate.binding, self._secret, self._attributes
            ):
                raise IssueError(IssueStatus.MISMATCH)
            _verify(
                pp.issuer_public_key,
                build_mcred(
                    pp,
                    credential.metadata,
                    credential.certificate.binding,
                    credential.revocation_identifier,
                ),
                credential.certificate.signature,
                CREDENTIAL_SIGNING_CONTEXT,
                IssueStatus.UNAUTHORISED,
            )
            _state_auth(pp, checkpoint.state)
            if (
                path_root(pp.domain, checkpoint.identifier, 0, checkpoint.path)
                != checkpoint.state.root
            ):
                raise IssueError(IssueStatus.STATE)
            result = IssueResult(IssueStatus.ACCEPTED, issued=issued)
            with self._lock:
                if self._accepted is not None:
                    raise IssueError(IssueStatus.REPLAY)
                self._accepted = issued
            return result
        except IssueError as error:
            return IssueResult(error.status)
        except EncodingError:
            return IssueResult(IssueStatus.INVALID_INPUT)
        except MemoryError:
            return IssueResult(IssueStatus.RESOURCE_EXHAUSTED)
        except Exception:
            return IssueResult(IssueStatus.FAILURE)
