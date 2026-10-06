"""Reference lifecycle only (IV-A/B, VII-A.7); not a production PQ-DAA verifier.

The proof boundary receives only public X and opaque bytes. No proof backend is
provided here. Trusted providers and a linearizable store remain deployment
obligations; this in-process store is not a transaction with a remote service.
"""

import re
import secrets
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Protocol

from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.codec import EncodingError, encode_record, require_bytes
from pqdid.expiry import is_unexpired
from pqdid.parameters import (
    PublicParameters,
    encode_instance_metadata,
    validate_parameters_structure,
)
from pqdid.policy import Policy
from pqdid.public_checks import pub_ok, public_policy_ok, state_auth
from pqdid.schema import decode_disclosed_attributes
from pqdid.statements import (
    AuthenticationStatement,
    Context,
    RevocationState,
    encode_auth_statement,
    encode_context,
    encode_state,
)

CURRENT_CONTEXT = b"PQ-DID/current/v1"
REQUEST_CONTEXT = b"PQ-DID/request/v1"


class Clock(Protocol):
    def now(self) -> int:
        """Trusted unsigned POSIX seconds; bounded and safe inside the store lock."""
        ...


class NonceSource(Protocol):
    def nonce(self) -> bytes:
        """Supply fresh uniform 32-byte nonces (deterministic sources are test-only)."""
        ...


class SystemNonces:
    def nonce(self) -> bytes:
        return secrets.token_bytes(32)


@dataclass(frozen=True)
class CurrentStateReply:
    nonce: bytes
    state: RevocationState
    signature: bytes


@dataclass(frozen=True)
class ResolvedDID:
    """Trusted method adapter result, never a presentation-supplied attestation."""

    document: bytes
    version: bytes
    media_type: str
    authenticated: bool


class TrustedPublicProvider(Protocol):
    def instance(self, expected: PublicParameters) -> PublicParameters | None:
        """Resolve issuer trust/key version/schema/namespace under pinned configuration."""
        ...

    def current(self, expected: PublicParameters, nonce: bytes) -> CurrentStateReply | None:
        """Latest authorised snapshot in a consistent ordering, signed under current."""
        ...

    def resolve_did(self, did: bytes, version: bytes) -> ResolvedDID | None:
        """Validate the disclosed specified historical state under the trusted method.

        The adapter must verify registry chain/signatures/nonces/active endpoint;
        a later controller rotation or deactivation is not an issuance-binding test.
        """
        ...


class RequestSigner(Protocol):
    def sign(self, message: bytes, context: bytes) -> bytes:
        """Sign the exact E(ctx); bounded production signing is not implemented here."""
        ...


class ProofVerdict(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


class ProofVerifier(Protocol):
    def verify(self, statement: AuthenticationStatement, proof: bytes) -> ProofVerdict:
        """Check the entire auth relation and exact public X using an admitted backend."""
        ...


class UnsupportedProofVerifier:
    def verify(self, statement: AuthenticationStatement, proof: bytes) -> ProofVerdict:
        return ProofVerdict.UNSUPPORTED


class Decision(Enum):
    ACCEPTED = "reference-model-accepted"
    UNKNOWN = "unknown-challenge"
    MISMATCH = "context-or-session-mismatch"
    EXPIRED = "expired"
    TRUST = "untrusted-instance"
    PUBLIC = "invalid-public-input-or-policy"
    STATE = "invalid-or-superseded-state"
    DID = "disclosed-DID-check-failed"
    PROOF = "invalid-proof-verdict"
    UNSUPPORTED = "unsupported-proof-backend"
    CONSUMED = "challenge-already-consumed-or-replaced"
    FAILURE = "provider-or-adapter-failure"

    @property
    def accepted(self) -> bool:
        return self is Decision.ACCEPTED


@dataclass(frozen=True)
class Presentation:
    """Local carrier of the existing D,mD,pi; no new wire encoding."""

    disclosed: tuple[int, ...]
    disclosed_attributes: bytes
    proof: bytes


@dataclass(frozen=True)
class StoredChallenge:
    parameters: PublicParameters
    context: Context
    state: RevocationState
    require_did_state: bool


@dataclass(frozen=True)
class AuthenticationRequest:
    context: Context
    state: RevocationState
    signature: bytes  # Outside ctx and vp, as prescribed in VII-A.7.


class Registration(Enum):
    ADDED = "added"
    DUPLICATE = "duplicate"
    UNAVAILABLE = "expired-or-at-capacity"


class ChallengeStore(Protocol):
    audience: bytes

    def register(self, challenge: StoredChallenge, clock: Clock) -> Registration: ...

    def pending(self, nonce: bytes) -> StoredChallenge | None: ...

    def consume(self, expected: StoredChallenge, session: bytes, clock: Clock) -> Decision:
        """Atomic full-record/session/expiry recheck and consume; failures do not consume."""
        ...


class InMemoryChallengeStore:
    """Finite reference store. Retain nonce tombstones; no eviction/reuse or persistence."""

    def __init__(self, audience: bytes, *, capacity: int = 100):
        _identifier(audience)
        if type(capacity) is not int or capacity < 1:
            raise EncodingError("positive challenge-store capacity required")
        self.audience = audience
        self.capacity = capacity
        self._records: dict[bytes, StoredChallenge] = {}
        self._consumed: set[bytes] = set()
        self._lock = Lock()

    def register(self, challenge: StoredChallenge, clock: Clock) -> Registration:
        if type(challenge) is not StoredChallenge or type(challenge.require_did_state) is not bool:
            raise EncodingError("invalid stored challenge")
        encode_context(challenge.parameters, challenge.context)
        encode_state(challenge.parameters, challenge.state)
        if (
            challenge.context.audience != self.audience
            or challenge.state.reference != challenge.context.state_reference
        ):
            raise EncodingError("challenge belongs to another audience or state")
        with self._lock:
            if challenge.context.nonce in self._records:
                return Registration.DUPLICATE
            if len(self._records) >= self.capacity or not is_unexpired(
                challenge.context.expires_at, now=clock.now()
            ):
                return Registration.UNAVAILABLE
            self._records[challenge.context.nonce] = challenge
            return Registration.ADDED

    def pending(self, nonce: bytes) -> StoredChallenge | None:
        with self._lock:
            return None if nonce in self._consumed else self._records.get(nonce)

    def consume(self, expected: StoredChallenge, session: bytes, clock: Clock) -> Decision:
        with self._lock:
            nonce = expected.context.nonce
            if nonce in self._consumed or self._records.get(nonce) != expected:
                return Decision.CONSUMED
            if session != expected.context.session or expected.context.audience != self.audience:
                return Decision.MISMATCH
            if not is_unexpired(expected.context.expires_at, now=clock.now()):
                return Decision.EXPIRED
            # Linearisation point: accepted and consumed together before any reply.
            self._consumed.add(nonce)
            return Decision.ACCEPTED


def _identifier(value: bytes) -> None:
    if not 1 <= len(require_bytes(value)) <= 256:
        raise EncodingError("audience/session length must be 1..256")


def _nonce(value: bytes) -> bytes:
    if len(require_bytes(value)) != 32:
        raise EncodingError("nonce must be exactly 32 bytes")
    return value


def build_current_message(pp: PublicParameters, nonce: bytes, state: RevocationState) -> bytes:
    """Existing VII-A.7 enc_current(suite,E(mu),nS,E(rse)); no extra fields."""
    return encode_record(
        "current",
        (
            pp.suite,
            encode_instance_metadata(pp, pp.metadata),
            _nonce(nonce),
            encode_state(pp, state),
        ),
    )


class ReferenceVerifier:
    """Public-only lifecycle model. Application session/configuration are trusted inputs.

    A missing proof adapter fails closed. Supplying a test adapter only demonstrates
    reference state transitions, never remote knowledge, ZK or production acceptance.
    """

    def __init__(
        self,
        *,
        parameters: PublicParameters,
        audience: bytes,
        request_public_key: bytes,
        clock: Clock,
        store: ChallengeStore,
        provider: TrustedPublicProvider,
        signer: RequestSigner | None = None,
        proof_verifier: ProofVerifier | None = None,
        nonces: NonceSource | None = None,
        proof_byte_limit: int = 10 * 1024**2,
        max_nonce_draws: int = 8,
    ):
        validate_parameters_structure(parameters)
        _identifier(audience)
        if store.audience != audience or len(require_bytes(request_public_key)) != 1952:
            raise EncodingError("store audience or request key mismatch")
        if type(proof_byte_limit) is not int or not 1 <= proof_byte_limit <= 10 * 1024**2:
            raise EncodingError("proof admission limit must be within the package ceiling")
        if type(max_nonce_draws) is not int or not 1 <= max_nonce_draws <= 100:
            raise EncodingError("nonce draw allowance must be 1..100")
        self.parameters, self.audience, self.request_public_key = (
            parameters,
            audience,
            request_public_key,
        )
        self.clock, self.store, self.provider, self.signer = clock, store, provider, signer
        self.proof_verifier = (
            proof_verifier if proof_verifier is not None else UnsupportedProofVerifier()
        )
        self.nonces = nonces if nonces is not None else SystemNonces()
        self.proof_byte_limit, self.max_nonce_draws = proof_byte_limit, max_nonce_draws

    def _trusted(self) -> bool:
        resolved = self.provider.instance(self.parameters)
        try:
            validate_parameters_structure(resolved, expected=self.parameters)
        except EncodingError:
            return False
        return True

    def _current(self) -> RevocationState | None:
        nonce = _nonce(self.nonces.nonce())
        reply = self.provider.current(self.parameters, nonce)
        if type(reply) is not CurrentStateReply or _nonce(reply.nonce) != nonce:
            return None
        message = build_current_message(self.parameters, nonce, reply.state)
        if not bounded_verify_mldsa65(
            self.parameters.revocation_public_key, message, reply.signature, context=CURRENT_CONTEXT
        ) or not state_auth(self.parameters, reply.state):
            return None
        return reply.state

    def create_challenge(
        self, *, session: bytes, policy: Policy, expires_at: int, require_did_state: bool = False
    ) -> AuthenticationRequest | None:
        """Register then sign an application-selected context, with no invented lifetime.

        On signing failure the unused reservation remains pending and cannot be
        recycled. A request is released only after signature validation. Collision
        resampling is bounded by an explicit local admission allowance.
        """
        try:
            _identifier(session)
            if type(require_did_state) is not bool or self.signer is None:
                return None
            if not self._trusted() or not is_unexpired(expires_at, now=self.clock.now()):
                return None
            state = self._current()
            if state is None:
                return None
            if require_did_state and not {
                self.parameters.schema.did_index,
                self.parameters.schema.version_index,
            }.issubset(policy.disclosed):
                return None
            for _ in range(self.max_nonce_draws):
                context = Context(
                    self.parameters.suite,
                    self.audience,
                    session,
                    _nonce(self.nonces.nonce()),
                    policy,
                    self.parameters.issuer_reference,
                    state.reference,
                    expires_at,
                )
                encoded = encode_context(self.parameters, context)
                stored = StoredChallenge(self.parameters, context, state, require_did_state)
                registered = self.store.register(stored, self.clock)
                if registered is Registration.DUPLICATE:
                    continue
                if registered is not Registration.ADDED:
                    return None
                signature = self.signer.sign(encoded, REQUEST_CONTEXT)
                if not bounded_verify_mldsa65(
                    self.request_public_key, encoded, signature, context=REQUEST_CONTEXT
                ):
                    return None
                return AuthenticationRequest(context, state, signature)
            return None
        except MemoryError:
            raise
        except Exception:
            return None

    def _did_ok(self, statement: AuthenticationStatement) -> bool:
        schema = self.parameters.schema
        values = decode_disclosed_attributes(
            schema, statement.disclosed, statement.disclosed_attributes
        )
        did, version = values.get(schema.did_index), values.get(schema.version_index)
        if type(did) is not bytes or type(version) is not bytes or len(version) != 56:
            return False
        if re.fullmatch(rb"did:pqdid:[0-9a-f]{64}:[0-9a-f]{96}", did) is None:
            return False
        result = self.provider.resolve_did(did, version)
        return (
            type(result) is ResolvedDID
            and result.authenticated is True
            and type(result.document) is bytes
            and type(result.version) is bytes
            and result.version == version
            and result.media_type == "application/did+json"
            and result.document == b'{"id":"' + did + b'"}'
        )

    def verify(self, *, session: bytes, context: Context, presentation: Presentation) -> Decision:
        """Compare untrusted ctx to stored ctx; build X exclusively from trusted state + D,mD."""
        try:
            _identifier(session)
            encode_context(self.parameters, context)
            if context.audience != self.audience or context.session != session:
                return Decision.MISMATCH
            stored = self.store.pending(context.nonce)
            if stored is None:
                return Decision.UNKNOWN
            if stored.context != context or stored.parameters != self.parameters:
                return Decision.MISMATCH
            if not is_unexpired(stored.context.expires_at, now=self.clock.now()):
                return Decision.EXPIRED
            if not self._trusted():
                return Decision.TRUST
            if type(presentation) is not Presentation:
                return Decision.PUBLIC
            proof = require_bytes(presentation.proof)
            if not 0 < len(proof) <= self.proof_byte_limit:
                return Decision.PROOF
            statement = AuthenticationStatement(
                self.parameters,
                self.parameters.metadata,
                stored.context,
                stored.state,
                presentation.disclosed,
                presentation.disclosed_attributes,
            )
            encode_auth_statement(self.parameters, statement)
            if not pub_ok(self.parameters, statement) or not public_policy_ok(
                self.parameters, statement
            ):
                return Decision.PUBLIC
            verdict = self.proof_verifier.verify(statement, proof)
            if verdict is ProofVerdict.UNSUPPORTED:
                return Decision.UNSUPPORTED
            if verdict is not ProofVerdict.VALID:
                return Decision.PROOF
            if stored.require_did_state and not self._did_ok(statement):
                return Decision.DID
            current = self._current()
            if current is None or current.reference != stored.context.state_reference:
                return Decision.STATE
            return self.store.consume(stored, session, self.clock)
        except MemoryError:
            raise  # Resource failure is not a credential rejection; no consume has occurred.
        except EncodingError:
            return Decision.PUBLIC
        except Exception:
            return Decision.FAILURE
