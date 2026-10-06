"""Isolated public-only integration, not a deployed proof or custody service.

Dependencies are trusted owner configuration. No test-proof selector, hidden-holder
lookup, automatic recovery or acceptance-redelivery endpoint is provided.
"""

import socket
from contextlib import contextmanager
from threading import Lock

from pqdid.bounded_manager import BoundedDurableManager
from pqdid.parameters import validate_parameters_structure
from pqdid.persistence.codec import CAP, Unavailable, decode, require
from pqdid.persistence.lifecycle import DurableVerifier
from pqdid.persistence.sqlite_store import digest
from pqdid.recovery_records import Role
from pqdid.signing_adapters import RequestSigningAdapter, TrustedSigningKey
from pqdid.statements import decode_state
from pqdid.verifier_state import CurrentStateReply, ReferenceVerifier, Registration


class ManagerVerificationProvider:
    """Pinned instance and admitted manager: current read commits before retrieval.

    Consumer/nonce identify a local operation, never a new signing format. Existing
    public retrieval fences the manager and withholds superseded replies. Verifiers
    independently check nonce and both signatures. Optional resolution is only for
    explicitly disclosed DID/version; no identifier is sent with a current read.
    """

    def __init__(self, manager, *, consumer: bytes, did_resolver=None):
        require(type(manager) is BoundedDurableManager, "manager-owner")
        require(type(consumer) is bytes and len(consumer) == 32, "consumer-identity")
        self._manager, self._consumer, self._resolver = manager, consumer, did_resolver

    def instance(self, expected):
        validate_parameters_structure(expected, expected=self._manager.parameters)
        return self._manager.parameters

    def current(self, expected, nonce):
        self.instance(expected)
        require(type(nonce) is bytes and len(nonce) == 32, "current-nonce")
        operation = digest((b"verifier-current", self._consumer, nonce))
        self._manager.read_current(operation, nonce)
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with sender, receiver:
            sender.setblocking(False)
            receiver.setblocking(False)
            self._manager.retrieve_committed(operation, sender)
            payload, _, flags, _ = receiver.recvmsg(CAP)
            require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "truncated-current")
        fields = decode(payload)
        require(type(fields) is tuple and len(fields) == 3, "current-shape")
        returned, state, signature = fields
        require(returned == nonce and type(signature) is bytes, "current-binding")
        return CurrentStateReply(returned, decode_state(expected, state), signature)

    def resolve_did(self, did, version):
        return None if self._resolver is None else self._resolver.resolve_did(did, version)


class _RequestAccess:
    def __init__(self, owner):
        self.owner, self.expected = owner, None

    def allow(self, key, operation, typed_inputs):
        owner, store = self.owner, self.owner._store
        if (
            key.authority_role is not Role.VERIFIER
            or key.service_id != store.key.service_id
            or key.parameters != store.key.parameters
            or operation != "request"
        ):
            return False
        if self.expected is None:
            self.expected = owner.ticket  # Registration has already committed.
        store.admit(owner._permit, self.expected)
        return True


class _RegisterPort:
    def __init__(self, owner):
        self.owner, self.audience = owner, owner._store.key.audience

    def register(self, challenge, clock):
        require(clock is self.owner._store._deps.clock, "trusted-clock")
        operation = digest((b"request", self.owner._store.key.service_id, challenge.context.nonce))
        try:
            result = self.owner.register(operation, challenge)
        except Unavailable as error:
            if str(error) == "nonce-reserved":
                return Registration.DUPLICATE
            if str(error) in {"expired", "challenge-cap"}:
                return Registration.UNAVAILABLE
            raise
        return Registration.DUPLICATE if result.replay else Registration.ADDED


class BoundedDurableVerifier:
    """Request/presentation operations on one explicitly admitted verifier authority.

    Audience, instance, role/key and proof dependency come only from trusted owner
    configuration. A missing proof dependency fails closed. Replicas of one audience
    must share the same durable store; there is no request-selected configuration.
    """

    def __init__(self, store, permit, ticket, *, signing_key: TrustedSigningKey):
        require(type(signing_key) is TrustedSigningKey, "signing-key")
        require(signing_key.service_id == store.key.service_id, "wrong-signing-service")
        validate_parameters_structure(signing_key.parameters, expected=store.key.parameters)
        self._owner = DurableVerifier(store, permit, ticket)
        RequestSigningAdapter(
            signing_key, audience=store.key.audience, expected_public_key=store._deps.request_key
        )
        self._key, self._serial = signing_key, Lock()

    @property
    def ticket(self):
        return self._owner.ticket

    @contextmanager
    def _operation(self):
        require(self._serial.acquire(blocking=False), "verifier-busy")
        try:
            yield
        finally:
            self._serial.release()

    def snapshot(self):
        with self._operation():
            return self._owner.snapshot()

    def create_challenge(self, *, session, policy, expires_at, require_did_state=False):
        with self._operation():
            owner, store = self._owner, self._owner._store
            owner.snapshot()
            deps = store._deps
            signer = RequestSigningAdapter(
                self._key,
                audience=store.key.audience,
                expected_public_key=deps.request_key,
                authorisation=_RequestAccess(owner),
            )
            verifier = ReferenceVerifier(
                parameters=store.key.parameters,
                audience=store.key.audience,
                request_public_key=deps.request_key,
                clock=deps.clock,
                store=_RegisterPort(owner),
                provider=deps.provider,
                signer=signer._bridge(),
                nonces=deps.nonces,
                max_nonce_draws=deps.nonce_draws,
            )
            return verifier.create_challenge(
                session=session,
                policy=policy,
                expires_at=expires_at,
                require_did_state=require_did_state,
            )

    def verify(self, *, session, context, presentation):
        with self._operation():
            return self._owner.verify(session=session, context=context, presentation=presentation)
