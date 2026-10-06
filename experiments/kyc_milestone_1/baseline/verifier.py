"""Direct ML-DSA/NR verification before actual durable one-time consumption.

No ProofVerifier, synthetic acceptance token or production proof path is invoked.
"""

import secrets
from enum import Enum

from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.expiry import is_unexpired
from pqdid.merkle import verify_non_revocation_path
from pqdid.persistence.codec import Unavailable
from pqdid.persistence.lifecycle import DurableVerifier, _ChallengeStore
from pqdid.persistence.sqlite_store import digest
from pqdid.policy import evaluate_policy
from pqdid.public_checks import state_auth
from pqdid.schema import project_attributes
from pqdid.statements import Context
from pqdid.verifier_state import Decision, StoredChallenge, build_current_message

from .records import (
    EncodingError,
    certified_expiry,
    decode_request,
    encode_presentation,
    encode_request,
    frame,
    request_body,
    require,
)
from .signing import Signer, verify


class Verdict(Enum):
    ACCEPTED = "accepted"
    REPLAY = "replay"
    MISMATCH = "mismatch"
    EXPIRED = "expired"
    CREDENTIAL = "invalid-credential"
    HOLDER = "invalid-holder"
    POLICY = "policy-failure"
    STATE = "stale-or-unauthenticated-state"
    REVOKED = "non-revocation-failed"
    FAILURE = "failure"


def current_state(pp, provider):
    nonce = secrets.token_bytes(32)
    require(provider.instance(pp) == pp, "trusted-instance")
    reply = provider.current(pp, nonce)
    require(reply is not None and reply.nonce == nonce, "current-nonce")
    require(state_auth(pp, reply.state), "state-signature")
    require(
        bounded_verify_mldsa65(
            pp.revocation_public_key,
            build_current_message(pp, nonce, reply.state),
            reply.signature,
            context=b"PQ-DID/current/v1",
        ),
        "current-signature",
    )
    return reply.state


class BaselineVerifier:
    def __init__(self, store, permit, ticket, key):
        self.owner = DurableVerifier(store, permit, ticket)
        self.store, self.clock, self.provider = store, store._deps.clock, store._deps.provider
        self.pp, self.audience = store.key.parameters, store.key.audience
        self.challenges = _ChallengeStore(self.owner)
        self.signer = Signer(self.pp, "verifier", key, store._deps.request_key, self._admitted)

    @property
    def ticket(self):
        return self.owner.ticket

    def _admitted(self):
        self.owner.snapshot()
        return True

    def request(self, policy, session, expires_at):
        self.owner.snapshot()
        require(is_unexpired(expires_at, now=self.clock.now()), "expired")
        state = current_state(self.pp, self.provider)
        context = Context(
            self.pp.suite,
            self.audience,
            session,
            secrets.token_bytes(32),
            policy,
            self.pp.issuer_reference,
            state.reference,
            expires_at,
        )
        stored = StoredChallenge(self.pp, context, state, False)
        self.owner.register(digest((b"baseline-request", context.nonce)), stored)
        body = request_body(self.pp, context, state)
        signature = self.signer.sign_request(context, state)
        return decode_request(self.pp, frame("request", (body, signature)))

    def verify(self, request, presentation):
        try:
            encode_request(self.pp, request)
            encode_presentation(self.pp, presentation)
            context = request.context
            if context.audience != self.audience or presentation.request != request:
                return Verdict.MISMATCH
            stored = self.challenges.pending(context.nonce)
            if stored is None:
                return Verdict.REPLAY
            if stored.context != context or stored.state != request.state:
                return Verdict.MISMATCH
            if not is_unexpired(context.expires_at, now=self.clock.now()):
                return Verdict.EXPIRED
            if not verify("request", self.store._deps.request_key, request.body, request.signature):
                return Verdict.MISMATCH
            credential = presentation.credential
            if not verify(
                "credential", self.pp.issuer_public_key, credential.body, credential.signature
            ):
                return Verdict.CREDENTIAL
            if not verify(
                "presentation",
                credential.holder_public_key,
                presentation.body,
                presentation.signature,
            ):
                return Verdict.HOLDER
            certified_expiry(self.pp, credential.attributes, context)
            selected = project_attributes(
                self.pp.schema, credential.attributes, context.policy.disclosed
            )
            if not evaluate_policy(self.pp.schema, context.policy, selected):
                return Verdict.POLICY
            if not state_auth(self.pp, request.state):
                return Verdict.STATE
            if not verify_non_revocation_path(
                self.pp.domain, credential.identifier, presentation.path, request.state.root
            ):
                return Verdict.REVOKED
            if current_state(self.pp, self.provider).reference != context.state_reference:
                return Verdict.STATE
            consumed = self.challenges.consume(stored, context.session, self.clock)
            if consumed is Decision.ACCEPTED:
                return Verdict.ACCEPTED
            if consumed is Decision.EXPIRED:
                return Verdict.EXPIRED
            return Verdict.REPLAY
        except MemoryError:
            raise
        except EncodingError, Unavailable, OSError:
            return Verdict.FAILURE

    def snapshot(self):
        _, cp, _ = self.owner.snapshot()
        return {
            "audience": self.audience.decode(),
            "challenges": len(cp.state.challenges),
            "consumed": sum(row.consumed for row in cp.state.challenges),
            "head": self.ticket.digest.hex(),
            "generation": self.ticket.generation,
        }
