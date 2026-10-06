"""Synthetic lifecycle harness; ordinary test-only signing, no proof backend.

Existing credential/attribute/path vectors are read unchanged. Ephemeral manager
and audience keys authenticate new service/request messages only. The ordinary
native signer does not establish bounded keygen/signing. Private witnesses remain
in the fixture harness; the controlled adapter stores public X and opaque tokens.
"""

from dataclasses import replace
from threading import Lock

from pqdid.backend import load_backend
from pqdid.relations import auth
from pqdid.statements import encode_auth_statement
from pqdid.verifier_state import (
    CURRENT_CONTEXT,
    CurrentStateReply,
    InMemoryChallengeStore,
    Presentation,
    ProofVerdict,
    ReferenceVerifier,
    ResolvedDID,
)

from .binding_merkle_reference import record
from .relation_cases import auth_case, state


class TestClock:
    __test__ = False

    def __init__(self, now=99):
        self.value = now

    def now(self):
        return self.value


class TestNonces:
    __test__ = False

    def __init__(self):
        self.count = 0
        self.lock = Lock()

    def nonce(self):
        with self.lock:
            self.count += 1
            return self.count.to_bytes(32, "big")


class NativeTestSigner:
    def __init__(self, native):
        self.signer = native.Signature("ML-DSA-65")
        self.public_key = self.signer.generate_keypair()
        self.lock = Lock()

    def sign(self, message, context):
        with self.lock:
            return self.signer.sign_with_ctx_str(message, context)

    def close(self):
        self.signer.free()


class TestAuthority:
    __test__ = False

    def __init__(self):
        native = load_backend()
        self.manager = NativeTestSigner(native)
        self.audiences = [NativeTestSigner(native), NativeTestSigner(native)]
        pp, self.original, self.witness = auth_case()
        self.pp = replace(pp, revocation_public_key=self.manager.public_key)
        self.metadata = record("meta", pp.issuer_reference, pp.namespace)
        self.states = {}
        for name in ("old", "updated"):
            original = state(name)
            message = record(
                "state", pp.suite, self.metadata, original.epoch.to_bytes(8, "big"), original.root
            )
            self.states[name] = replace(
                original, signature=self.manager.sign(message, b"PQ-DID/state/v1")
            )

    def reply(self, nonce, current, *, context=CURRENT_CONTEXT):
        encoded = record(
            "rstate",
            current.namespace,
            current.epoch.to_bytes(8, "big"),
            current.root,
            current.signature,
        )
        message = record("current", self.pp.suite, self.metadata, nonce, encoded)
        return CurrentStateReply(nonce, current, self.manager.sign(message, context))

    def close(self):
        for signer in [self.manager, *self.audiences]:
            signer.close()


class TestProvider:
    __test__ = False

    def __init__(self, authority):
        self.authority = authority
        self.current_state = authority.states["old"]
        self.instance_value = authority.pp
        self.transform_reply = lambda reply: reply
        self.after_read = lambda: None
        self.resolve_calls = []
        self.resolution = None

    def instance(self, expected):
        return self.instance_value

    def current(self, expected, nonce):
        reply = self.authority.reply(nonce, self.current_state)
        reply = self.transform_reply(reply)
        self.after_read()  # Snapshot has already linearised before this deterministic event.
        return reply

    def resolve_did(self, did, version):
        self.resolve_calls.append((did, version))
        return self.resolution


class ControlledProofAdapter:
    """Explicit test seam, not a cryptographic proof implementation or receipt."""

    def __init__(self, pp):
        self.pp = pp
        self.approved = set()
        self.calls = []
        self.before_verdict = lambda: None
        self.override = None

    def verify(self, statement, proof):
        encoded = encode_auth_statement(self.pp, statement)
        self.calls.append((encoded, proof))
        self.before_verdict()
        if self.override is not None:
            return self.override
        return ProofVerdict.VALID if (encoded, proof) in self.approved else ProofVerdict.INVALID


class Harness:
    def __init__(self, authority, index=0, *, did=False, policy=None, store=None):
        self.authority = authority
        self.pp = authority.pp
        self.clock = TestClock()
        self.nonces = TestNonces()
        self.provider = TestProvider(authority)
        self.adapter = ControlledProofAdapter(self.pp)
        self.audience = (b"audience-A", b"audience-B")[index]
        self.session = b"trusted-session"
        self.store = store if store is not None else InMemoryChallengeStore(self.audience)
        self.verifier = ReferenceVerifier(
            parameters=self.pp,
            audience=self.audience,
            request_public_key=authority.audiences[index].public_key,
            clock=self.clock,
            store=self.store,
            provider=self.provider,
            signer=authority.audiences[index],
            proof_verifier=self.adapter,
            nonces=self.nonces,
        )
        self.policy = policy if policy is not None else authority.original.context.policy
        self.request = self.verifier.create_challenge(
            session=self.session, policy=self.policy, expires_at=100, require_did_state=did
        )
        assert self.request is not None
        self.statement = replace(
            authority.original,
            parameters=self.pp,
            state=self.request.state,
            context=self.request.context,
            disclosed=self.policy.disclosed,
        )

    def model_presentation(self, statement=None):
        """Approve public fixture bytes for lifecycle tests, without claiming a proof."""
        statement = self.statement if statement is None else statement
        token = b"TEST-ONLY-REFERENCE-VERDICT"
        self.adapter.approved.add((encode_auth_statement(self.pp, statement), token))
        return Presentation(statement.disclosed, statement.disclosed_attributes, token)

    def relation_presentation(self, statement, witness):
        """Local same-witness evaluator; output is only a fixture for the test seam."""
        outcome = auth(self.pp, statement, witness)
        token = b"TEST-ONLY-LOCAL-RELATION-RESULT"
        if outcome:
            self.adapter.approved.add((encode_auth_statement(self.pp, statement), token))
        return Presentation(statement.disclosed, statement.disclosed_attributes, token), outcome

    def verify(self, presentation=None, *, context=None, session=None):
        return self.verifier.verify(
            session=self.session if session is None else session,
            context=self.request.context if context is None else context,
            presentation=self.model_presentation() if presentation is None else presentation,
        )


def valid_resolution(did, version):
    return ResolvedDID(b'{"id":"' + did + b'"}', version, "application/did+json", True)
