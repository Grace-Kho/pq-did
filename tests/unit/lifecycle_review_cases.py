"""Bounded integration/fault fixtures; no persistence engine or real proof backend.

Reuse native TEST-ONLY signing and holder-local evaluators from preceding packages.
Reconstructed objects are quiescent in-memory simulations, not crash recovery.
Fault diagnostics retain labels/counters only, never arguments or private results.
"""

from dataclasses import replace

from pqdid.issuance import HolderAcceptance
from pqdid.revocation_state import ManagerStatus, ReferenceRevocationManager
from pqdid.schema import project_attributes
from pqdid.verifier_state import ReferenceVerifier
from pqdid.witnesses import AuthenticationWitness

from .did_state_cases import DIDHarness
from .verifier_state_cases import Harness


class Cut:
    """One explicit before/after-call fault, with no sleep or automatic retry."""

    def __init__(self, label, call, *, after=False, error=ConnectionError):
        self.label, self.call, self.after, self.error = label, call, after, error
        self.hits = 0
        self.completed = False

    def __call__(self, *args, **kwargs):
        assert self.hits == 0, "fault point unexpectedly repeated"
        self.hits += 1
        if self.after:
            self.call(*args, **kwargs)
            self.completed = True
        raise self.error(self.label)


class LifecycleHarness:
    def __init__(self, authority):
        self.did = DIDHarness(authority)
        self.issue, self.provider = self.did.issuance()
        self.authority, self.pp = authority, authority.pp

    def certify(self):
        self.challenge, self.submission, self.issued = self.issue.issue()
        self.wallet = HolderAcceptance(
            self.pp, self.issue.secret, self.issue.attributes, self.submission.statement
        )
        self.witness = AuthenticationWitness(
            self.issue.secret,
            self.issue.attributes,
            self.issued.credential.revocation_identifier,
            self.issued.credential.certificate.signature,
            self.issued.checkpoint.path,
        )
        return self.issued

    def presentation(self, index=0, *, witness=None):
        harness = Harness(self.authority, index=index)
        harness.verifier.provider = self.provider
        harness.session = b"integration-session"
        harness.request = harness.verifier.create_challenge(
            session=harness.session,
            policy=harness.policy,
            expires_at=100,
        )
        assert harness.request is not None
        harness.statement = replace(
            harness.statement,
            context=harness.request.context,
            state=harness.request.state,
            disclosed_attributes=project_attributes(
                self.pp.schema, self.issue.attributes, harness.policy.disclosed
            ),
        )
        presentation, valid = harness.relation_presentation(
            harness.statement,
            self.witness if witness is None else witness,
        )
        return harness, presentation, valid

    def revoke(self, identifier=41, *, nonce=b"R" * 32):
        manager = self.issue.manager
        request = self.authority.request(manager.snapshot().state, identifier, nonce=nonce)
        result = manager.revoke(request)
        assert result.status is ManagerStatus.COMMITTED
        return request, result


def simulated_manager(pp, checkpoint, signer):
    """Use the existing TRUSTED-checkpoint constructor; it does not detect rollback.

    The constructor starts history at this checkpoint; old history is NOT restored.
    The test supplies live trusted state except in explicitly named negative controls.
    """
    return ReferenceRevocationManager(
        pp,
        state=checkpoint.state,
        allocated_count=checkpoint.allocated_count,
        revoked=checkpoint.revoked,
        consumed_nonces=checkpoint.consumed_nonces,
        signer=signer,
    )


def simulated_verifier(original, store):
    """New verifier object, explicitly supplied in-memory store; no durability claim."""
    return ReferenceVerifier(
        parameters=original.parameters,
        audience=original.audience,
        request_public_key=original.request_public_key,
        clock=original.clock,
        store=store,
        provider=original.provider,
        signer=original.signer,
        proof_verifier=original.proof_verifier,
        nonces=original.nonces,
    )
