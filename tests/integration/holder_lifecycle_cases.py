"""TEST ONLY issued synthetic credentials and separate A/B/C evidence boundaries."""

from dataclasses import replace

from bounded_manager_cases import channel
from durable_issuance_cases import ISSUE
from durable_issuance_cases import Rig as IssuanceRig
from durable_issuance_cases import keys as keys

from pqdid.durable_issuance import accept_delivery
from pqdid.durable_verification import BoundedDurableVerifier, ManagerVerificationProvider
from pqdid.holder_lifecycle import ReferenceHolderLifecycle
from pqdid.issuance import HolderAcceptance, IssueStatus
from pqdid.parameters import encode_parameters
from pqdid.persistence.records import ServiceKey
from pqdid.persistence.sqlite_store import SQLiteStore, digest
from pqdid.recovery import Dependencies
from pqdid.recovery_records import Checkpoint, Role, VerifierRecord
from pqdid.relations import auth
from pqdid.revocation_state import RevocationRequest, SigningStatus
from pqdid.schema import project_attributes
from pqdid.signing_adapters import TrustedSigningKey
from pqdid.statements import AuthenticationStatement, decode_state, encode_auth_statement
from pqdid.verifier_state import Presentation
from tests.unit.relation_cases import auth_case
from tests.unit.test_signing_adapters import StorePolicy
from tests.unit.verifier_state_cases import ControlledProofAdapter, TestClock, TestNonces

TOKEN = b"TEST-ONLY-LOCALLY-EVALUATED-AUTH-RESULT"


class Rig(IssuanceRig):
    def __init__(self, root, material):
        super().__init__(root, material)
        submission = self.pending()
        assert self.flow.finish(ISSUE, submission).decision == b"CERTIFIED"
        with channel() as (sender, receiver):
            self.flow.retrieve(ISSUE, b"recipient", sender)
            assert accept_delivery(self.holder, receiver.recv(65536)).status is IssueStatus.ACCEPTED
        self.local = ReferenceHolderLifecycle(self.pp, self.holder, self.h.secret)
        self.initial = self.local.snapshot()
        self.clock, self.policy = TestClock(), auth_case()[1].context.policy
        self.verifiers, self.proofs, self.providers, self.requests, self.vkeys = [], [], [], [], []
        self.other = None
        for i in range(2):
            name = (b"A", b"B")[i]
            # Independent existing synthetic material; fixture role pins these keys to VERIFIER.
            pair = material[4 + i]
            key = TrustedSigningKey(
                self.pp, name * 32, Role.VERIFIER, name, pair.public_key, pair.secret_key
            )
            provider = ManagerVerificationProvider(self.manager, consumer=key.service_id)
            proof = ControlledProofAdapter(self.pp)
            deps = Dependencies(
                provider=provider,
                proof_verifier=proof,
                clock=self.clock,
                nonces=TestNonces(),
                audience=name,
                request_key=key.public_key,
            )
            directory = root / ("verifier" + str(i))
            directory.mkdir(mode=0o700)
            store = SQLiteStore(
                directory / "authority.sqlite3",
                ServiceKey(Role.VERIFIER, key.service_id, key.service_id, self.pp, name),
                dependencies=deps,
                authorisation=StorePolicy(),
            )
            cp = Checkpoint(
                1,
                Role.VERIFIER,
                key.service_id,
                encode_parameters(self.pp),
                VerifierRecord(name, key.public_key, ()),
            )
            ticket = store.initialise(b"admin", cp)
            permit, ticket = store.acquire(b"admin", b"g" * 32, ticket, b"writer")
            self.verifiers.append(BoundedDurableVerifier(store, permit, ticket, signing_key=key))
            self.proofs.append(proof)
            self.providers.append(provider)
            self.requests.append(None)
            self.vkeys.append(key)

    def issue_other(self):
        assert self.other is None
        op = b"j" * 32
        state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        challenge = self.flow.begin(
            op, replace(self.h.request, session=b"other"), state, b"recipient"
        )
        secret = self.h.secret
        try:
            self.h.secret = b"O" * 32
            submission = self.h.prepare(challenge)
        finally:
            self.h.secret = secret
        holder = HolderAcceptance(self.pp, b"O" * 32, self.h.attributes, submission.statement)
        assert self.flow.finish(op, submission).decision == b"CERTIFIED"
        with channel() as (sender, receiver):
            self.flow.retrieve(op, b"recipient", sender)
            assert accept_delivery(holder, receiver.recv(65536)).status is IssueStatus.ACCEPTED
        self.other = holder.snapshot()
        assert self.other.credential.revocation_identifier == 2
        return self.other

    def revoke(self, identifier):
        state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        request = RevocationRequest(
            identifier, state.reference, (state.epoch + 100).to_bytes(32, "big"), bytes(3309)
        )
        signed = self.h.issuer_adapter.revocation_request(self.pp, request)
        assert signed.status is SigningStatus.SIGNED
        return self.manager.revoke(
            digest((b"revoke", state.epoch, identifier)),
            replace(request, signature=signed.signature),
        )

    def request(self, index=0):
        request = self.verifiers[index].create_challenge(
            session=b"session", policy=self.policy, expires_at=100
        )
        assert request is not None
        self.requests[index] = request
        return request

    def prepare(self, index=0, *, request=None, **changes):
        args = dict(
            audience=self.vkeys[index].reference,
            session=b"session",
            request_public_key=self.vkeys[index].public_key,
            approved_policy=self.policy,
            now=self.clock.now(),
        )
        args.update(changes)
        return self.local.prepare(request or self.requests[index], **args)

    def local_at_request(self, index=0, witness=None):
        request = self.requests[index]
        snap = self.local.snapshot()
        statement = AuthenticationStatement(
            self.pp,
            self.pp.metadata,
            request.context,
            request.state,
            self.policy.disclosed,
            project_attributes(self.pp.schema, snap.credential.attributes, self.policy.disclosed),
        )
        return statement, auth(self.pp, statement, snap.witness if witness is None else witness)

    def synthetic_verify(self, index, inputs):
        # Test coordinator evaluates locally. Only canonical public X/token enter adapter.
        assert auth(self.pp, inputs.statement, inputs.witness)
        self.proofs[index].approved.add((encode_auth_statement(self.pp, inputs.statement), TOKEN))
        presentation = Presentation(
            inputs.statement.disclosed, inputs.statement.disclosed_attributes, TOKEN
        )
        return self.verifiers[index].verify(
            session=b"session", context=inputs.statement.context, presentation=presentation
        )

    def history(self):
        target = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        return self.manager.updates(self.pp.namespace, 0, target.epoch).page

    def two_updates(self):
        self.issue_other()
        self.revoke(2)
        self.revoke(1)
        return self.history()

    def summary(self):
        result = super().summary()
        snap = self.local.snapshot()
        result.update(
            holder_epoch=snap.state.epoch,
            holder_credential_unchanged=snap.credential == self.initial.credential,
            verifier_consumed=[
                sum(row.consumed for row in v.snapshot()[1].state.challenges)
                for v in self.verifiers
            ],
        )
        return result
