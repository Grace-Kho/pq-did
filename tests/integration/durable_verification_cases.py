"""TEST ONLY synthetic public statements; no credential/knowledge/non-revocation proof."""

from dataclasses import replace

from pqdid import bounded_mldsa_sign as core
from pqdid.bounded_manager import BoundedDurableManager
from pqdid.durable_verification import BoundedDurableVerifier, ManagerVerificationProvider
from pqdid.merkle import default_subtree_roots
from pqdid.parameters import encode_parameters
from pqdid.persistence.records import ServiceKey
from pqdid.persistence.sqlite_store import SQLiteStore
from pqdid.recovery import Dependencies
from pqdid.recovery_records import Checkpoint, ManagerRecord, Role, VerifierRecord
from pqdid.revocation_state import RevocationRequest, SigningStatus
from pqdid.signing_adapters import IssuerSigningAdapter, ManagerSigningAdapter, TrustedSigningKey
from pqdid.statements import decode_state, encode_state
from pqdid.verifier_state import Presentation
from tests.unit.relation_cases import auth_case, parameters
from tests.unit.test_signing_adapters import Gate, StorePolicy
from tests.unit.verifier_state_cases import ControlledProofAdapter, TestClock, TestNonces

TOKEN = b"TEST-ONLY-REFERENCE-VERDICT"


def material():
    keys = tuple(core.reference_keygen_mldsa65(bytes([n]) * 32) for n in range(11, 15))
    pp = replace(
        parameters(), issuer_public_key=keys[0].public_key, revocation_public_key=keys[1].public_key
    )
    selected = tuple(
        TrustedSigningKey(pp, name * 32, role, name, key.public_key, key.secret_key)
        for key, role, name in zip(
            keys,
            (Role.ISSUER, Role.MANAGER, Role.VERIFIER, Role.VERIFIER),
            (b"I", b"M", b"A", b"B"),
            strict=True,
        )
    )
    _, original, _ = auth_case()
    root = default_subtree_roots(pp.domain)[20]
    blank = replace(original.state, root=root, epoch=0, signature=bytes(3309))
    adapter = ManagerSigningAdapter(selected[1], authorisation=Gate(selected[1]))
    signed = adapter.state(pp, blank)
    assert signed.status is SigningStatus.SIGNED
    return pp, selected, replace(blank, signature=signed.signature), original


class Rig:
    def __init__(self, root, data):
        self.pp, self.keys, self.state, self.original = data
        self.root, self.notes = root, {}
        self.clock = TestClock()
        self.ms = self.store("manager", self.keys[1], Dependencies())
        encoded = encode_state(self.pp, self.state)
        cp = self.checkpoint(self.keys[1], ManagerRecord(2, encoded, (), (), encoded, (), (), ()))
        mt = self.ms.initialise(b"admin", cp)
        self.mp, mt = self.ms.acquire(b"admin", b"g" * 32, mt, b"writer")
        self.manager = BoundedDurableManager(self.ms, self.mp, mt, signing_key=self.keys[1])
        self.providers, self.proofs, self.deps, self.stores = [], [], [], []
        self.permits, self.verifiers, self.requests, self.statements = [], [], [], []
        for index in range(2):
            key = self.keys[index + 2]
            audience = (b"audience-A", b"audience-B")[index]
            provider = ManagerVerificationProvider(self.manager, consumer=key.service_id)
            proof = ControlledProofAdapter(self.pp)
            deps = Dependencies(
                provider=provider,
                proof_verifier=proof,
                clock=self.clock,
                nonces=TestNonces(),
                audience=audience,
                request_key=key.public_key,
            )
            store = self.store("verifier" + str(index), key, deps, audience)
            cp = self.checkpoint(key, VerifierRecord(audience, key.public_key, ()))
            ticket = store.initialise(b"admin", cp)
            permit, ticket = store.acquire(b"admin", b"g" * 32, ticket, b"writer")
            verifier = BoundedDurableVerifier(store, permit, ticket, signing_key=key)
            self.providers.append(provider)
            self.proofs.append(proof)
            self.deps.append(deps)
            self.stores.append(store)
            self.permits.append(permit)
            self.verifiers.append(verifier)
            request = verifier.create_challenge(
                session=b"session", policy=self.original.context.policy, expires_at=100
            )
            assert request is not None
            self.requests.append(request)
            self.statements.append(
                replace(
                    self.original, parameters=self.pp, context=request.context, state=request.state
                )
            )

    def checkpoint(self, key, state):
        return Checkpoint(1, key.authority_role, key.service_id, encode_parameters(self.pp), state)

    def store(self, name, key, deps, audience=b""):
        directory = self.root / name
        directory.mkdir(mode=0o700, exist_ok=True)
        return SQLiteStore(
            directory / "authority.sqlite3",
            ServiceKey(key.authority_role, key.service_id, key.service_id, self.pp, audience),
            dependencies=deps,
            authorisation=StorePolicy(),
        )

    def presentation(self, index=0):
        statement = self.statements[index]
        from pqdid.statements import encode_auth_statement

        self.proofs[index].approved.add((encode_auth_statement(self.pp, statement), TOKEN))
        return Presentation(statement.disclosed, statement.disclosed_attributes, TOKEN)

    def verify(self, index=0, *, context=None, presentation=None):
        return self.verifiers[index].verify(
            session=b"session",
            context=self.requests[index].context if context is None else context,
            presentation=self.presentation(index) if presentation is None else presentation,
        )

    def summary(self):
        values = []
        for store in self.stores:
            ticket, cp, _ = store.inspect(b"writer")
            values.append(
                {
                    "audience": cp.state.audience.decode(),
                    "head": ticket.digest.hex(),
                    "generation": ticket.generation,
                    "challenges": len(cp.state.challenges),
                    "consumed": sum(row.consumed for row in cp.state.challenges),
                }
            )
        mt, cp, _ = self.ms.inspect(b"writer")
        return {
            "verifiers": values,
            "manager_head": mt.digest.hex(),
            "manager_epoch": decode_state(self.pp, cp.state.state).epoch,
        }

    def consumed(self):
        return [v["consumed"] for v in self.summary()["verifiers"]]

    def reopen(self, index, ticket):
        key, deps = self.keys[index + 2], self.deps[index]
        store = self.store("verifier" + str(index), key, deps, deps.audience)
        verifier = BoundedDurableVerifier(store, self.permits[index], ticket, signing_key=key)
        self.stores[index], self.verifiers[index] = store, verifier

    def revoke(self):
        state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        blank = RevocationRequest(1, state.reference, b"r" * 32, bytes(3309))
        key = self.keys[0]
        signed = IssuerSigningAdapter(key, authorisation=Gate(key)).revocation_request(
            self.pp, blank
        )
        assert signed.status is SigningStatus.SIGNED
        return self.manager.revoke(b"R" * 32, replace(blank, signature=signed.signature))
