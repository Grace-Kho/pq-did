"""Synthetic adapter contracts; no native ABI, remote proof or host activation.

Fixture admission/claims/proof verdicts are explicit in-memory simulations. SQLite
tests use temporary real stores and application faults, not crash/power-loss tests.
"""

import inspect
import socket
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from pqdid import bounded_mldsa as verify
from pqdid import bounded_mldsa_sign as core
from pqdid import signing_adapters as a
from pqdid.binding import create_binding
from pqdid.codec import EncodingError
from pqdid.credentials import build_mcred
from pqdid.did_state import (
    DIDConfiguration,
    DIDStatus,
    IssuanceDIDAdapter,
    ReferenceDIDController,
    ReferenceDIDRegistry,
    ReferenceDIDResolver,
)
from pqdid.issuance import (
    EnrolmentChallenge,
    EnrolmentSubmission,
    IssueRequest,
    IssueStatus,
    ReferenceIssuer,
    SessionPhase,
)
from pqdid.merkle import default_subtree_roots
from pqdid.parameters import encode_parameters
from pqdid.persistence import sqlite_store
from pqdid.persistence.codec import Unavailable, decode
from pqdid.persistence.lifecycle import DurableManager
from pqdid.persistence.records import ServiceKey
from pqdid.persistence.sqlite_store import SQLiteStore
from pqdid.policy import Policy
from pqdid.recovery import Dependencies, _manager
from pqdid.recovery_records import (
    ApprovedChallenge,
    Checkpoint,
    IssuerRecord,
    ManagerRecord,
    Role,
)
from pqdid.relations import enrol
from pqdid.revocation_state import (
    ManagerStatus,
    ReferenceRevocationManager,
    RevocationRequest,
    SigningStatus,
)
from pqdid.schema import decode_attributes, encode_attributes
from pqdid.statements import RevocationState, encode_enrol_statement, encode_state
from pqdid.verifier_state import InMemoryChallengeStore, ProofVerdict, ReferenceVerifier
from pqdid.witnesses import EnrolmentWitness

from .relation_cases import auth_case, parameters


@pytest.fixture(scope="module")
def keys():
    # Explicit PUBLIC SYNTHETIC seeds; retain no private outputs on disk.
    return tuple(core.reference_keygen_mldsa65(bytes([i]) * 32) for i in range(1, 7))


class Gate:
    """TEST ONLY current-owner grant. No production authorisation is inferred."""

    def __init__(self, key):
        self.key, self.active, self.calls = key, True, []

    def allow(self, key, operation, inputs):
        self.calls.append(operation)  # No keys, randomness, message or intermediates.
        return self.active and key == self.key


class Nonces:
    def __init__(self):
        self.counter = 0

    def nonce(self):
        self.counter += 1
        return self.counter.to_bytes(32, "big")


class Approval:
    allowed = True

    def approve(self, pp, request, controller):
        return request.attributes if self.allowed and request.evidence == b"SYNTHETIC" else None


class Proof:
    """Exact locally evaluated statement/token, never a cryptographic proof."""

    def __init__(self, pp):
        self.pp, self.approved = pp, set()

    def verify(self, statement, proof):
        return (
            ProofVerdict.VALID
            if (encode_enrol_statement(self.pp, statement), proof) in self.approved
            else ProofVerdict.INVALID
        )


class Harness:
    def __init__(self, keys):
        self.pp = replace(
            parameters(),
            issuer_public_key=keys[0].public_key,
            revocation_public_key=keys[1].public_key,
        )
        self.keys = keys

        def selection(index, role, name):
            return a.TrustedSigningKey(
                self.pp, name[:1] * 32, role, name, keys[index].public_key, keys[index].secret_key
            )

        self.selected = [
            selection(i, role, name)
            for i, role, name in [
                (0, Role.ISSUER, b"issuer"),
                (1, Role.MANAGER, b"manager"),
                (2, Role.CONTROLLER, b"controller"),
                (3, Role.REGISTRY, b"registry"),
                (4, Role.CONTROLLER, b"next-controller"),
                (5, Role.VERIFIER, b"request"),
            ]
        ]
        self.gates = [Gate(key) for key in self.selected]
        self.issuer_adapter = a.IssuerSigningAdapter(self.selected[0], authorisation=self.gates[0])
        self.manager_adapter = a.ManagerSigningAdapter(
            self.selected[1], authorisation=self.gates[1]
        )
        self.config = DIDConfiguration(self.pp, b"G" * 32, keys[3].public_key)
        registry_adapter = a.RegistrySigningAdapter(
            self.selected[3], config=self.config, authorisation=self.gates[3]
        )
        self.registry = ReferenceDIDRegistry(self.config, signer=registry_adapter._bridge())
        self.resolver = ReferenceDIDResolver(self.config, self.registry, nonces=Nonces())

        def current(did):
            return next(
                (chain[-1] for name, chain in self.registry.snapshot() if name == did), None
            )

        self.current_record = current
        self.controller_adapters = [
            a.ControllerSigningAdapter(
                self.selected[i],
                config=self.config,
                expected_public_key=keys[i].public_key,
                current_record=current,
                authorisation=self.gates[i],
            )
            for i in (2, 4)
        ]
        self.controller = ReferenceDIDController(
            self.resolver,
            keys[2].public_key,
            b"s" * 32,
            signer=self.controller_adapters[0]._bridge(),
        )
        assert self.controller.publish() is DIDStatus.CONFIRMED
        self.did = self.controller.snapshot().did
        _, _, witness = auth_case()
        self.secret = witness.holder_secret
        values = list(decode_attributes(self.pp.schema, witness.attributes))
        values[self.pp.schema.did_index - 1] = self.did
        values[self.pp.schema.version_index - 1] = self.controller.snapshot().version
        self.attributes = encode_attributes(self.pp.schema, tuple(values))
        root = default_subtree_roots(self.pp.domain)[20]
        blank = RevocationState(self.pp.namespace, 0, root, bytes(3309))
        state = replace(blank, signature=self.manager_adapter.state(self.pp, blank).signature)
        self.manager = ReferenceRevocationManager(
            self.pp,
            state=state,
            allocated_count=0,
            revoked=frozenset(),
            consumed_nonces=frozenset(),
            signer=self.manager_adapter._bridge(),
        )
        self.approval, self.proof = Approval(), Proof(self.pp)
        self.issuer = ReferenceIssuer(
            self.pp,
            manager=self.manager,
            resolver=IssuanceDIDAdapter(self.resolver),
            authorisation=self.approval,
            proof_verifier=self.proof,
            signer=self.issuer_adapter._bridge(),
            nonces=Nonces(),
        )
        self.request = IssueRequest(
            b"session",
            self.did,
            self.controller.snapshot().version,
            self.attributes,
            b"SYNTHETIC",
            self.attributes,
        )
        self.request_adapter = a.RequestSigningAdapter(
            self.selected[5],
            audience=b"aud",
            expected_public_key=keys[5].public_key,
            authorisation=self.gates[5],
        )
        self.request_store = InMemoryChallengeStore(b"aud")
        self.verifier = ReferenceVerifier(
            parameters=self.pp,
            audience=b"aud",
            request_public_key=keys[5].public_key,
            clock=SimpleNamespace(now=lambda: 100),
            store=self.request_store,
            provider=self.manager,
            signer=self.request_adapter._bridge(),
            nonces=Nonces(),
        )

    def prepare(self, challenge):
        binding = create_binding(self.pp.domain, self.secret, self.attributes)
        statement = challenge.statement(binding)
        assert enrol(self.pp, statement, EnrolmentWitness(self.secret))
        token = b"SYNTHETIC-LOCAL-RELATION-VERDICT"
        self.proof.approved.add((encode_enrol_statement(self.pp, statement), token))
        signed = self.controller_adapters[0].control(self.pp, statement)
        assert signed.status is SigningStatus.SIGNED
        return EnrolmentSubmission(statement, token, signed.signature)

    def pending(self):
        result = self.issuer.begin(self.request, self.manager.snapshot().state)
        assert result.status is IssueStatus.PENDING
        return self.prepare(result.challenge)

    def revoke_request(self, identifier=0):
        request = RevocationRequest(
            identifier, self.manager.snapshot().state.reference, b"r" * 32, bytes(3309)
        )
        result = self.issuer_adapter.revocation_request(self.pp, request)
        assert result.status is SigningStatus.SIGNED
        return replace(request, signature=result.signature)


@pytest.fixture
def h(keys):
    return Harness(keys)


def failed_issue(h, result, status):
    assert result.status is status and result.issued is None
    snap = h.issuer.snapshot()
    assert not snap.certifications and snap.sessions[0][1] is SessionPhase.ABORTED
    assert len(snap.used_nonces) == 1 and h.manager.snapshot().allocated_count == 1


def test_trusted_selection_instance_context_and_override_rejection(h):
    before = h.manager.snapshot()
    binding = create_binding(h.pp.domain, h.secret, h.attributes)
    wrong = replace(h.pp, namespace=b"X" * 32)
    assert h.issuer_adapter.credential(wrong, binding, 0).status is SigningStatus.FAILED
    message = build_mcred(h.pp, h.pp.metadata, binding, 0)
    assert (
        h.issuer_adapter._bridge().sign(message, b"PQ-DID/state/v1").status is SigningStatus.FAILED
    )
    assert (
        h.issuer_adapter._bridge().sign(message + b"!", b"PQ-DID/credential/v1").status
        is SigningStatus.FAILED
    )
    foreign = build_mcred(wrong, wrong.metadata, binding, 0)
    assert (
        h.issuer_adapter._bridge().sign(foreign, b"PQ-DID/credential/v1").status
        is SigningStatus.FAILED
    )
    with pytest.raises(TypeError):
        h.issuer_adapter.credential(h.pp, binding, 0, role="state")
    with pytest.raises(TypeError):
        h.issuer_adapter.credential(h.pp, binding, 0, key_reference=b"manager", context=b"")
    assert h.manager.snapshot() == before and not h.issuer.snapshot().certifications


def test_default_denial_and_key_public_role_mismatch(h):
    binding = create_binding(h.pp.domain, h.secret, h.attributes)
    denied = a.IssuerSigningAdapter(h.selected[0])
    assert denied.credential(h.pp, binding, 0).signature is None
    with pytest.raises(EncodingError):
        a.IssuerSigningAdapter(h.selected[1])
    with pytest.raises(EncodingError):
        a.IssuerSigningAdapter(replace(h.selected[0], public_key=h.keys[1].public_key))
    with pytest.raises(core.BoundedMLDSAError):
        a.IssuerSigningAdapter(replace(h.selected[0], secret_key=h.keys[1].secret_key))
    alien = replace(h.selected[0], reference=b"foreign-handle")
    assert (
        a.IssuerSigningAdapter(alien, authorisation=h.gates[0])
        .credential(h.pp, binding, 0)
        .signature
        is None
    )
    assert not h.issuer.snapshot().certifications and h.manager.snapshot().allocated_count == 0


def test_all_nine_roles_through_authorised_lifecycle(h):
    submission = h.pending()
    result = h.issuer.finish(h.request.session, submission)
    assert result.status is IssueStatus.CERTIFIED and result.issued is not None
    assert h.issuer.snapshot().certifications == (result.issued,)
    revoked = h.manager.revoke(h.revoke_request())
    assert revoked.status is ManagerStatus.COMMITTED and revoked.state.epoch == 1
    snap = h.manager.snapshot()
    assert snap.history == (revoked.record,) and snap.revoked == frozenset({0})
    assert snap.consumed_nonces == frozenset({b"r" * 32})
    assert h.manager.read_current(b"c" * 32).status is ManagerStatus.CURRENT
    request = h.verifier.create_challenge(session=b"s", policy=Policy((), ()), expires_at=200)
    assert request is not None and h.request_store.pending(request.context.nonce) is not None
    operations = set().union(*(set(g.calls) for g in h.gates))
    assert operations == {
        "credential",
        "revreq",
        "state",
        "update",
        "current",
        "did-read",
        "did-record",
        "control",
        "request",
    }


def test_failed_authorisation_and_invalid_enrolment_preserve_reservations(h):
    h.approval.allowed = False
    denied = h.issuer.begin(h.request, h.manager.snapshot().state)
    assert denied.status is IssueStatus.UNAUTHORISED and denied.issued is None
    assert h.manager.snapshot().allocated_count == 0
    h.approval.allowed = True
    h.request = replace(h.request, session=b"second-session")
    submission = h.pending()
    before = h.gates[0].calls[:]
    result = h.issuer.finish(h.request.session, replace(submission, proof=b"invalid"))
    assert result.status is IssueStatus.PROOF and result.issued is None
    assert not h.issuer.snapshot().certifications and h.manager.snapshot().allocated_count == 1
    assert h.gates[0].calls == before and len(h.issuer.snapshot().used_nonces) == 1


@pytest.mark.parametrize("fault", ["entropy", "sampler", "attempts", "post-verify"])
def test_signing_faults_cannot_release_or_recycle(h, monkeypatch, fault):
    submission = h.pending()
    original, calls = core.bounded_sign_mldsa65, []

    def sign(key, message, *, role):
        if role != "credential":
            return original(key, message, role=role)
        calls.append(role)
        with monkeypatch.context() as m:
            if fault == "entropy":

                def unavailable(_length):
                    raise OSError("synthetic")

                m.setattr(core.secrets, "token_bytes", unavailable)
            elif fault == "sampler":

                def exhausted(_reader):
                    raise verify._SamplerExhausted("SampleInBall", 256)

                m.setattr(verify, "_sample_in_ball", exhausted)
            elif fault == "attempts":
                m.setattr(core, "_candidate", lambda *_args: None)
            else:
                m.setattr(
                    verify,
                    "_verify_diagnostic",
                    lambda *_args, **_kwargs: verify._VerificationResult(verify._Status.INVALID),
                )
            return original(key, message, role=role)

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    result = h.issuer.finish(h.request.session, submission)
    status = (
        IssueStatus.RESOURCE_EXHAUSTED if fault in {"sampler", "attempts"} else IssueStatus.FAILURE
    )
    failed_issue(h, result, status)
    assert calls == ["credential"]
    assert h.issuer.finish(h.request.session, submission).status is IssueStatus.REPLAY
    assert calls == ["credential"]


def test_issue_log_failure_holds_signed_candidate_private(h, monkeypatch):
    submission = h.pending()

    def fail(entry, issued):
        assert issued.credential.certificate.signature and not h.issuer.snapshot().certifications
        raise MemoryError("synthetic commit failure")

    monkeypatch.setattr(h.issuer, "_commit", fail)
    failed_issue(h, h.issuer.finish(h.request.session, submission), IssueStatus.RESOURCE_EXHAUSTED)


def test_second_revocation_signature_failure_publishes_neither(h, monkeypatch):
    assert (
        h.manager.reserve_identifier(h.manager.snapshot().state.reference).status
        is ManagerStatus.ALLOCATED
    )
    request = h.revoke_request()
    before, calls, original = h.manager.snapshot(), [], core.bounded_sign_mldsa65

    def sign(key, message, *, role):
        calls.append(role)
        if role == "update":
            raise core.BoundedMLDSAError(core.Failure.ENTROPY_FAILURE)
        return original(key, message, role=role)

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    result = h.manager.revoke(request)
    assert result.status is ManagerStatus.SIGNING_FAILED and result.state is result.record is None
    assert h.manager.snapshot() == before and calls == ["state", "update"]


def test_revocation_final_commit_conflict_preserves_atomic_publication(h, monkeypatch):
    import pqdid.revocation_state as rev

    h.manager.reserve_identifier(h.manager.snapshot().state.reference)
    request, before = h.revoke_request(), h.manager.snapshot()
    original = rev.decode_update

    def concurrent(pp, encoded):
        value = original(pp, encoded)
        assert (
            h.manager.reserve_identifier(before.state.reference).status is ManagerStatus.ALLOCATED
        )
        return value

    monkeypatch.setattr(rev, "decode_update", concurrent)
    result = h.manager.revoke(request)
    after = h.manager.snapshot()
    assert result.status is ManagerStatus.CONFLICT and result.record is result.state is None
    assert after.state == before.state and after.history == before.history
    assert after.allocated_count == before.allocated_count + 1 and not after.consumed_nonces


def test_controller_rotation_deactivation_and_stale_key(h):
    assert (
        h.controller.publish(
            (1, 1),
            new_public_key=h.keys[4].public_key,
            new_signer=h.controller_adapters[1]._bridge(),
        )
        is DIDStatus.CONFIRMED
    )
    prior = h.current_record(h.did)
    next_body = replace(prior.body, index=prior.body.index + 1, predecessor=prior.version[8:])
    assert h.controller_adapters[0].record(next_body).status is SigningStatus.FAILED
    assert h.current_record(h.did) == prior
    assert h.controller.publish((0, 0)) is DIDStatus.CONFIRMED
    after = h.registry.snapshot()
    assert h.controller.publish() is DIDStatus.DEACTIVATED and h.registry.snapshot() == after
    inactive = h.current_record(h.did)
    body = replace(inactive.body, index=inactive.body.index + 1, predecessor=inactive.version[8:])
    assert h.controller_adapters[1].record(body).status is SigningStatus.FAILED


def test_authority_withdrawn_during_signing_discards_signature(h, monkeypatch):
    submission = h.pending()
    original = core.bounded_sign_mldsa65

    def sign(key, message, *, role):
        signed = original(key, message, role=role)
        if role == "credential":
            h.gates[0].active = False
        return signed

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    failed_issue(h, h.issuer.finish(h.request.session, submission), IssueStatus.FAILURE)


class StorePolicy:
    """TEST ONLY existing store Authorisation protocol; no host identity claim."""

    def allow(self, key, principal, action):
        if action in {"initialise", "replace"}:
            return principal == b"admin"
        if action == "retrieve":
            return principal in {b"recipient", b"wrong-recipient"}
        return principal in {b"writer", b"replacement"}


class DurableFixture:
    def __init__(self, h, root):
        self.h, self.pp = h, h.pp
        pp, state = h.pp, h.manager.snapshot().state
        cp = Checkpoint(
            1,
            Role.MANAGER,
            b"manager"[:1] * 32,
            encode_parameters(pp),
            ManagerRecord(0, encode_state(pp, state), (), (), encode_state(pp, state), (), (), ()),
        )
        key = ServiceKey(Role.MANAGER, cp.service_id, b"A" * 32, pp)
        self.manager_store, permit, ticket = self.store(root / "manager", key, cp, Dependencies())
        self.manager = DurableManager(self.manager_store, permit, ticket)
        manager = self.manager

        class Port:
            parameters = pp

            def snapshot(self):
                return manager.snapshot()[1].state

            def registered_witness(self, identifier, reference):
                state = manager.snapshot()[1].state
                return _manager(pp, state, Dependencies()).registered_witness(identifier, reference)

        self.port = Port()
        deps = Dependencies(
            manager=self.port,
            resolver=IssuanceDIDAdapter(h.resolver),
            authorisation=h.approval,
            proof_verifier=h.proof,
        )
        cp = Checkpoint(
            1,
            Role.ISSUER,
            h.selected[0].service_id,
            encode_parameters(pp),
            IssuerRecord(0, (), (), ()),
        )
        key = ServiceKey(Role.ISSUER, cp.service_id, b"B" * 32, pp)
        self.issuer_store, self.permit, ticket = self.store(root / "issuer", key, cp, deps)
        self.issuer = a.BoundedDurableIssuer(
            self.issuer_store, self.permit, ticket, signing_key=h.selected[0]
        )
        approved = ApprovedChallenge(
            h.attributes,
            encode_state(pp, state),
            h.did,
            h.controller.snapshot().version,
            h.keys[2].public_key,
        )
        self.issue = b"i" * 32
        self.issuer.intent(
            self.issue,
            b"session",
            b"recipient",
            approved,
            self.manager_store.key.service_id,
            state.reference,
        )
        self.manager.reserve(
            b"r" * 32, self.issuer_store.key.service_id, self.issue, state.reference
        )
        self.issuer.attach(b"a" * 32, self.issue, self.manager)
        self.issuer.pending(b"p" * 32, self.issue, b"n" * 32)
        self.submission = h.prepare(EnrolmentChallenge(pp, h.attributes, 0, b"n" * 32, state))

    @staticmethod
    def store(root, key, cp, deps):
        root.mkdir(mode=0o700)
        store = SQLiteStore(
            root / "state.sqlite3", key, dependencies=deps, authorisation=StorePolicy()
        )
        ticket = store.initialise(b"admin", cp)
        permit, ticket = store.acquire(b"admin", b"g" * 32, ticket, b"writer")
        return store, permit, ticket

    def certify(self):
        return self.issuer.certify(b"s" * 32, b"c" * 32, self.issue, self.submission)


def test_durable_commit_recipient_and_interrupted_redelivery(h, monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        d = DurableFixture(h, Path(directory))
        original, signed = core.bounded_sign_mldsa65, []

        def sign(key, message, *, role):
            signed.append(role)
            return original(key, message, role=role)

        monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
        result = d.certify()
        assert result.decision == b"CERTIFIED" and result.response == b""
        assert signed.count("credential") == 1
        ticket, cp, entries = d.issuer.snapshot()
        assert entries[d.issue][0] == b"CERTIFIED" and len(cp.state.certifications) == 1
        assert d.manager.snapshot()[1].state.allocated_count == 1
        with pytest.raises(Unavailable):
            d.certify()  # A claim never re-signs after a response.
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            left.setblocking(False)
            right.setblocking(False)
            with pytest.raises(Unavailable, match="wrong-recipient"):
                d.issuer.retrieve_committed(b"c" * 32, b"wrong-recipient", left)
            with pytest.raises(BlockingIOError):
                right.recv(65536)

            def lost(point):
                if point == "before-enqueue":
                    raise Unavailable("synthetic interrupted delivery")

            with monkeypatch.context() as m:
                m.setattr(sqlite_store, "_fault", lost)
                with pytest.raises(Unavailable):
                    d.issuer.retrieve_committed(b"c" * 32, b"recipient", left)
            with pytest.raises(BlockingIOError):
                right.recv(65536)
            # Reopen the actual temporary SQLite file with the independently held head.
            store = SQLiteStore(
                d.issuer_store._path,
                d.issuer_store.key,
                dependencies=d.issuer_store._deps,
                authorisation=StorePolicy(),
            )
            recovered = a.BoundedDurableIssuer(store, d.permit, ticket, signing_key=h.selected[0])
            before = list(signed)
            assert recovered.retrieve_committed(b"c" * 32, b"recipient", left) == b"REDELIVERY"
            first = right.recv(65536)
            assert decode(first) == cp.state.certifications[0].issued
            assert recovered.retrieve_committed(b"c" * 32, b"recipient", left) == b"REDELIVERY"
            assert right.recv(65536) == first and signed == before
            assert recovered.snapshot()[0] == ticket
        finally:
            left.close()
            right.close()


def test_durable_log_failure_no_delivery_then_explicit_retirement(h, monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        d = DurableFixture(h, Path(directory))

        def fail(point):
            # Only certification writes include the private result; fail after rows,
            # before COMMIT, once the actual bounded signature has been computed.
            if point == "rows-before-commit":
                raise Unavailable("synthetic required commit failure")

        original = d.issuer._owner.log_certificate

        def log(*args):
            with monkeypatch.context() as m:
                m.setattr(sqlite_store, "_fault", fail)
                return original(*args)

        monkeypatch.setattr(d.issuer._owner, "log_certificate", log)
        with pytest.raises(Unavailable):
            d.certify()
        _, cp, entries = d.issuer.snapshot()
        assert entries[d.issue][0] == b"SIGNING" and not cp.state.certifications
        assert d.manager.snapshot()[1].state.allocated_count == 1
        with pytest.raises(Unavailable):
            d.certify()
        d.issuer.reconcile(b"x" * 32, d.issue, d.manager)
        _, cp, entries = d.issuer.snapshot()
        assert (
            entries[d.issue][0] == b"RETIRED" and cp.state.sessions[0].phase is SessionPhase.ABORTED
        )
        assert d.manager.snapshot()[1].state.allocated_count == 1


def test_durable_writer_fenced_during_signing_and_stale_head(h, monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        d = DurableFixture(h, Path(directory))
        original, calls = core.bounded_sign_mldsa65, []

        def sign(key, message, *, role):
            signature = original(key, message, role=role)
            if role == "credential":
                calls.append(role)
                d.issuer_store.acquire(b"admin", b"f" * 32, d.issuer.ticket, b"replacement")
            return signature

        monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
        with pytest.raises(Unavailable):
            d.certify()
        assert calls == ["credential"]
        ticket, cp, entries = d.issuer_store.inspect(b"replacement")
        assert ticket.generation == 2 and entries[d.issue][0] == b"SIGNING"
        assert not cp.state.certifications and d.manager.snapshot()[1].state.allocated_count == 1
        with pytest.raises(Unavailable):
            d.certify()
        assert calls == ["credential"]
        with pytest.raises(Unavailable):
            a.BoundedDurableIssuer(d.issuer_store, d.permit, ticket, signing_key=h.selected[0])


def test_request_signing_failure_retains_nonce_without_request(h):
    h.gates[5].active = False
    request = h.verifier.create_challenge(session=b"s", policy=Policy((), ()), expires_at=200)
    assert request is None
    record = h.request_store.pending((2).to_bytes(32, "big"))
    assert record is not None and record.context.session == b"s"
    assert not h.request_store._consumed


def test_api_has_no_raw_endpoint_or_fault_hooks_and_defaults_stay_closed(h):
    assert not hasattr(h.issuer_adapter, "sign") and not hasattr(h.manager_adapter, "sign")
    assert set(inspect.signature(h.issuer_adapter.credential).parameters) == {
        "pp",
        "binding",
        "identifier",
    }
    assert set(inspect.signature(a.BoundedDurableIssuer.certify).parameters) == {
        "self",
        "claim_operation",
        "certificate_operation",
        "issue_operation",
        "submission",
    }
    from pqdid.issuance import UnsupportedIssuerSigner
    from pqdid.revocation_state import UnsupportedManagerSigner

    assert UnsupportedIssuerSigner().sign(b"x", b"").status is SigningStatus.UNSUPPORTED
    assert UnsupportedManagerSigner().sign(b"x", b"").status is SigningStatus.UNSUPPORTED
    assert not hasattr(a.BoundedDurableIssuer, "log_certificate")
    assert not hasattr(a.BoundedDurableIssuer, "claim_signing")
