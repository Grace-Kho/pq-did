"""Cross-service reference tests and explicit UNSAFE-restart negative controls.

Passing negative controls demonstrate a missing recovery guarantee; they do NOT
certify that stale reconstruction is safe. No real crash, storage or proof test.
"""

import inspect
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from threading import Barrier

import pytest

import pqdid.issuance as issuance
from pqdid.did_state import DIDStatus, ReferenceDIDController
from pqdid.issuance import HolderAcceptance, IssueStatus, ReferenceIssuer, SessionPhase
from pqdid.revocation_state import HistoryResult, ManagerError, ManagerStatus
from pqdid.verifier_state import (
    Decision,
    InMemoryChallengeStore,
    Presentation,
    Registration,
    UnsupportedProofVerifier,
)
from pqdid.witness_updates import UpdateStatus, update_authentication_witness, update_witness

from .did_state_cases import DIDAuthority
from .lifecycle_review_cases import (
    Cut,
    LifecycleHarness,
    simulated_manager,
    simulated_verifier,
)
from .revocation_state_cases import RecordingSigner
from .verifier_state_cases import TestNonces


@pytest.fixture(scope="module")
def authority():
    value = DIDAuthority()
    yield value
    value.close()


@pytest.fixture
def h(authority):
    return LifecycleHarness(authority)


@pytest.mark.parametrize("point", ["reserved", "signed-before-log", "logged-before-delivery"])
def test_issuance_cut_preserves_effects_and_new_session_never_reuses_id(h, monkeypatch, point):
    issue = h.issue
    if point == "reserved":
        target, name = issue.manager, "reserve_identifier"
        original = getattr(target, name)
        fault = Cut(point, original, after=True)
        monkeypatch.setattr(target, name, fault)
        result = issue.begin()
        submission = None
    else:
        _, submission = issue.pending()
        target, name = issue.issuer, "_commit"
        original = getattr(target, name)
        fault = Cut(point, original, after=point == "logged-before-delivery")
        monkeypatch.setattr(target, name, fault)
        result = issue.issuer.finish(issue.request.session, submission)
        assert len(issue.signer.calls) == 1  # Actual native signing + bounded validation happened.
    assert fault.hits == 1 and result.status is IssueStatus.FAILURE and result.issued is None
    before = issue.issuer.snapshot()
    assert issue.manager.snapshot().allocated_count == 43
    logged = point == "logged-before-delivery"
    assert len(before.certifications) == int(logged)
    assert before.sessions[0][1] is (SessionPhase.CERTIFIED if logged else SessionPhase.ABORTED)
    assert len(before.used_nonces) == int(point != "reserved")
    assert issue.begin().status is IssueStatus.REPLAY
    if submission is not None:
        assert issue.issuer.finish(issue.request.session, submission).status is IssueStatus.REPLAY
    monkeypatch.setattr(target, name, original)
    next_challenge = issue.begin(session=b"separately-approved-session").challenge
    assert next_challenge.identifier == 43
    prepared = issue.prepare(next_challenge)
    next_result = issue.issuer.finish(b"separately-approved-session", prepared)
    assert next_result.status is IssueStatus.CERTIFIED
    final = issue.issuer.snapshot()
    ids = [item.credential.revocation_identifier for item in final.certifications]
    assert ids == ([42, 43] if logged else [43])
    assert issue.manager.snapshot().allocated_count == 44
    assert before.certifications == final.certifications[: int(logged)]
    assert fault.completed is (point != "signed-before-log")


@pytest.mark.parametrize("after_commit", [False, True])
def test_holder_interruption_retains_whole_pair_or_nothing(h, monkeypatch, after_commit):
    issued = h.certify()
    if after_commit:
        fault = Cut("holder-return-lost", h.wallet.accept, after=True)
        with pytest.raises(ConnectionError):
            fault(issued)
        assert h.wallet.snapshot() is issued
        assert h.wallet.accept(issued).status is IssueStatus.REPLAY
    else:
        original = issuance.path_root
        fault = Cut("holder-check-interrupted", original, after=True, error=MemoryError)
        monkeypatch.setattr(issuance, "path_root", fault)
        assert h.wallet.accept(issued).status is IssueStatus.RESOURCE_EXHAUSTED
        assert h.wallet.snapshot() is None
        monkeypatch.setattr(issuance, "path_root", original)
        assert h.wallet.accept(issued).status is IssueStatus.ACCEPTED
    assert fault.hits == 1 and fault.completed
    assert h.wallet.snapshot().checkpoint == issued.checkpoint
    assert h.wallet.snapshot().credential == issued.credential
    assert h.issue.issuer.snapshot().certifications == (issued,)


def test_two_holder_acceptance_attempts_commit_one_complete_pair(h, monkeypatch):
    issued = h.certify()
    barrier, original = Barrier(2), issuance.path_root

    def at_commit(*args):
        root = original(*args)
        barrier.wait(timeout=3)
        return root

    monkeypatch.setattr(issuance, "path_root", at_commit)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(h.wallet.accept, issued) for _ in range(2)]
        outcomes = [future.result(timeout=5).status for future in futures]
    assert outcomes.count(IssueStatus.ACCEPTED) == 1
    assert outcomes.count(IssueStatus.REPLAY) == 1
    assert h.wallet.snapshot() is issued


def test_revocation_committed_during_update_delivery_outage_then_explicit_catchup(h, monkeypatch):
    issued = h.certify()
    assert h.wallet.accept(issued).status is IssueStatus.ACCEPTED
    verifier, presentation, valid = h.presentation()
    assert valid
    manager = h.issue.manager
    old = manager.snapshot()
    request = h.authority.request(old.state, 41)
    lost = Cut("revocation-response-lost", manager.revoke, after=True)
    with pytest.raises(ConnectionError):
        lost(request)
    committed = manager.snapshot()
    assert committed.state.epoch == 1 and len(committed.history) == 1
    assert request.nonce in committed.consumed_nonces
    retrieve = manager.updates
    calls = []

    def unavailable(namespace, after_epoch, target_epoch):
        calls.append((namespace, after_epoch, target_epoch))
        return HistoryResult(ManagerStatus.UNAVAILABLE)

    monkeypatch.setattr(manager, "updates", unavailable)
    assert manager.updates(h.pp.namespace, 0, 1).page is None
    assert verifier.verify(presentation) is Decision.STATE
    assert verifier.store.pending(verifier.request.context.nonce) is not None
    assert h.wallet.snapshot() is issued  # No partially advanced path/state.
    assert manager.revoke(request).status is ManagerStatus.CONFLICT
    monkeypatch.setattr(manager, "updates", retrieve)
    page = manager.updates(h.pp.namespace, 0, 1).page
    assert page.records == committed.history
    update = update_authentication_witness(
        h.pp, h.witness, old.state, page.endpoint_state, page.records
    )
    assert update.status is UpdateStatus.UPDATED
    fresh, proof, valid = h.presentation(index=1, witness=update.witness)
    assert valid and fresh.verify(proof) is Decision.ACCEPTED
    assert h.issue.issuer.snapshot().certifications == (issued,)
    assert update.witness.signature == h.witness.signature
    assert update.witness.attributes == h.witness.attributes
    assert calls == [(h.pp.namespace, 0, 1)]  # Public retrieval never receives private rid/path.


def test_did_outage_does_not_prevent_independent_revocation_or_anonymous_verification(
    h, monkeypatch
):
    h.certify()
    original = h.did.transport.read

    def unavailable(*_):
        raise ConnectionError("registry unavailable")

    monkeypatch.setattr(h.did.transport, "read", unavailable)
    assert h.did.controller.publish() is DIDStatus.UNAVAILABLE
    _, committed = h.revoke()
    update = update_authentication_witness(
        h.pp, h.witness, h.issued.checkpoint.state, committed.state, (committed.record,)
    )
    assert update.status is UpdateStatus.UPDATED
    verifier, presentation, valid = h.presentation(witness=update.witness)
    assert valid and verifier.verify(presentation) is Decision.ACCEPTED
    monkeypatch.setattr(h.did.transport, "read", original)
    assert h.did.controller.snapshot().version == h.issue.request.version


@pytest.mark.parametrize("operation", ["rotate", "deactivate"])
def test_did_change_after_issuance_read_has_no_cross_service_transaction(h, monkeypatch, operation):
    challenge, submission = h.issue.pending()
    resolver = h.issue.issuer.resolver
    current = resolver.current

    def read_then_change(*args):
        resolved = current(*args)  # Current DID read has linearised.
        outcome = h.did.rotate() if operation == "rotate" else h.did.controller.publish((0, 0))
        assert outcome is DIDStatus.CONFIRMED
        return resolved

    monkeypatch.setattr(resolver, "current", read_then_change)
    result = h.issue.issuer.finish(h.issue.request.session, submission)
    assert result.status is IssueStatus.CERTIFIED
    assert result.issued.credential.attributes == challenge.approved_attributes
    assert result.issued.checkpoint.state == challenge.state
    assert h.did.controller.snapshot().version != h.issue.request.version
    assert h.issue.manager.snapshot().state.epoch == 0


def test_revocation_after_final_issuance_read_does_not_roll_back_certification(h):
    _, submission = h.issue.pending()
    committed = []

    def during_signing(*_):
        _, result = h.revoke(42)
        committed.append(result)

    h.issue.signer.hook = during_signing
    result = h.issue.issuer.finish(h.issue.request.session, submission)
    assert result.status is IssueStatus.CERTIFIED
    issued = result.issued
    assert issued.checkpoint.state.epoch == 0 and committed[0].state.epoch == 1
    wallet = HolderAcceptance(h.pp, h.issue.secret, h.issue.attributes, submission.statement)
    assert (
        wallet.accept(issued).status is IssueStatus.ACCEPTED
    )  # Original valid issuance reference.
    updated = update_witness(h.pp, issued.checkpoint, committed[0].state, (committed[0].record,))
    assert updated.status is UpdateStatus.REVOKED and updated.checkpoint is None
    assert h.issue.issuer.snapshot().certifications == (issued,)


@pytest.mark.parametrize(
    "event,expected",
    [
        ("revocation-before-final-read", Decision.STATE),
        ("revocation-after-final-read", Decision.ACCEPTED),
        ("expiry-after-final-read", Decision.EXPIRED),
    ],
)
def test_real_manager_ordering_and_atomic_expiry(h, monkeypatch, event, expected):
    h.certify()
    verifier, presentation, valid = h.presentation()
    assert valid
    if event == "revocation-before-final-read":
        verifier.adapter.before_verdict = lambda: h.revoke()
    else:
        read = h.provider.current

        def after_read(*args):
            reply = read(*args)
            assert reply.state.epoch == 0
            if event.startswith("revocation"):
                h.revoke()
            else:
                verifier.clock.value = 100
            return reply

        monkeypatch.setattr(h.provider, "current", after_read)
    assert verifier.verify(presentation) is expected
    pending = verifier.store.pending(verifier.request.context.nonce)
    assert (pending is None) is (expected is Decision.ACCEPTED)
    assert h.issue.manager.snapshot().state.epoch == int(event.startswith("revocation"))


@pytest.mark.parametrize("error", [ConnectionError, MemoryError])
def test_acceptance_followed_by_lost_response_cannot_consume_twice(h, error):
    h.certify()
    verifier, presentation, valid = h.presentation()
    assert valid
    original = verifier.store.pending(verifier.request.context.nonce)
    fault = Cut("accepted-response-lost", verifier.verify, after=True, error=error)
    with pytest.raises(error):
        fault(presentation)
    assert fault.completed and fault.hits == 1
    assert verifier.store.pending(original.context.nonce) is None
    assert verifier.verify(presentation) is Decision.UNKNOWN
    assert verifier.store.consume(original, verifier.session, verifier.clock) is Decision.CONSUMED


def test_concurrent_presentations_with_real_services_and_wrong_audience(h, monkeypatch):
    h.certify()
    left, presentation, valid = h.presentation()
    right, own, valid_right = h.presentation(index=1)
    assert valid and valid_right
    assert right.verify(presentation, context=left.request.context) is Decision.MISMATCH
    assert right.store.pending(right.request.context.nonce) is not None
    barrier, original = Barrier(2), left.store.consume

    def simultaneous(*args):
        barrier.wait(timeout=3)
        return original(*args)

    monkeypatch.setattr(left.store, "consume", simultaneous)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(left.verify, presentation) for _ in range(2)]
        outcomes = [future.result(timeout=5) for future in futures]
    assert outcomes.count(Decision.ACCEPTED) == 1 and outcomes.count(Decision.CONSUMED) == 1
    assert right.verify(own) is Decision.ACCEPTED


def test_simulated_missing_verifier_records_and_complete_retained_tombstone(h):
    h.certify()
    verifier, presentation, valid = h.presentation()
    assert valid and verifier.verify(presentation) is Decision.ACCEPTED
    empty = InMemoryChallengeStore(verifier.audience)
    missing = simulated_verifier(verifier.verifier, empty)
    assert (
        missing.verify(
            session=verifier.session, context=verifier.request.context, presentation=presentation
        )
        is Decision.UNKNOWN
    )
    # TEST-ONLY reconstruction from a quiescent complete store; no persistence API exists.
    retained = InMemoryChallengeStore(verifier.audience)
    retained._records = dict(verifier.store._records)
    retained._consumed = set(verifier.store._consumed)
    restored = simulated_verifier(verifier.verifier, retained)
    assert (
        restored.verify(
            session=verifier.session, context=verifier.request.context, presentation=presentation
        )
        is Decision.UNKNOWN
    )
    assert retained._consumed == {verifier.request.context.nonce}
    assert verifier.store._consumed == retained._consumed


def test_unsafe_restart_negative_control_stale_pending_snapshot_can_reaccept(h):
    """Demonstrates unsupported rollback, NOT a passing at-most-once recovery guarantee."""
    h.certify()
    verifier, presentation, valid = h.presentation()
    saved_pending = verifier.store.pending(verifier.request.context.nonce)
    assert valid and verifier.verify(presentation) is Decision.ACCEPTED
    # Deliberately violate the existing trusted/shared-store contract by losing the tombstone.
    stale = InMemoryChallengeStore(verifier.audience)
    assert stale.register(saved_pending, verifier.clock) is Registration.ADDED
    unsafe = simulated_verifier(verifier.verifier, stale)
    assert (
        unsafe.verify(
            session=verifier.session, context=verifier.request.context, presentation=presentation
        )
        is Decision.ACCEPTED
    )
    assert verifier.store.pending(saved_pending.context.nonce) is None
    assert stale.pending(saved_pending.context.nonce) is None
    # A complete local snapshot can be rolled back. No production restore API/anchor is claimed.


def test_simulated_manager_complete_counter_survives_but_old_history_is_unavailable(h):
    h.certify()
    _, result = h.revoke()
    checkpoint = h.issue.manager.snapshot()
    restored = simulated_manager(h.pp, checkpoint, h.issue.manager_signer)
    assert restored.snapshot().allocated_count == 43
    assert restored.snapshot().state == checkpoint.state
    assert restored.snapshot().consumed_nonces == checkpoint.consumed_nonces
    assert restored.updates(h.pp.namespace, 0, 1).status is ManagerStatus.UNAVAILABLE
    assert (
        update_witness(h.pp, h.issued.checkpoint, result.state, ()).status
        is UpdateStatus.INVALID_HISTORY
    )
    reserved = restored.reserve_identifier(result.state.reference)
    assert reserved.status is ManagerStatus.ALLOCATED and reserved.identifier == 43
    assert h.issue.manager.snapshot() is checkpoint  # Reconstruction does not mutate the source.


def test_unsafe_restart_negative_control_signed_root_does_not_bind_allocation_counter(h):
    old = h.issue.manager.snapshot()
    h.certify()
    current = h.issue.manager.snapshot()
    assert old.state == current.state and (old.allocated_count, current.allocated_count) == (42, 43)
    stale = simulated_manager(h.pp, old, h.issue.manager_signer)
    duplicate = stale.reserve_identifier(old.state.reference)
    assert duplicate.status is ManagerStatus.ALLOCATED
    assert duplicate.identifier == h.issued.credential.revocation_identifier == 42
    # Explicit negative control: using an old checkpoint violates trusted bootstrap.
    assert current.allocated_count == 43 and h.issue.issuer.snapshot().certifications == (h.issued,)


def test_simulated_inconsistent_manager_checkpoint_fails_validation(h):
    h.certify()
    h.revoke()
    checkpoint = h.issue.manager.snapshot()
    with pytest.raises(ManagerError) as caught:
        simulated_manager(h.pp, replace(checkpoint, revoked=frozenset()), h.issue.manager_signer)
    assert caught.value.status is ManagerStatus.INVALID_ARTEFACT
    assert h.issue.manager.snapshot() is checkpoint


def test_simulated_pending_did_recovery_needs_retained_attempt_and_key_handles(h, monkeypatch):
    original = h.did.transport.append
    fault = Cut("DID-rotation-reply-lost", original, after=True)
    monkeypatch.setattr(h.did.transport, "append", fault)
    assert h.did.rotate() is DIDStatus.UNAVAILABLE
    snapshot = h.did.controller.snapshot()
    assert snapshot.pending is not None and len(h.did.registry.snapshot()[0][1]) == 2
    monkeypatch.setattr(h.did.transport, "append", original)
    # A fresh controller cannot infer its old possibly active private key from public records.
    missing = ReferenceDIDController(
        h.did.resolver,
        h.authority.controller.public_key,
        b"s" * 32,
        signer=RecordingSigner(h.authority.controller),
    )
    assert missing.recover() is DIDStatus.INVALID and missing.publish() is DIDStatus.CONFLICT
    restored = ReferenceDIDController(
        h.did.resolver,
        h.authority.controller.public_key,
        b"s" * 32,
        signer=RecordingSigner(h.authority.controller),
    )
    # TEST-ONLY complete quiescent rehydration; public ControllerSnapshot alone is insufficient.
    restored._state = snapshot
    restored._pending_signer = RecordingSigner(h.authority.rotated)
    assert restored.recover() is DIDStatus.CONFIRMED
    assert len(h.did.transport.writes) == 2  # Authenticated recovery did not resubmit.
    assert restored.publish((0, 0)) is DIDStatus.CONFIRMED
    assert h.did.registry.snapshot()[0][1][-1].body.active == 0


@pytest.mark.parametrize("damage", ["missing-approved-challenge", "interrupted-claimed"])
def test_simulated_incomplete_issuer_session_never_certifies(h, damage):
    _, submission = h.issue.pending()
    source = h.issue.issuer
    restored = ReferenceIssuer(
        h.pp,
        resolver=source.resolver,
        authorisation=source.authorisation,
        manager=h.issue.manager,
        signer=source.signer,
        proof_verifier=source.proof_verifier,
        nonces=TestNonces(),
    )
    # TEST-ONLY damaged checkpoint, never a supported import API.
    restored._sessions = {name: replace(entry) for name, entry in source._sessions.items()}
    restored._used_nonces = set(source._used_nonces)
    entry = restored._sessions[h.issue.request.session]
    if damage == "missing-approved-challenge":
        entry.challenge = None
        expected = IssueStatus.FAILURE
    else:
        entry.phase = SessionPhase.CLAIMED
        expected = IssueStatus.REPLAY
    result = restored.finish(h.issue.request.session, submission)
    assert result.status is expected and result.issued is None
    assert (
        restored.snapshot().certifications == ()
        and h.issue.manager.snapshot().allocated_count == 43
    )
    assert restored.snapshot().used_nonces == source.snapshot().used_nonces
    if damage == "interrupted-claimed":
        assert restored.abort(h.issue.request.session).status is IssueStatus.BUSY
    else:
        assert restored.snapshot().sessions[0][1] is SessionPhase.ABORTED


def test_simulated_complete_certification_log_keeps_replay_rejection(h):
    h.certify()
    source = h.issue.issuer
    restored = ReferenceIssuer(
        h.pp,
        resolver=source.resolver,
        authorisation=source.authorisation,
        manager=h.issue.manager,
        signer=source.signer,
        proof_verifier=source.proof_verifier,
        nonces=TestNonces(),
    )
    restored._sessions = {name: replace(entry) for name, entry in source._sessions.items()}
    restored._used_nonces = set(source._used_nonces)
    restored._certifications = source.snapshot().certifications
    assert restored.finish(h.issue.request.session, h.submission).status is IssueStatus.REPLAY
    assert (
        restored.begin(h.issue.request, h.issue.manager.snapshot().state).status
        is IssueStatus.REPLAY
    )
    assert restored.snapshot() == source.snapshot()
    assert h.issue.manager.snapshot().allocated_count == 43


def test_simulated_holder_missing_or_mixed_checkpoint_must_not_activate(h):
    h.certify()
    assert h.wallet.accept(h.issued).status is IssueStatus.ACCEPTED
    _, changed = h.revoke()
    reconstructed = HolderAcceptance(
        h.pp, h.issue.secret, h.issue.attributes, h.submission.statement
    )
    assert reconstructed.accept(None).status is IssueStatus.INVALID_INPUT
    mixed = replace(h.issued, checkpoint=replace(h.issued.checkpoint, state=changed.state))
    assert reconstructed.accept(mixed).status is IssueStatus.MISMATCH
    assert reconstructed.snapshot() is None
    assert reconstructed.accept(h.issued).status is IssueStatus.ACCEPTED
    # Acceptance restores the ORIGINAL pair; it asserts no latest-root freshness.
    fresh, presentation, valid = h.presentation()
    assert not valid and fresh.store.pending(fresh.request.context.nonce) is not None
    assert fresh.verify(presentation) is Decision.PROOF


def test_public_verifier_boundary_and_default_dependencies(h, monkeypatch, capsys):
    h.certify()
    left, presentation, valid = h.presentation()
    assert valid
    assert {field.name for field in fields(Presentation)} == {
        "disclosed",
        "disclosed_attributes",
        "proof",
    }
    assert set(inspect.signature(left.verifier.verify).parameters) == {
        "session",
        "context",
        "presentation",
    }
    h.did.transport.reads.clear()

    def forbidden(*_):
        pytest.fail("anonymous verifier must not request holder DID/controller/private material")

    monkeypatch.setattr(h.did.transport, "read", forbidden)
    left.verifier.proof_verifier = UnsupportedProofVerifier()
    assert left.verify(presentation) is Decision.UNSUPPORTED
    assert left.store.pending(left.request.context.nonce) is not None
    left.verifier.signer = None
    assert (
        left.verifier.create_challenge(session=b"other", policy=left.policy, expires_at=100) is None
    )
    left.verifier.proof_verifier = left.adapter
    assert left.verify(presentation) is Decision.ACCEPTED
    assert h.did.transport.reads == []
    assert len(left.adapter.calls[-1]) == 2  # Encoded public X and opaque token only.
    assert h.issue.secret not in left.adapter.calls[-1][0]
    for value in (
        h.issued,
        h.wallet.snapshot(),
        h.issue.issuer.snapshot(),
        h.did.controller.snapshot(),
    ):
        assert h.issue.secret.hex() not in repr(value) and h.issue.attributes.hex() not in repr(
            value
        )
    output = capsys.readouterr()
    assert output.out == output.err == ""
