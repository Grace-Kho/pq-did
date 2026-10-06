"""Reference lifecycle transitions only; no real enrolment/authentication proof."""

import inspect
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event

import pytest

from pqdid import bounded_mldsa
from pqdid.binding import create_binding
from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT, build_mcred, cred_valid
from pqdid.issuance import (
    CONTROL_CONTEXT,
    HolderAcceptance,
    IssueLimits,
    IssueStatus,
    SessionPhase,
)
from pqdid.revocation_state import ManagerStatus, SigningResult, SigningStatus
from pqdid.schema import decode_attributes, encode_attributes
from pqdid.statements import encode_enrol_statement
from pqdid.verifier_state import Decision, ProofVerdict
from pqdid.witness_updates import UpdateStatus, update_authentication_witness, update_witness
from pqdid.witnesses import AuthenticationWitness

from .issuance_cases import IssuanceAuthority, IssuanceHarness
from .sampler_streams import CountingReader
from .verifier_state_cases import Harness


@pytest.fixture(scope="module")
def authority():
    value = IssuanceAuthority()
    yield value
    value.close()


@pytest.fixture
def h(authority):
    return IssuanceHarness(authority)


def retired(h, status, result):
    assert result.status is status and result.issued is None and result.challenge is None
    assert h.issuer.snapshot().sessions[0][1] is SessionPhase.ABORTED
    assert h.issuer.snapshot().certifications == ()
    assert h.manager.snapshot().allocated_count == 43
    assert h.issuer.snapshot().used_nonces == frozenset({(1).to_bytes(32, "big")})


def test_success_exact_messages_and_holder_atomic_acceptance(h):
    before = h.manager.snapshot()
    challenge, submission, issued = h.issue()
    after = h.manager.snapshot()
    assert after.allocated_count == 43 and after.state is before.state
    assert after.tree is before.tree and after.history == before.history
    assert challenge.identifier == issued.credential.revocation_identifier == 42
    message, context = h.signer.calls[0]
    assert context == CREDENTIAL_SIGNING_CONTEXT
    assert message == build_mcred(h.pp, h.pp.metadata, submission.statement.binding, 42)
    assert decode_record(message, "cred")[-1] == (42).to_bytes(4, "big")
    assert h.proofs.calls == [(submission.statement, submission.proof)]
    assert len(h.resolver.calls) == 2 and len(h.authorisation.calls) == 1
    assert len(h.signer.calls) == 1 and not h.manager_signer.calls
    assert h.issuer.snapshot().certifications == (issued,)
    assert h.issuer.snapshot().sessions[0][1] is SessionPhase.CERTIFIED
    assert cred_valid(h.pp, issued.credential, h.secret)
    wallet = HolderAcceptance(h.pp, h.secret, h.attributes, submission.statement)
    assert wallet.snapshot() is None
    result = wallet.accept(issued)
    assert result.status is IssueStatus.ACCEPTED and wallet.snapshot() is issued
    assert wallet.accept(issued).status is IssueStatus.REPLAY
    assert wallet.snapshot() is issued
    assert "holder_secret" not in inspect.signature(h.issuer.finish).parameters
    assert "holder_secret" not in inspect.signature(h.issuer.begin).parameters
    assert "holder_secret" not in inspect.signature(h.proofs.verify).parameters


@pytest.mark.parametrize(
    "change",
    [
        "evidence",
        "approval",
        "did",
        "version",
        "resolution",
        "key",
        "current-version",
        "mutable-document",
    ],
)
def test_invalid_authorised_request_before_reservation(h, change):
    request = h.request
    if change == "evidence":
        request = replace(request, evidence=b"not-approved")
    elif change == "approval":
        request = replace(request, holder_approval=bytes(1024))
    elif change == "did":
        request = replace(request, did=b"did:wrong")
    elif change == "version":
        request = replace(request, version=b"x")
    elif change == "resolution":
        h.resolver.value = None
    elif change == "key":
        h.resolver.value = replace(h.resolver.value, controller_public_key=b"bad")
    elif change == "current-version":
        h.resolver.value = replace(
            h.resolver.value, resolution=replace(h.resolver.value.resolution, version=b"x" * 56)
        )
    else:
        h.resolver.value = replace(
            h.resolver.value,
            resolution=replace(
                h.resolver.value.resolution,
                document=bytearray(h.resolver.value.resolution.document),
            ),
        )
    before = h.manager.snapshot()
    result = h.issuer.begin(request, before.state)
    assert result.status in {
        IssueStatus.UNAUTHORISED,
        IssueStatus.MISMATCH,
        IssueStatus.INVALID_INPUT,
    }
    assert result.challenge is None and h.manager.snapshot() is before
    assert h.issuer.snapshot().certifications == ()
    assert not h.signer.calls and not h.proofs.calls


@pytest.mark.parametrize(
    "change",
    [
        "nonce",
        "identifier",
        "attributes",
        "binding",
        "issuer",
        "namespace",
        "state",
        "control-context",
    ],
)
def test_substituted_statement_or_controller_signature_retires_challenge(h, change):
    challenge, submission = h.pending()
    statement = submission.statement
    if change == "nonce":
        statement = replace(statement, issuer_nonce=b"X" * 32)
    elif change == "identifier":
        statement = replace(statement, revocation_identifier=43)
    elif change == "attributes":
        statement = replace(statement, approved_attributes=bytes(1024))
    elif change == "binding":
        statement = replace(statement, binding=replace(statement.binding, holder_value=b"x" * 48))
    elif change == "issuer":
        statement = replace(
            statement, parameters=replace(h.pp, issuer_public_key=h.authority.manager.public_key)
        )
    elif change == "namespace":
        statement = replace(statement, metadata=replace(statement.metadata, namespace=b"x" * 32))
    elif change == "state":
        statement = replace(statement, state=replace(statement.state, epoch=1))
    else:
        submission = replace(
            submission,
            controller_signature=h.authority.controller.sign(
                encode_enrol_statement(h.pp, statement), CREDENTIAL_SIGNING_CONTEXT
            ),
        )
    result = h.issuer.finish(h.request.session, replace(submission, statement=statement))
    assert result.status in {
        IssueStatus.UNAUTHORISED,
        IssueStatus.MISMATCH,
        IssueStatus.INVALID_INPUT,
    }
    assert result.issued is None and not h.signer.calls
    assert h.issuer.snapshot().sessions[0][1] is SessionPhase.ABORTED
    assert h.manager.snapshot().allocated_count == 43
    assert h.issuer.finish(h.request.session, h.prepare(challenge)).status is IssueStatus.REPLAY


@pytest.mark.parametrize("verdict", [ProofVerdict.INVALID, ProofVerdict.UNSUPPORTED, True])
def test_invalid_unsupported_or_truthy_proof_verdict(h, verdict):
    _, submission = h.pending()
    h.proofs.override = verdict
    result = h.issuer.finish(h.request.session, submission)
    retired(
        h,
        IssueStatus.UNSUPPORTED if verdict is ProofVerdict.UNSUPPORTED else IssueStatus.PROOF,
        result,
    )
    assert not h.signer.calls


def test_changed_binding_with_real_controller_signature_still_needs_exact_proof(h):
    _, submission = h.pending()
    statement = replace(
        submission.statement, binding=replace(submission.statement.binding, holder_value=b"x" * 48)
    )
    submission = replace(
        submission,
        statement=statement,
        controller_signature=h.authority.controller.sign(
            encode_enrol_statement(h.pp, statement), CONTROL_CONTEXT
        ),
    )
    retired(h, IssueStatus.PROOF, h.issuer.finish(h.request.session, submission))


@pytest.mark.parametrize("dependency", ["resolver", "authorisation", "reservation", "nonce"])
def test_begin_failure_boundary_preserves_completed_allocation(h, monkeypatch, dependency):
    def fail(*args):
        raise RuntimeError("controlled boundary failure")

    if dependency == "resolver":
        h.resolver.hook = fail
    elif dependency == "authorisation":
        h.authorisation.hook = fail
    elif dependency == "reservation":
        monkeypatch.setattr(h.manager, "reserve_identifier", fail)
    else:
        monkeypatch.setattr(h.issuer.nonces, "nonce", fail)
    result = h.begin()
    assert result.status is IssueStatus.FAILURE and result.challenge is None
    assert h.manager.snapshot().allocated_count == (43 if dependency == "nonce" else 42)
    assert h.issuer.snapshot().sessions[0][1] is SessionPhase.ABORTED
    assert not h.issuer.snapshot().certifications


@pytest.mark.parametrize(
    "dependency", ["proof", "final-did", "final-state", "sign", "commit", "post-commit"]
)
def test_finish_failure_boundaries_and_log_survival(h, monkeypatch, dependency):
    _, submission = h.pending()

    def fail(*args):
        raise RuntimeError("controlled boundary failure")

    if dependency == "proof":
        h.proofs.hook = fail
    elif dependency == "final-did":
        h.resolver.hook = fail
    elif dependency == "final-state":
        monkeypatch.setattr(h.manager, "registered_witness", fail)
    elif dependency == "sign":
        h.signer.hook = fail
    elif dependency == "commit":
        monkeypatch.setattr(h.issuer, "_commit", fail)
    else:
        commit = h.issuer._commit

        def committed_then_lost(*args):
            commit(*args)
            fail()

        monkeypatch.setattr(h.issuer, "_commit", committed_then_lost)
    result = h.issuer.finish(h.request.session, submission)
    assert result.status is IssueStatus.FAILURE and result.issued is None
    snapshot = h.issuer.snapshot()
    assert snapshot.sessions[0][1] is (
        SessionPhase.CERTIFIED if dependency == "post-commit" else SessionPhase.ABORTED
    )
    assert len(snapshot.certifications) == (1 if dependency == "post-commit" else 0)
    assert h.manager.snapshot().allocated_count == 43
    assert h.issuer.finish(h.request.session, submission).status is IssueStatus.REPLAY


@pytest.mark.parametrize(
    "failure", ["signature", "certified-message", "exhausted", "unsupported", "memory"]
)
def test_signing_failure_never_releases(h, failure):
    _, submission = h.pending()

    def hook(message, context):
        if failure == "memory":
            raise MemoryError("controlled allocation failure")
        if failure == "signature":
            return SigningResult(SigningStatus.SIGNED, bytes(3309))
        if failure == "certified-message":
            return SigningResult(
                SigningStatus.SIGNED, h.authority.issuer.sign(message + b"changed", context)
            )
        return SigningResult(
            SigningStatus.EXHAUSTED if failure == "exhausted" else SigningStatus.UNSUPPORTED
        )

    h.signer.hook = hook
    expected = {
        "signature": IssueStatus.UNAUTHORISED,
        "certified-message": IssueStatus.UNAUTHORISED,
        "unsupported": IssueStatus.UNSUPPORTED,
    }.get(failure, IssueStatus.RESOURCE_EXHAUSTED)
    retired(h, expected, h.issuer.finish(h.request.session, submission))
    assert len(h.signer.calls) == 1


@pytest.mark.parametrize("stage", ["proof", "bounded-verify"])
def test_real_verification_exhaustion_or_adapter_memory_failure(h, monkeypatch, stage):
    _, submission = h.pending()
    if stage == "proof":

        def fail():
            raise MemoryError("adapter capacity")

        h.proofs.hook = fail
    else:
        # Real unchanged RejNTTPoly loop exhausts, rather than a mocked VALID verdict.
        real_reader = bounded_mldsa._shake_reader
        streams = []

        def reader(bits, seed):
            if bits == 128:
                stream = CountingReader(b"\xff" * 1026)
                streams.append(stream)
                return stream
            return real_reader(bits, seed)

        monkeypatch.setattr(bounded_mldsa, "_shake_reader", reader)
    retired(h, IssueStatus.RESOURCE_EXHAUSTED, h.issuer.finish(h.request.session, submission))
    if stage == "bounded-verify":
        assert len(streams) == 1 and streams[0].consumed == 1026


@pytest.mark.parametrize(
    "mutation",
    [
        "bad-state-signature",
        "path",
        "identifier",
        "revoked",
        "advanced-state",
        "rotated-controller",
    ],
)
def test_invalid_initial_or_final_state_and_current_did(h, monkeypatch, mutation):
    if mutation == "bad-state-signature":
        old = h.manager.snapshot()
        result = h.issuer.begin(h.request, replace(old.state, signature=bytes(3309)))
        assert result.status is IssueStatus.STATE and h.manager.snapshot() is old
        return
    if mutation in {"path", "identifier"}:
        original = h.manager.reserve_identifier

        def reserve(reference):
            value = original(reference)
            return (
                replace(value, path=bytes(960))
                if mutation == "path"
                else replace(value, identifier=1 << 20)
            )

        monkeypatch.setattr(h.manager, "reserve_identifier", reserve)
        result = h.begin()
        assert result.status in {IssueStatus.STATE, IssueStatus.INVALID_INPUT}
        assert result.challenge is None and h.manager.snapshot().allocated_count == 43
        return
    _, submission = h.pending()
    if mutation == "rotated-controller":
        h.resolver.value = replace(
            h.resolver.value, controller_public_key=h.authority.manager.public_key
        )
    else:
        identifier = 42 if mutation == "revoked" else 41
        revoked = h.manager.revoke(h.authority.request(h.manager.snapshot().state, identifier))
        assert revoked.status is ManagerStatus.COMMITTED
    result = h.issuer.finish(h.request.session, submission)
    retired(
        h,
        IssueStatus.UNAUTHORISED if mutation == "rotated-controller" else IssueStatus.STATE,
        result,
    )
    assert not h.signer.calls


@pytest.mark.parametrize(
    "mutation",
    ["signature", "attributes", "binding", "issuer", "namespace", "path", "state", "identifier"],
)
def test_holder_substitution_does_not_commit_or_undo_issuer_log(h, mutation):
    _, submission, issued = h.issue()
    original = issued
    credential, point = issued.credential, issued.checkpoint
    if mutation == "signature":
        credential = replace(
            credential, certificate=replace(credential.certificate, signature=bytes(3309))
        )
    elif mutation == "attributes":
        values = list(decode_attributes(h.pp.schema, h.attributes))
        values[-1] += 1
        attributes = encode_attributes(h.pp.schema, values)
        credential = replace(
            credential,
            attributes=attributes,
            certificate=replace(
                credential.certificate,
                binding=replace(credential.certificate.binding, attributes=attributes),
            ),
        )
    elif mutation == "binding":
        credential = replace(
            credential,
            certificate=replace(
                credential.certificate, binding=create_binding(h.pp.domain, b"x" * 32, h.attributes)
            ),
        )
    elif mutation == "issuer":
        _, key_id, schema = decode_record(credential.metadata.issuer_reference, "iref")
        credential = replace(
            credential,
            metadata=replace(
                credential.metadata,
                issuer_reference=encode_record("iref", (b"other-issuer", key_id, schema)),
            ),
        )
    elif mutation == "namespace":
        credential = replace(credential, metadata=replace(credential.metadata, namespace=b"x" * 32))
    elif mutation == "path":
        point = replace(point, path=bytes(960))
    elif mutation == "state":
        point = replace(point, state=replace(point.state, signature=bytes(3309)))
    else:
        credential = replace(credential, revocation_identifier=43)
    wallet = HolderAcceptance(h.pp, h.secret, h.attributes, submission.statement)
    result = wallet.accept(replace(issued, credential=credential, checkpoint=point))
    assert result.status is not IssueStatus.ACCEPTED and result.issued is None
    assert wallet.snapshot() is None and h.issuer.snapshot().certifications == (original,)


def test_wrong_holder_opening_and_invalid_expected_instance(h):
    _, submission, _ = h.issue()
    for pp, secret in [
        (h.pp, b"wrong" * 6 + b"xx"),
        (replace(h.pp, issuer_public_key=h.authority.manager.public_key), h.secret),
    ]:
        with pytest.raises(EncodingError):
            HolderAcceptance(pp, secret, h.attributes, submission.statement)


def test_boundary_exhaustion_abort_and_revocation_of_aborted_allocation(authority):
    h = IssuanceHarness(authority, allocated_count=(1 << 20) - 1)
    challenge, _ = h.pending()
    assert challenge.identifier == (1 << 20) - 1
    h.issuer.abort(h.request.session)
    assert h.begin(b"new-session").status is IssueStatus.RESOURCE_EXHAUSTED
    assert h.manager.snapshot().allocated_count == 1 << 20
    result = h.manager.revoke(authority.request(h.manager.snapshot().state, challenge.identifier))
    assert result.status is ManagerStatus.COMMITTED
    assert (
        h.manager.registered_witness(challenge.identifier, result.state.reference).status
        is ManagerStatus.ALREADY_REVOKED
    )


def test_duplicate_sessions_nonce_reuse_and_no_holder_quota(h, monkeypatch):
    first = h.begin()
    assert h.begin().status is IssueStatus.REPLAY and h.manager.snapshot().allocated_count == 43
    h.issuer.abort(h.request.session)
    second = h.begin(b"same-holder-new-session")
    assert second.status is IssueStatus.PENDING and second.challenge.identifier == 43
    # A distinct session with the SAME approved attributes/binding is admissible.
    result = h.issuer.finish(b"same-holder-new-session", h.prepare(second.challenge))
    assert result.status is IssueStatus.CERTIFIED
    assert (
        h.issuer.finish(b"same-holder-new-session", h.prepare(second.challenge)).status
        is IssueStatus.REPLAY
    )
    monkeypatch.setattr(h.issuer.nonces, "nonce", lambda: first.challenge.nonce)
    assert h.begin(b"nonce-collision").status is IssueStatus.RESOURCE_EXHAUSTED
    assert h.manager.snapshot().allocated_count == 45  # Never recycle the third reservation.


def test_finite_store_and_default_adapters_fail_closed(authority):
    h = IssuanceHarness(authority, limits=IssueLimits(sessions=1), proof_verifier=None)
    _, submission = h.pending()
    retired(h, IssueStatus.UNSUPPORTED, h.issuer.finish(h.request.session, submission))
    assert h.begin(b"next").status is IssueStatus.RESOURCE_EXHAUSTED
    h = IssuanceHarness(authority, signer=None)
    _, submission = h.pending()
    retired(h, IssueStatus.UNSUPPORTED, h.issuer.finish(h.request.session, submission))


def test_input_and_local_capacity_admission(authority):
    h = IssuanceHarness(authority, limits=IssueLimits(proof_bytes=4, evidence_bytes=32))
    state = h.manager.snapshot().state
    assert (
        h.issuer.begin(replace(h.request, evidence=b"x" * 33), state).status
        is IssueStatus.RESOURCE_EXHAUSTED
    )
    assert h.manager.snapshot().allocated_count == 42
    _, submission = h.pending()
    retired(h, IssueStatus.RESOURCE_EXHAUSTED, h.issuer.finish(h.request.session, submission))
    with pytest.raises(EncodingError):
        IssueLimits(sessions=65)
    assert h.issuer.abort(bytearray(b"session")).status is IssueStatus.INVALID_INPUT


def test_concurrent_distinct_sessions_complete_with_distinct_identifiers(h):
    # Same holder/approved vector, distinct sessions; both may complete.
    first = h.begin().challenge
    second = h.begin(b"session-B").challenge
    a, b = h.prepare(first), h.prepare(second)
    barrier = Barrier(2)
    h.proofs.hook = lambda: barrier.wait(timeout=2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [
            pool.submit(h.issuer.finish, h.request.session, a),
            pool.submit(h.issuer.finish, b"session-B", b),
        ]
        results = [task.result(timeout=5) for task in tasks]
    assert all(r.status in {IssueStatus.CERTIFIED, IssueStatus.BUSY} for r in results)
    completed = [r for r in results if r.status is IssueStatus.CERTIFIED]
    identifiers = [r.issued.credential.revocation_identifier for r in completed]
    assert completed and len(identifiers) == len(set(identifiers))
    assert set(identifiers) <= {42, 43}
    assert len(h.issuer.snapshot().certifications) == len(completed)
    assert h.manager.snapshot().allocated_count == 44


def test_concurrent_duplicate_finish_only_one_can_certify(h):
    _, submission = h.pending()
    entered, resume = Event(), Event()

    def hold():
        entered.set()
        assert resume.wait(timeout=2)

    h.proofs.hook = hold
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(h.issuer.finish, h.request.session, submission)
        assert entered.wait(timeout=2)
        second = pool.submit(h.issuer.finish, h.request.session, submission).result(timeout=2)
        assert second.status is IssueStatus.REPLAY
        resume.set()
        assert first.result(timeout=5).status is IssueStatus.CERTIFIED
    assert len(h.issuer.snapshot().certifications) == len(h.signer.calls) == 1


def test_manager_reservation_race_and_stale_reference(h):
    reference = h.manager.snapshot().state.reference
    barrier = Barrier(2)

    def allocate():
        barrier.wait(timeout=2)
        return h.manager.reserve_identifier(reference)

    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [pool.submit(allocate) for _ in range(2)]
        results = [t.result(timeout=5) for t in tasks]
    winners = [r.identifier for r in results if r.status is ManagerStatus.ALLOCATED]
    assert len(winners) == len(set(winners)) and len(winners) >= 1
    assert all(r.status in {ManagerStatus.ALLOCATED, ManagerStatus.BUSY} for r in results)
    assert h.manager.snapshot().allocated_count == 42 + len(winners)
    before = h.manager.snapshot()
    assert (
        h.manager.reserve_identifier(replace(reference, epoch=1)).status is ManagerStatus.CONFLICT
    )
    assert h.manager.snapshot() is before
    assert h.manager.registered_witness(100, reference).status is ManagerStatus.UNALLOCATED


def test_issued_credential_composes_with_presentation_revocation_and_holder_update(h):
    _, submission, issued = h.issue()
    wallet = HolderAcceptance(h.pp, h.secret, h.attributes, submission.statement)
    assert wallet.accept(issued).status is IssueStatus.ACCEPTED
    h.resolver.value = None  # Later loss/rotation of DID control is no presentation condition.
    witness = AuthenticationWitness(
        h.secret, h.attributes, 42, issued.credential.certificate.signature, issued.checkpoint.path
    )
    harness = Harness(h.authority)
    harness.verifier.provider = h.manager
    harness.request = harness.verifier.create_challenge(
        session=harness.session, policy=harness.policy, expires_at=100
    )
    harness.statement = replace(
        harness.statement, state=harness.request.state, context=harness.request.context
    )
    presentation, local_ok = harness.relation_presentation(harness.statement, witness)
    assert local_ok and harness.verify(presentation) is Decision.ACCEPTED
    # An unrelated revocation updates this surviving credential's local witness.
    old = h.manager.snapshot().state
    transition = h.manager.revoke(h.authority.request(old, 41))
    updated = update_authentication_witness(
        h.pp, witness, old, transition.state, (transition.record,)
    )
    assert updated.status is UpdateStatus.UPDATED
    assert (
        updated.witness.signature == witness.signature
        and updated.witness.attributes == h.attributes
    )
    harness.request = harness.verifier.create_challenge(
        session=harness.session, policy=harness.policy, expires_at=100
    )
    harness.statement = replace(
        harness.statement, state=harness.request.state, context=harness.request.context
    )
    presentation, local_ok = harness.relation_presentation(harness.statement, updated.witness)
    assert local_ok and harness.verify(presentation) is Decision.ACCEPTED
    old = h.manager.snapshot().state
    transition = h.manager.revoke(h.authority.request(old, 42, nonce=b"S" * 32))
    checkpoint = replace(issued.checkpoint, path=updated.witness.path, state=old)
    revoked = update_witness(h.pp, checkpoint, transition.state, (transition.record,))
    assert revoked.status is UpdateStatus.REVOKED and revoked.checkpoint is None
    assert h.issuer.snapshot().certifications == (issued,)


def test_holder_rejects_authenticated_revoked_initial_checkpoint(h):
    _, submission, issued = h.issue()
    result = h.manager.revoke(h.authority.request(h.manager.snapshot().state, 42))
    assert result.status is ManagerStatus.COMMITTED
    revoked = replace(
        issued,
        checkpoint=replace(
            issued.checkpoint, state=result.state, path=h.manager.snapshot().tree.path(42)
        ),
    )
    # Even if the expected, authentically signed state is current, zero membership fails.
    statement = replace(submission.statement, state=result.state)
    wallet = HolderAcceptance(h.pp, h.secret, h.attributes, statement)
    assert wallet.accept(revoked).status is IssueStatus.STATE
    assert wallet.snapshot() is None
    assert h.issuer.snapshot().certifications == (issued,)


def test_two_simultaneous_begins_same_authenticated_session_reserve_once(h):
    entered, resume = Event(), Event()

    def hold():
        entered.set()
        assert resume.wait(timeout=2)

    h.authorisation.hook = hold
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(h.begin)
        assert entered.wait(timeout=2)
        second = pool.submit(h.begin).result(timeout=2)
        assert second.status is IssueStatus.REPLAY
        resume.set()
        assert first.result(timeout=5).status is IssueStatus.PENDING
    assert h.manager.snapshot().allocated_count == 43
    assert len(h.issuer.snapshot().used_nonces) == 1


def test_reservation_reply_loss_retains_manager_counter(h, monkeypatch):
    reserve = h.manager.reserve_identifier

    def lose(reference):
        assert reserve(reference).status is ManagerStatus.ALLOCATED
        raise OSError("controlled delivery failure after allocation")

    monkeypatch.setattr(h.manager, "reserve_identifier", lose)
    assert h.begin().status is IssueStatus.FAILURE
    assert h.manager.snapshot().allocated_count == 43
    assert h.issuer.snapshot().certifications == ()
    assert h.issuer.snapshot().sessions[0][1] is SessionPhase.ABORTED
