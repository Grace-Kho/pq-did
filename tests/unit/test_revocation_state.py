"""Manager state-machine tests; independent trees and explicitly synthetic signing."""

import inspect
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from pqdid import bounded_mldsa as mldsa
from pqdid import revocation_state as manager_module
from pqdid.codec import EncodingError, decode_record
from pqdid.revocation_state import (
    ManagerError,
    ManagerLimits,
    ManagerStatus,
    ReferenceRevocationManager,
    SigningResult,
    SigningStatus,
    build_revocation_request_message,
)
from pqdid.statements import encode_state
from pqdid.verifier_state import Decision, build_current_message
from pqdid.witness_updates import (
    UPDATE_RECORD_BYTES,
    UpdateLimits,
    UpdateStatus,
    WitnessCheckpoint,
    build_update_message,
    decode_update,
    update_authentication_witness,
    update_witness,
)
from pqdid.witnesses import encode_auth_witness

from .binding_merkle_reference import SparseReferenceTree, record
from .relation_cases import auth_case
from .revocation_state_cases import RevocationAuthority
from .sampler_streams import CountingReader, ball_stream, ntt_stream
from .verifier_state_cases import Harness
from .witness_update_cases import ref_bytes


@pytest.fixture(scope="module")
def authority():
    authority = RevocationAuthority()
    yield authority
    authority.close()


@pytest.fixture
def model(authority):
    return authority.manager_model()[0]


def unchanged(model, before, result, status=None):
    assert model.snapshot() is before
    assert result.state is None and result.record is None
    assert result.status is not ManagerStatus.COMMITTED
    if status is not None:
        assert result.status is status


def commit(authority, model, identifier, nonce=None):
    old = model.snapshot()
    nonce = old.state.epoch.to_bytes(32, "big") if nonce is None else nonce
    result = model.revoke(authority.request(old.state, identifier, nonce))
    assert result.status is ManagerStatus.COMMITTED
    return result


def test_exact_authorised_transition_and_independent_messages(authority):
    model, signer, tree = authority.manager_model()
    old = model.snapshot()
    request = authority.request(old.state)
    assert build_revocation_request_message(authority.pp, request) == record(
        "revreq",
        authority.pp.suite,
        authority.metadata,
        (42).to_bytes(4, "big"),
        ref_bytes(old.state),
        request.nonce,
    )
    result = model.revoke(request)
    assert result.status is ManagerStatus.COMMITTED
    new = model.snapshot()
    expected = SparseReferenceTree(authority.pp.suite, authority.metadata, [*old.revoked, 42])
    assert new.state == result.state and new.tree.root == expected.root == result.state.root
    assert new.allocated_count == old.allocated_count
    assert new.revoked == old.revoked | {42}
    assert new.consumed_nonces == old.consumed_nonces | {request.nonce}
    assert new.history == (result.record,) and old.history == ()
    update = decode_update(authority.pp, result.record)
    assert update.old_path == tree.path(42)
    assert update.old_state == old.state and update.new_state == result.state
    assert decode_record(result.record, "rupdate")[3] == tree.path(42)
    assert len(result.record) == 11162
    assert signer.calls == [
        (
            record(
                "state",
                authority.pp.suite,
                authority.metadata,
                (old.state.epoch + 1).to_bytes(8, "big"),
                expected.root,
            ),
            b"PQ-DID/state/v1",
        ),
        (
            record(
                "update",
                authority.pp.suite,
                authority.metadata,
                ref_bytes(old.state),
                ref_bytes(result.state),
                (42).to_bytes(4, "big"),
                tree.path(42),
            ),
            b"PQ-DID/update/v1",
        ),
    ]
    assert build_update_message(authority.pp, update) == signer.calls[1][0]


@pytest.mark.parametrize("identifier", [0, 2**20 - 1])
def test_identifier_boundaries(authority, identifier):
    model, _, tree = authority.manager_model(empty=True)
    result = commit(authority, model, identifier)
    expected = SparseReferenceTree(authority.pp.suite, authority.metadata, [identifier])
    assert result.state.root == expected.root
    assert decode_update(authority.pp, result.record).old_path == tree.path(identifier)


def test_allocated_aborted_issuance_can_revoke_without_a_credential(authority):
    model, _, _ = authority.manager_model(empty=True, allocated_count=8)
    assert commit(authority, model, 7).status is ManagerStatus.COMMITTED
    before = model.snapshot()
    unchanged(
        model, before, model.revoke(authority.request(before.state, 8)), ManagerStatus.UNALLOCATED
    )
    assert before.allocated_count == 8  # No allocation or recycling operation exists.


@pytest.mark.parametrize(
    "kind",
    [
        "negative-id",
        "boolean-id",
        "high-id",
        "namespace",
        "short-root",
        "negative-epoch",
        "short-nonce",
        "long-nonce",
        "mutable-nonce",
        "short-signature",
        "wrong-type",
    ],
)
def test_malformed_request_before_signing(authority, model, kind):
    old = model.snapshot()
    request = authority.request(old.state)
    if kind in {"negative-id", "boolean-id", "high-id"}:
        request = replace(
            request, identifier={"negative-id": -1, "boolean-id": True, "high-id": 2**20}[kind]
        )
    elif kind in {"namespace", "short-root", "negative-epoch"}:
        field, value = {
            "namespace": ("namespace", b"N" * 32),
            "short-root": ("root", bytes(47)),
            "negative-epoch": ("epoch", -1),
        }[kind]
        request = replace(request, reference=replace(request.reference, **{field: value}))
    elif kind == "short-signature":
        request = replace(request, signature=bytes(3308))
    elif kind == "wrong-type":
        request = ()
    else:
        request = replace(
            request,
            nonce={
                "short-nonce": bytes(31),
                "long-nonce": bytes(33),
                "mutable-nonce": bytearray(32),
            }[kind],
        )
    unchanged(model, old, model.revoke(request), ManagerStatus.INVALID_INPUT)
    assert not model._signer.calls


@pytest.mark.parametrize(
    "kind", ["signature", "wrong-issuer", "role", "nonce", "identifier", "metadata"]
)
def test_invalid_issuer_authorisation(authority, model, kind):
    old = model.snapshot()
    request = authority.request(old.state)
    if kind == "signature":
        request = replace(request, signature=bytes(3309))
    elif kind == "wrong-issuer":
        request = authority.request(old.state, signer=authority.manager)
    elif kind == "role":
        request = authority.request(old.state, context=b"PQ-DID/state/v1")
    elif kind == "metadata":
        request = authority.request(
            old.state, metadata=record("meta", authority.pp.issuer_reference, b"X" * 32)
        )
    elif kind == "identifier":
        request = replace(request, identifier=43)
    else:
        request = replace(request, nonce=b"N" * 32)
    unchanged(model, old, model.revoke(request), ManagerStatus.UNAUTHORISED)
    assert not model._signer.calls


def test_duplicate_revocation_replay_and_stale_reference_do_not_commit(authority, model):
    old = model.snapshot()
    request = authority.request(old.state)
    assert model.revoke(request).status is ManagerStatus.COMMITTED
    before = model.snapshot()
    unchanged(model, before, model.revoke(request), ManagerStatus.CONFLICT)
    unchanged(
        model,
        before,
        model.revoke(authority.request(before.state, 42, b"N" * 32)),
        ManagerStatus.ALREADY_REVOKED,
    )
    unchanged(
        model,
        before,
        model.revoke(authority.request(before.state, 43, request.nonce)),
        ManagerStatus.REPLAY,
    )
    for field, value in [("epoch", before.state.epoch + 1), ("root", bytes(48))]:
        wrong = replace(
            authority.request(before.state, 43),
            reference=replace(before.state.reference, **{field: value}),
        )
        unchanged(model, before, model.revoke(wrong), ManagerStatus.CONFLICT)
    assert len(model._signer.calls) == 2


@pytest.mark.parametrize(
    "kind",
    [
        "counter",
        "revoked-domain",
        "revoked-unallocated",
        "nonce",
        "nonce-cap",
        "revoked-cap",
        "signature",
        "root",
        "limits",
    ],
)
def test_bootstrap_rejects_invalid_or_oversized_state(authority, kind):
    source, _, _ = authority.manager_model(empty=True)
    state = source.snapshot().state
    kwargs = dict(
        state=state, allocated_count=2**20, revoked=frozenset(), consumed_nonces=frozenset()
    )
    if kind == "counter":
        kwargs["allocated_count"] = 2**20 + 1
    elif kind == "revoked-domain":
        kwargs["revoked"] = frozenset({2**20})
    elif kind == "revoked-unallocated":
        kwargs.update(revoked=frozenset({0}), allocated_count=0)
    elif kind == "nonce":
        kwargs["consumed_nonces"] = frozenset({bytes(31)})
    elif kind == "nonce-cap":
        kwargs["consumed_nonces"] = frozenset(i.to_bytes(32, "big") for i in range(65))
    elif kind == "revoked-cap":
        kwargs["revoked"] = frozenset(range(65))
    elif kind == "signature":
        kwargs["state"] = replace(state, signature=bytes(3309))
    elif kind == "root":
        kwargs["state"] = authority.signed_state(bytes(48), 0)
    else:
        kwargs["limits"] = ()
    with pytest.raises((EncodingError, ManagerError)):
        ReferenceRevocationManager(authority.pp, **kwargs)


@pytest.mark.parametrize("dimension", ["history", "revoked", "nonces"])
def test_storage_limit_preserves_state_nonce_and_history(authority, dimension):
    limits = ManagerLimits(**{dimension: 0})
    model, signer, _ = authority.manager_model(empty=True, limits=limits)
    old = model.snapshot()
    unchanged(
        model, old, model.revoke(authority.request(old.state)), ManagerStatus.RESOURCE_EXHAUSTED
    )
    assert not signer.calls


def test_uint64_epoch_exhaustion_and_bad_limit_domains(authority):
    model, signer, _ = authority.manager_model(empty=True, epoch=2**64 - 1)
    old = model.snapshot()
    unchanged(
        model, old, model.revoke(authority.request(old.state)), ManagerStatus.RESOURCE_EXHAUSTED
    )
    assert not signer.calls
    for kwargs in [
        dict(history=33),
        dict(revoked=65),
        dict(nonces=65),
        dict(history=-1),
        dict(nonces=True),
    ]:
        with pytest.raises(EncodingError):
            ManagerLimits(**kwargs)


@pytest.mark.parametrize("phase", [0, 1])
@pytest.mark.parametrize(
    "failure", ["unsupported", "exhausted", "failed", "bad-shape", "bad-signature", "exception"]
)
def test_signing_failure_never_publishes_or_consumes(authority, phase, failure):
    model, signer, _ = authority.manager_model()
    old = model.snapshot()
    context = (b"PQ-DID/state/v1", b"PQ-DID/update/v1")[phase]

    def fail(message, role):
        if role != context:
            return None
        if failure == "exception":
            raise RuntimeError("controlled signer failure")
        return {
            "unsupported": SigningResult(SigningStatus.UNSUPPORTED),
            "exhausted": SigningResult(SigningStatus.EXHAUSTED),
            "failed": SigningResult(SigningStatus.FAILED),
            "bad-shape": b"not-a-typed-result",
            "bad-signature": SigningResult(SigningStatus.SIGNED, bytes(3309)),
        }[failure]

    signer.hook = fail
    expected = {
        "unsupported": ManagerStatus.SIGNING_UNSUPPORTED,
        "exhausted": ManagerStatus.RESOURCE_EXHAUSTED,
        "bad-signature": ManagerStatus.INVALID_ARTEFACT,
    }.get(failure, ManagerStatus.SIGNING_FAILED)
    unchanged(model, old, model.revoke(authority.request(old.state)), expected)
    assert len(signer.calls) == phase + 1


def test_absent_signer_and_wrong_width_fail_closed(authority):
    base, _, _ = authority.manager_model()
    old = base.snapshot()
    model = ReferenceRevocationManager(
        authority.pp,
        state=old.state,
        allocated_count=old.allocated_count,
        revoked=old.revoked,
        consumed_nonces=old.consumed_nonces,
    )
    unchanged(
        model,
        model.snapshot(),
        model.revoke(authority.request(old.state)),
        ManagerStatus.SIGNING_UNSUPPORTED,
    )
    assert model.read_current(b"N" * 32).status is ManagerStatus.SIGNING_UNSUPPORTED
    assert model.current(authority.pp, b"N" * 32) is None
    base._signer.hook = lambda *_: SigningResult(SigningStatus.SIGNED, bytes(3310))
    unchanged(base, old, base.revoke(authority.request(old.state)), ManagerStatus.INVALID_ARTEFACT)


@pytest.mark.parametrize("phase", [1, 2, 3])
@pytest.mark.parametrize("stream_kind", ["matrix", "challenge"])
def test_actual_bounded_verification_exhaustion_no_fallback(
    authority, phase, stream_kind, monkeypatch
):
    model, signer, _ = authority.manager_model()
    old = model.snapshot()
    request = authority.request(old.state)
    real_verify, real_reader = mldsa._verify_diagnostic, mldsa._shake_reader
    calls, streams = [], []
    active = None

    def reader(bits, seed):
        if active is not None:
            key, signature = active
            matching = (
                (bits == 128 and seed[:32] == key[:32])
                if stream_kind == "matrix"
                else (bits == 256 and seed == signature[:48])
            )
            if matching:
                stream = CountingReader(
                    ntt_stream(87) if stream_kind == "matrix" else ball_stream(200)
                )
                streams.append(stream)
                return stream
        return real_reader(bits, seed)

    def verify(key, message, signature, *, context):
        nonlocal active
        calls.append(context)
        active = (key, signature) if len(calls) == phase else None
        try:
            return real_verify(key, message, signature, context=context)
        finally:
            active = None

    monkeypatch.setattr(mldsa, "_shake_reader", reader)
    monkeypatch.setattr(mldsa, "_verify_diagnostic", verify)
    unchanged(model, old, model.revoke(request), ManagerStatus.RESOURCE_EXHAUSTED)
    assert len(calls) == phase and len(streams) == 1
    assert streams[0].consumed == (1026 if stream_kind == "matrix" else 256)
    assert len(signer.calls) == phase - 1


@pytest.mark.parametrize("fault", ["tree-memory", "transport", "decoder", "candidate-memory"])
def test_faults_during_preparation_leave_old_snapshot_usable(authority, model, monkeypatch, fault):
    old = model.snapshot()
    request = authority.request(old.state)

    def memory(*args, **kwargs):
        raise MemoryError("controlled allocation failure")

    expected = ManagerStatus.RESOURCE_EXHAUSTED
    if fault == "tree-memory":
        monkeypatch.setattr(manager_module._Tree, "revoke", memory)
    elif fault == "candidate-memory":
        monkeypatch.setattr(manager_module, "ManagerSnapshot", memory)
    elif fault == "transport":
        monkeypatch.setattr(manager_module, "encode_update", lambda *_: bytes(1))
        expected = ManagerStatus.INVALID_ARTEFACT
    else:
        original = manager_module.decode_update
        monkeypatch.setattr(
            manager_module,
            "decode_update",
            lambda *args: replace(original(*args), revoked_identifier=99),
        )
        expected = ManagerStatus.INVALID_ARTEFACT
    unchanged(model, old, model.revoke(request), expected)


@pytest.mark.parametrize("same_identifier", [False, True])
def test_concurrent_preparations_commit_one_consistent_successor(authority, same_identifier):
    model, signer, _ = authority.manager_model(empty=True)
    old = model.snapshot()
    requests = [
        authority.request(old.state, rid, bytes([index]) * 32)
        for index, rid in enumerate([0, 0 if same_identifier else 1], 1)
    ]
    barrier = Barrier(2, timeout=3)

    def rendezvous(message, context):
        if context == b"PQ-DID/state/v1":
            barrier.wait()

    signer.hook = rendezvous
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(model.revoke, requests))
    assert sum(r.status is ManagerStatus.COMMITTED for r in results) == 1
    assert all(
        r.status in {ManagerStatus.COMMITTED, ManagerStatus.CONFLICT, ManagerStatus.BUSY}
        for r in results
    )
    winner = next(i for i, r in enumerate(results) if r.status is ManagerStatus.COMMITTED)
    snapshot = model.snapshot()
    assert snapshot.state.epoch == 1 and len(snapshot.history) == 1
    assert snapshot.revoked == {requests[winner].identifier}
    assert snapshot.consumed_nonces == {requests[winner].nonce}
    assert len(signer.calls) == 4  # Both prepared against old; only one publishes.
    signer.hook = None
    if not same_identifier:
        loser = requests[1 - winner]
        # Explicitly new authorised request for the now-current reference.
        commit(authority, model, loser.identifier, loser.nonce)
        assert model.snapshot().state.epoch == 2 and model.snapshot().revoked == {0, 1}
    expected = SparseReferenceTree(
        authority.pp.suite, authority.metadata, list(model.snapshot().revoked)
    )
    assert model.snapshot().state.root == expected.root


def test_read_current_signature_and_overlap_linearisation(authority):
    model, signer, _ = authority.manager_model()
    original = model.snapshot()
    reply = model.read_current(b"C" * 32)
    assert reply.status is ManagerStatus.CURRENT and reply.reply.state == original.state
    message = record(
        "current",
        authority.pp.suite,
        authority.metadata,
        b"C" * 32,
        encode_state(authority.pp, original.state),
    )
    assert message == build_current_message(authority.pp, b"C" * 32, original.state)
    assert signer.calls[-1] == (message, b"PQ-DID/current/v1")
    request = authority.request(original.state)

    def advance(message, context):
        if context == b"PQ-DID/current/v1":
            assert model.revoke(request).status is ManagerStatus.COMMITTED

    signer.hook = advance
    assert model.read_current(b"D" * 32).status is ManagerStatus.CONFLICT
    signer.hook = None
    assert model.read_current(b"E" * 32).reply.state == model.snapshot().state
    assert reply.reply.state == original.state  # Later commits do not alter a past read.
    assert model.read_current(bytes(31)).status is ManagerStatus.INVALID_INPUT
    assert model.instance(replace(authority.pp, namespace=b"X" * 32)) is None
    assert model.current(replace(authority.pp, namespace=b"X" * 32), b"C" * 32) is None
    assert model.resolve_did(b"did", bytes(56)) is None


def test_busy_admission_has_no_wait_signing_or_state_mutation(authority, model):
    old = model.snapshot()
    request = authority.request(old.state)
    assert model._operations.acquire(blocking=False)
    assert model._operations.acquire(blocking=False)
    try:
        unchanged(model, old, model.revoke(request), ManagerStatus.BUSY)
        assert model.read_current(b"N" * 32).status is ManagerStatus.BUSY
        assert model.updates(authority.pp.namespace, 7, 7).status is ManagerStatus.BUSY
    finally:
        model._operations.release()
        model._operations.release()
    assert not model._signer.calls
    model._lock.acquire()
    try:
        assert model.revoke(request).status is ManagerStatus.BUSY
    finally:
        model._lock.release()


def test_full_history_retrieval_in_holder_sized_batches_and_storage_stop(authority):
    model, signer, initial = authority.manager_model(empty=True)
    checkpoint = WitnessCheckpoint(43, initial.path(43), model.snapshot().state)
    for identifier in range(32):
        commit(authority, model, identifier)
    old = model.snapshot()
    unchanged(
        model, old, model.revoke(authority.request(old.state, 32)), ManagerStatus.RESOURCE_EXHAUSTED
    )
    assert len(signer.calls) == 64
    first = model.updates(authority.pp.namespace, 0, 32).page
    assert first.next_epoch == 16 and not first.complete and len(first.records) == 16
    assert sum(map(len, first.records)) == 178592
    second = model.updates(authority.pp.namespace, first.next_epoch, first.requested_epoch).page
    assert second.next_epoch == 32 and second.complete and len(second.records) == 16
    for page in [first, second]:
        result = update_witness(authority.pp, checkpoint, page.endpoint_state, page.records)
        assert result.status is UpdateStatus.UPDATED
        checkpoint = result.checkpoint
    expected = SparseReferenceTree(authority.pp.suite, authority.metadata, list(range(32)))
    assert checkpoint.path == expected.path(43) and checkpoint.state.root == expected.root
    assert first.records + second.records == old.history
    assert model.updates(authority.pp.namespace, 0, 32).page == first  # No delivery consumption.


def test_lowered_retrieval_limits_empty_range_and_unavailable_history(authority):
    model, _, _ = authority.manager_model()
    initial = model.snapshot().state
    for identifier in [0, 2, 4]:
        commit(authority, model, identifier)
    page = model.updates(
        authority.pp.namespace,
        7,
        10,
        limits=UpdateLimits(records=3, encoded_bytes=2 * UPDATE_RECORD_BYTES),
    ).page
    assert len(page.records) == 2 and page.next_epoch == 9 and not page.complete
    assert (
        model.updates(
            authority.pp.namespace,
            7,
            10,
            limits=UpdateLimits(encoded_bytes=UPDATE_RECORD_BYTES - 1),
        ).status
        is ManagerStatus.RESOURCE_EXHAUSTED
    )
    empty = model.updates(authority.pp.namespace, 7, 7, limits=UpdateLimits(0, 0)).page
    assert empty.records == () and empty.complete and empty.endpoint_state == initial
    for start, end, status in [
        (6, 7, ManagerStatus.UNAVAILABLE),
        (7, 11, ManagerStatus.UNAVAILABLE),
        (9, 8, ManagerStatus.INVALID_INPUT),
        (-1, 7, ManagerStatus.INVALID_INPUT),
        (True, 7, ManagerStatus.INVALID_INPUT),
    ]:
        assert model.updates(authority.pp.namespace, start, end).status is status
    assert model.updates(b"X" * 32, 7, 7).status is ManagerStatus.INVALID_INPUT


@pytest.mark.parametrize("damage", ["gap", "duplicate", "malformed"])
def test_inconsistent_internal_history_is_never_silently_omitted(authority, model, damage):
    commit(authority, model, 0)
    commit(authority, model, 2)
    old = model.snapshot()
    history = {
        "gap": old.history[:1],
        "duplicate": (old.history[0],) * 2,
        "malformed": (old.history[0], b"malformed"),
    }[damage]
    # Test-only internal corruption; no public import/mutation/retention API exists.
    model._snapshot = replace(old, history=history)
    result = model.updates(authority.pp.namespace, 7, 9)
    assert result.status is ManagerStatus.UNAVAILABLE and result.page is None


def test_delivery_failure_cannot_undo_committed_retrievable_record(authority, model):
    old = model.snapshot()
    request = authority.request(old.state)

    def transport():
        result = model.revoke(request)
        assert result.status is ManagerStatus.COMMITTED
        raise ConnectionError("test-only lost response after commit")

    with pytest.raises(ConnectionError):
        transport()
    snapshot = model.snapshot()
    page = model.updates(authority.pp.namespace, old.state.epoch, snapshot.state.epoch).page
    assert page.records == snapshot.history
    unchanged(model, snapshot, model.revoke(request), ManagerStatus.CONFLICT)
    assert request.nonce in snapshot.consumed_nonces


@pytest.mark.parametrize("case", ["survivor", "revoked", "stale", "expired"])
def test_composition_holder_update_full_relation_and_verifier(authority, model, case):
    harness = Harness(authority)
    harness.verifier.provider = model
    rid = 42 if case == "revoked" else 43
    _, original, _ = auth_case(f"alpha-{rid}-old-002c")
    witness = authority.witnesses[rid]
    statement = replace(
        original,
        parameters=authority.pp,
        context=harness.request.context,
        state=harness.request.state,
    )
    token, valid = harness.relation_presentation(statement, witness)
    assert valid
    before = encode_auth_witness(authority.pp.schema, witness)
    commit(authority, model, 42)
    if case == "stale":
        assert harness.verify(token) is Decision.STATE
        return
    page = model.updates(authority.pp.namespace, 7, 8).page
    updated = update_authentication_witness(
        authority.pp, witness, page.starting_state, page.endpoint_state, page.records
    )
    request = harness.verifier.create_challenge(
        session=harness.session, policy=harness.policy, expires_at=100
    )
    assert request is not None
    current = replace(
        original, parameters=authority.pp, context=request.context, state=request.state
    )
    if case == "revoked":
        assert updated.status is UpdateStatus.REVOKED and updated.witness is None
        expected = SparseReferenceTree(
            authority.pp.suite, authority.metadata, list(model.snapshot().revoked)
        )
        token, valid = harness.relation_presentation(
            current, replace(witness, path=expected.path(rid))
        )
        assert not valid and harness.verify(token, context=request.context) is Decision.PROOF
    else:
        assert updated.status is UpdateStatus.UPDATED
        assert encode_auth_witness(authority.pp.schema, updated.witness)[:-960] == before[:-960]
        token, valid = harness.relation_presentation(current, updated.witness)
        assert valid
        if case == "expired":
            harness.clock.value = 100
        expected = Decision.EXPIRED if case == "expired" else Decision.ACCEPTED
        assert harness.verify(token, context=request.context) is expected
    assert encode_auth_witness(authority.pp.schema, witness) == before


def test_public_api_privacy_immutable_snapshot_and_no_diagnostics(authority, model, capsys):
    snapshot = model.snapshot()
    assert set(inspect.signature(model.updates).parameters) == {
        "namespace",
        "after_epoch",
        "target_epoch",
        "limits",
    }
    with pytest.raises(TypeError):
        snapshot.tree.layers[0][42] = bytes(48)
    assert snapshot.state.signature.hex() not in repr(snapshot)
    request = authority.request(snapshot.state)
    assert request.nonce.hex() not in repr(request)
    result = model.revoke(request)
    assert request.nonce not in result.record
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
