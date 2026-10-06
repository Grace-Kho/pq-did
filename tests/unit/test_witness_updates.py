"""Bounded UpdateWit reference tests; controlled adapters never represent proofs."""

from dataclasses import replace

import pytest

from pqdid import bounded_mldsa as mldsa
from pqdid import witness_updates as updater
from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.statements import encode_auth_statement
from pqdid.verifier_state import Decision
from pqdid.witness_updates import (
    MAX_UPDATE_BYTES,
    UPDATE_RECORD_BYTES,
    UpdateLimits,
    UpdateReason,
    UpdateStatus,
    WitnessCheckpoint,
    build_update_message,
    decode_update,
    encode_update,
    update_authentication_witness,
    update_witness,
)
from pqdid.witnesses import encode_auth_witness

from .binding_merkle_reference import record
from .relation_cases import auth_case
from .sampler_streams import CountingReader, ball_stream, ntt_stream
from .verifier_state_cases import Harness
from .witness_update_cases import UpdateAuthority, ref_bytes


@pytest.fixture(scope="module")
def authority():
    result = UpdateAuthority()
    yield result
    result.close()


@pytest.fixture(scope="module")
def history(authority):
    return authority.history([0, 2, 4])


def checkpoint(history, identifier=43, at=0):
    return WitnessCheckpoint(identifier, history.trees[at].path(identifier), history.states[at])


def run(authority, history, identifier=43, *, records=None, start=None, target=None, **kwargs):
    return update_witness(
        authority.pp,
        checkpoint(history, identifier) if start is None else start,
        history.states[-1] if target is None else target,
        history.records if records is None else records,
        **kwargs,
    )


def assert_no_replacement(result):
    assert result.status is not UpdateStatus.UPDATED
    assert result.checkpoint is None


def test_exact_independent_transport_and_signed_message(authority, history):
    encoded = history.records[0]
    update = decode_update(authority.pp, encoded)
    assert len(encoded) == UPDATE_RECORD_BYTES
    assert encode_update(authority.pp, update) == encoded
    fields = decode_record(encoded, "rupdate")
    assert len(fields) == 5 and len(fields[3]) == 960
    expected = record(
        "update",
        authority.pp.suite,
        authority.metadata,
        ref_bytes(update.old_state),
        ref_bytes(update.new_state),
        update.revoked_identifier.to_bytes(4, "big"),
        update.old_path,
    )
    assert build_update_message(authority.pp, update) == expected
    assert expected != encoded


def test_empty_chain_preserves_only_authenticated_same_state(authority, history):
    old = checkpoint(history)
    result = run(authority, history, records=(), start=old, target=old.state)
    assert result.status is UpdateStatus.UPDATED and result.checkpoint == old
    # Logical identity is ref(ns,e,root), with both carried signatures still checked.
    resigned = authority.signed_state(old.state.root, old.state.epoch)
    assert (
        run(authority, history, records=(), start=old, target=resigned).status
        is UpdateStatus.UPDATED
    )
    assert run(authority, history, records=(), start=old).status is UpdateStatus.INVALID_HISTORY
    bad = replace(old.state, signature=bytes(3309))
    assert (
        run(authority, history, records=(), start=old, target=bad).reason
        is UpdateReason.AUTHENTICATION
    )


@pytest.mark.parametrize("level", range(20))
def test_each_divergence_level_matches_independent_tree(authority, level):
    history = authority.history([1 << level], empty=True)
    old = checkpoint(history, 0)
    result = run(authority, history, 0)
    assert result.status is UpdateStatus.UPDATED
    assert result.checkpoint.path == history.trees[-1].path(0)
    changed = [
        j
        for j in range(20)
        if old.path[j * 48 : (j + 1) * 48] != result.checkpoint.path[j * 48 : (j + 1) * 48]
    ]
    assert changed == [level]
    assert old == checkpoint(history, 0)


@pytest.mark.parametrize(
    "holder,revoked", [(0, 2**20 - 1), (2**20 - 1, 0), (0, 0), (2**20 - 1, 2**20 - 1)]
)
def test_identifier_boundaries_and_own_revocation(authority, holder, revoked):
    history = authority.history([revoked], empty=True)
    result = run(authority, history, holder)
    if holder == revoked:
        assert result.status is UpdateStatus.REVOKED
        assert_no_replacement(result)
    else:
        assert result.checkpoint.path == history.trees[-1].path(holder)
        assert result.checkpoint.identifier == holder


def test_multiple_updates_and_explicit_validated_chunk_resume(authority, history):
    whole = run(authority, history)
    assert whole.checkpoint.path == history.trees[-1].path(43)
    first = run(
        authority,
        history,
        records=history.records[:1],
        target=history.states[1],
        limits=UpdateLimits(records=1, encoded_bytes=UPDATE_RECORD_BYTES),
    )
    rest = run(authority, history, records=history.records[1:], start=first.checkpoint)
    assert rest.checkpoint == whole.checkpoint
    replay = run(authority, history, start=whole.checkpoint)
    assert replay.status is UpdateStatus.INVALID_HISTORY
    assert whole.checkpoint == checkpoint(history, at=-1)


@pytest.mark.parametrize("position", [0, 2])
def test_revocation_within_batch_never_returns_usable_witness(authority, position):
    additions = [0, 2]
    additions.insert(position, 43)
    h = authority.history(additions)
    result = run(authority, h)
    assert result.status is UpdateStatus.REVOKED
    assert_no_replacement(result)


@pytest.mark.parametrize("kind", ["identifier", "path", "short-path", "long-path"])
def test_wrong_starting_witness(authority, history, kind):
    old = checkpoint(history, 0)
    if kind == "identifier":
        old = replace(old, identifier=2)  # Non-uniform initial tree distinguishes these paths.
    elif kind == "path":
        old = replace(old, path=bytes(960))
    else:
        old = replace(old, path=bytes(959 if kind == "short-path" else 961))
    result = run(authority, history, start=old)
    assert result.status is UpdateStatus.INVALID_INPUT
    assert_no_replacement(result)


@pytest.mark.parametrize(
    "kind",
    [
        "siblings",
        "old-root",
        "new-root",
        "update-signature",
        "state-signature",
        "metadata",
        "wrong-role",
        "signed-transport",
    ],
)
def test_tampered_authenticated_data(authority, history, kind):
    update = decode_update(authority.pp, history.records[0])
    old, new, path = update.old_state, update.new_state, update.old_path
    metadata = authority.metadata
    context = b"PQ-DID/update/v1"
    if kind == "siblings":
        path = bytes([path[0] ^ 1]) + path[1:]
    elif kind == "old-root":
        old = authority.signed_state(bytes(48), old.epoch)
    elif kind == "new-root":
        new = authority.signed_state(bytes(48), new.epoch)
    elif kind == "state-signature":
        new = replace(new, signature=bytes(3309))
    elif kind == "metadata":
        metadata = record("meta", authority.pp.issuer_reference, b"Z" * 32)
    elif kind == "wrong-role":
        context = b"PQ-DID/state/v1"
    encoded = authority.public_update(
        old,
        new,
        update.revoked_identifier,
        path,
        metadata=metadata,
        context=context,
        sign_transport=kind == "signed-transport",
    )
    if kind == "update-signature":
        encoded = encoded[:-1] + bytes([encoded[-1] ^ 1])
    # Restrict to one transition so a signed but incorrect root reaches tree validation.
    result = run(
        authority,
        history,
        records=(encoded,),
        target=new,
        start=replace(checkpoint(history), state=old),
    )
    assert_no_replacement(result)
    if kind in {"siblings", "new-root"}:
        assert result.reason is UpdateReason.TRANSITION


@pytest.mark.parametrize("kind", ["issuer", "namespace", "authority"])
def test_wrong_expected_instance_or_authority(authority, history, kind):
    from .relation_cases import parameters

    expected = authority.pp
    if kind == "issuer":
        expected = replace(expected, issuer_reference=parameters("beta").issuer_reference)
    elif kind == "namespace":
        expected = replace(expected, namespace=b"N" * 32)
    else:
        expected = replace(expected, revocation_public_key=parameters("beta").revocation_public_key)
    result = update_witness(expected, checkpoint(history), history.states[-1], history.records)
    assert_no_replacement(result)


@pytest.mark.parametrize("kind", ["missing", "duplicate", "reordered", "conflict"])
def test_history_order_and_endpoints(authority, history, kind):
    records = history.records
    if kind == "missing":
        records = records[:-1]
    elif kind == "duplicate":
        records = (records[0], records[0], records[2])
    elif kind == "reordered":
        records = (records[1], records[0], records[2])
    else:
        fork = authority.history([6, 8])
        records = (records[0], fork.records[1], records[2])
    result = run(authority, history, records=records)
    assert result.status is UpdateStatus.INVALID_HISTORY
    assert_no_replacement(result)


def test_repeated_revocation_and_unrevoke_transitions_fail(authority):
    already = authority.history([42])
    tree = already.trees[-1]
    old = already.states[-1]
    for root in (tree.root, already.trees[0].root):
        target = authority.signed_state(root, old.epoch + 1)
        record_bytes = authority.public_update(old, target, 42, tree.path(42))
        result = update_witness(authority.pp, checkpoint(already, at=-1), target, (record_bytes,))
        assert result.status is UpdateStatus.INVALID_HISTORY
        assert result.reason is UpdateReason.TRANSITION


@pytest.mark.parametrize(
    "kind",
    ["index-high", "short-path", "nested-path", "trailing", "tag", "field-count", "truncated"],
)
def test_malformed_transport_before_crypto(authority, history, kind, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("cryptography invoked before malformed transport admission")

    monkeypatch.setattr(mldsa, "_verify_diagnostic", forbidden)
    fields = list(decode_record(history.records[0], "rupdate"))
    if kind == "index-high":
        fields[2] = (2**20).to_bytes(4, "big")
    elif kind == "short-path":
        fields[3] = fields[3][:-1]
    elif kind == "nested-path":
        fields[3] = len(fields[3]).to_bytes(4, "big") + fields[3]
    encoded = encode_record("rupdate", tuple(fields))
    if kind == "trailing":
        encoded += b"x"
    elif kind == "tag":
        encoded = encoded[:4] + b"x" + encoded[5:]
    elif kind == "field-count":
        encoded = encoded[:11] + (4).to_bytes(4, "big") + encoded[15:]
    elif kind == "truncated":
        encoded = encoded[:-1]
    result = run(authority, history, records=(encoded,), target=history.states[1])
    assert result.status is UpdateStatus.INVALID_INPUT


def test_byte_record_admission_and_non_iterable_boundary(authority, history, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("cryptography invoked after resource admission failure")

    monkeypatch.setattr(mldsa, "_verify_diagnostic", forbidden)
    for records, limits in [
        (history.records, UpdateLimits(records=2)),
        (history.records, UpdateLimits(encoded_bytes=3 * UPDATE_RECORD_BYTES - 1)),
        ((history.records[0],) * 17, UpdateLimits()),
        ((bytes(MAX_UPDATE_BYTES + 1),), UpdateLimits()),
    ]:
        result = run(authority, history, records=records, limits=limits)
        assert result.status is UpdateStatus.RESOURCE_EXHAUSTED
        assert result.reason is UpdateReason.ADMISSION
    generator = (value for value in history.records)
    assert run(authority, history, records=generator).status is UpdateStatus.INVALID_INPUT
    assert next(generator) == history.records[0]
    for value in (-1, True, 17):
        with pytest.raises(EncodingError):
            UpdateLimits(records=value)


def test_maximum_admitted_batch_matches_independent_tree(authority):
    history = authority.history(list(range(16)), empty=True)
    result = run(authority, history, 2**20 - 1)
    assert result.status is UpdateStatus.UPDATED
    assert result.checkpoint.path == history.trees[-1].path(2**20 - 1)


def test_epoch_wrap_and_invalid_holder_index(authority, history):
    top = authority.signed_state(history.states[0].root, 2**64 - 1)
    bottom = authority.signed_state(history.states[1].root, 0)
    update = authority.public_update(top, bottom, 0, history.trees[0].path(0))
    result = run(
        authority,
        history,
        records=(update,),
        start=replace(checkpoint(history), state=top),
        target=bottom,
    )
    assert result.status is UpdateStatus.INVALID_HISTORY
    for identifier in (-1, True, 2**20):
        assert (
            run(
                authority, history, start=replace(checkpoint(history), identifier=identifier)
            ).status
            is UpdateStatus.INVALID_INPUT
        )


@pytest.mark.parametrize("kind", ["state-matrix", "update-challenge"])
def test_real_bounded_sampler_exhaustion_has_no_fallback_or_retry(
    authority, history, kind, monkeypatch
):
    real_reader = mldsa._shake_reader
    update = decode_update(authority.pp, history.records[0])
    streams = []

    def reader(bits, seed):
        matching = (
            (bits == 128 and seed[:32] == authority.pp.revocation_public_key[:32])
            if kind == "state-matrix"
            else (bits == 256 and seed == update.signature[:48])
        )
        if matching:
            stream = CountingReader(ntt_stream(87) if kind == "state-matrix" else ball_stream(200))
            streams.append(stream)
            return stream
        return real_reader(bits, seed)

    monkeypatch.setattr(mldsa, "_shake_reader", reader)
    result = run(authority, history)
    assert result.status is UpdateStatus.RESOURCE_EXHAUSTED
    assert result.reason is UpdateReason.SAMPLER
    assert len(streams) == 1
    assert streams[0].consumed == (1026 if kind == "state-matrix" else 256)
    assert_no_replacement(result)


@pytest.mark.parametrize(
    "error,expected",
    [
        (MemoryError, UpdateStatus.RESOURCE_EXHAUSTED),
        (RuntimeError, UpdateStatus.PROCESSING_FAILED),
    ],
)
def test_failure_mid_batch_exposes_no_partial_checkpoint(
    authority, history, monkeypatch, error, expected
):
    original = checkpoint(history)
    real = updater._ancestors
    calls = 0

    def fail_second(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise error("controlled fault")
        return real(*args)

    monkeypatch.setattr(updater, "_ancestors", fail_second)
    result = run(authority, history, start=original)
    assert result.status is expected and calls == 2
    assert_no_replacement(result)
    assert original == checkpoint(history)


@pytest.mark.parametrize("fault", ["private-path-failure", "corrupt-ancestor"])
def test_private_phase_failure_does_not_commit_and_checks_result(
    authority, history, monkeypatch, fault
):
    original = checkpoint(history)
    if fault == "private-path-failure":
        real = updater.path_root
        calls = 0

        def fail_after_one_private_step(*args):
            nonlocal calls
            calls += 1
            if calls == 6:  # Initial + three public paths + first and second private steps.
                raise RuntimeError("controlled private processing fault")
            return real(*args)

        monkeypatch.setattr(updater, "path_root", fail_after_one_private_step)
        expected = UpdateReason.RUNTIME
    else:
        real = updater._ancestors

        def corrupt_intermediate(*args):
            values = list(real(*args))
            values[5] = bytes(48)  # Holder 43 / update 0 diverge here; public root stays intact.
            return tuple(values)

        monkeypatch.setattr(updater, "_ancestors", corrupt_intermediate)
        expected = UpdateReason.RESULT_WITNESS
    result = run(authority, history, start=original)
    assert result.reason is expected
    assert_no_replacement(result)
    assert original == checkpoint(history)


def test_authenticated_revocation_not_reported_for_invalid_remaining_batch(authority):
    history = authority.history([43, 0])
    bad = history.records[-1][:-1] + bytes([history.records[-1][-1] ^ 1])
    result = run(authority, history, records=(history.records[0], bad))
    assert result.reason is UpdateReason.AUTHENTICATION
    assert result.status is not UpdateStatus.REVOKED
    assert_no_replacement(result)


@pytest.mark.parametrize("case", ["survivor", "revoked", "stale"])
def test_composition_with_full_local_auth_and_verifier_state(authority, case):
    history = authority.history([42])
    h = Harness(authority)
    rid = 42 if case == "revoked" else 43
    _, original, witness = auth_case(f"alpha-{rid}-old-002c")
    old = replace(original, parameters=h.pp, context=h.request.context, state=h.request.state)
    old_token, old_valid = h.relation_presentation(old, witness)
    assert old_valid
    before = encode_auth_witness(h.pp.schema, witness)
    updated = update_authentication_witness(
        h.pp, witness, history.states[0], history.states[-1], history.records
    )
    h.provider.current_state = history.states[-1]
    if case == "stale":
        assert h.verify(old_token).value == Decision.STATE.value
        return
    request = h.verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100)
    current = replace(original, parameters=h.pp, context=request.context, state=request.state)
    if case == "revoked":
        assert updated.status is UpdateStatus.REVOKED
        assert updated.witness is None and updated.state is None
        token, valid = h.relation_presentation(
            current, replace(witness, path=history.trees[-1].path(rid))
        )
        assert not valid
        assert h.verify(token, context=request.context) is Decision.PROOF
    else:
        assert updated.status is UpdateStatus.UPDATED
        assert updated.state == history.states[-1]
        assert encode_auth_witness(h.pp.schema, updated.witness)[:-960] == before[:-960]
        assert encode_auth_witness(h.pp.schema, witness) == before
        token, valid = h.relation_presentation(current, updated.witness)
        assert valid and h.verify(token, context=request.context).accepted
        assert encode_auth_statement(h.pp, current) == h.adapter.calls[-1][0]


def test_private_repr_and_no_diagnostic_output(authority, history, capsys):
    result = run(authority, history)
    assert history.trees[0].path(43).hex() not in repr(checkpoint(history))
    assert result.checkpoint.path.hex() not in repr(result)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
