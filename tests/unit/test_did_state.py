"""Reference lifecycle evidence, not proofs, production signing or W3C conformance."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from threading import Barrier, Event

import pytest

from pqdid import bounded_mldsa
from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.did_state import (
    MAX_READ_BYTES,
    MAX_RECORD_BYTES,
    READ_CONTEXT,
    RECORD_CONTEXT,
    DIDError,
    DIDLifecycleProvider,
    DIDLimits,
    DIDStatus,
    IssuanceDIDAdapter,
    ReferenceDIDController,
    ReferenceDIDRegistry,
    ReferenceDIDResolver,
    RegistryReply,
    decode_did_record,
    encode_body,
    encode_did_record,
)
from pqdid.issuance import HolderAcceptance, IssueStatus
from pqdid.policy import make_policy
from pqdid.revocation_state import SigningResult, SigningStatus
from pqdid.schema import project_attributes
from pqdid.verifier_state import Decision
from pqdid.witnesses import AuthenticationWitness

from .did_state_cases import DIDAuthority, DIDHarness
from .verifier_state_cases import Harness


@pytest.fixture(scope="module")
def authority():
    value = DIDAuthority()
    yield value
    value.close()


@pytest.fixture
def h(authority):
    return DIDHarness(authority)


def test_registration_exact_bytes_and_signed_absence(h):
    answer = h.resolver.resolve(h.pp, h.did)
    assert answer.status is DIDStatus.UNKNOWN and answer.document is None
    original = h.publish()
    assert len(h.did) == 171 and len(original.version) == 56
    encoded = encode_did_record(original)
    assert decode_did_record(encoded) == original
    body, sig = decode_record(encoded, "did-record")
    assert body == encode_body(original.body) and sig == original.signature
    assert bounded_mldsa.bounded_verify_mldsa65(
        h.authority.controller.public_key, body, sig, context=RECORD_CONTEXT
    )
    answer = h.resolver.resolve(h.pp, h.did)
    assert answer.status is DIDStatus.ACTIVE and answer.chain == (original,)
    assert answer.document.document == b'{"id":"' + h.did + b'"}'
    assert answer.document.media_type == "application/did+json"
    assert answer.document.version == original.version and answer.document.authenticated
    assert h.registry.append(encoded, None) is DIDStatus.CONFLICT
    assert h.registry.snapshot()[0][1] == (original,)
    assert all(context == READ_CONTEXT for _, context in h.signer.calls)


def test_rotation_deactivation_history_and_terminal_state(h):
    genesis = h.publish()
    assert h.rotate() is DIDStatus.CONFIRMED
    rotated = h.registry.snapshot()[0][1][-1]
    assert rotated.body.controller_key == h.authority.rotated.public_key
    assert bounded_mldsa.bounded_verify_mldsa65(
        h.authority.controller.public_key,
        encode_body(rotated.body),
        rotated.signature,
        context=RECORD_CONTEXT,
    )
    assert h.controller.publish((0, 0)) is DIDStatus.CONFIRMED
    answer = h.resolver.resolve(h.pp, h.did)
    assert answer.status is DIDStatus.DEACTIVATED and answer.document is None
    old = h.resolver.resolve(h.pp, h.did, b"\x01" + genesis.version)
    assert old.status is DIDStatus.ACTIVE and old.chain == (genesis,)
    assert h.controller.publish() is DIDStatus.DEACTIVATED
    inactive = answer.chain[-1]
    forged = h.record(inactive, signer=h.authority.rotated)
    assert h.registry.append(encode_did_record(forged), inactive.version) is DIDStatus.INCONSISTENT
    assert len(h.registry.snapshot()[0][1]) == 3


@pytest.mark.parametrize(
    "value,status",
    [
        (b"not-a-did", DIDStatus.INVALID),
        (b"did:other:123", DIDStatus.UNSUPPORTED),
        (b"did:pqdid:" + b"G" * 161, DIDStatus.INVALID),
        (b"x" * 172, DIDStatus.INVALID),
        (bytearray(171), DIDStatus.INVALID),
        (b"did:pqdid:" + b"ab" * 32 + b":" + b"ab" * 48, DIDStatus.MISMATCH),
    ],
)
def test_bad_identifier_never_reaches_transport(h, value, status):
    assert h.resolver.resolve(h.pp, value).status is status
    assert h.transport.reads == []


@pytest.mark.parametrize(
    "selector",
    [
        b"",
        b"\x02",
        b"\x00extra",
        b"\x01" + bytes(55),
        b"\x01" + (65536).to_bytes(8, "big") + bytes(48),
    ],
)
def test_unsupported_or_malformed_selector(h, selector):
    assert h.resolver.resolve(h.pp, h.did, selector).status in {
        DIDStatus.UNSUPPORTED,
        DIDStatus.INVALID,
    }
    assert h.transport.reads == []


@pytest.mark.parametrize(
    "field",
    ["namespace", "issuer_public_key", "revocation_public_key", "issuer_reference", "suite"],
)
def test_expected_instance_never_replaced(h, field):
    if field == "issuer_reference":
        issuer, kid, schema = decode_record(h.pp.issuer_reference, "iref")
        pp = replace(h.pp, issuer_reference=encode_record("iref", (issuer + b"x", kid, schema)))
    elif field == "suite":
        with pytest.raises(EncodingError):
            replace(h.pp, suite=b"different-suite")
        return
    else:
        value = getattr(h.pp, field)
        pp = replace(h.pp, **{field: bytes((value[0] ^ 1,)) + value[1:]})
    assert h.resolver.resolve(pp, h.did).status is DIDStatus.MISMATCH
    manager, _, _ = h.authority.manager_model()
    provider = DIDLifecycleProvider(h.resolver, manager)
    assert provider.instance(pp) is None and provider.current(pp, b"N" * 32) is None
    assert h.transport.reads == []


@pytest.mark.parametrize(
    "change",
    ["identity", "salt", "index", "predecessor", "registry", "signer", "deactivate-and-rotate"],
)
def test_invalid_successor_does_not_change_committed_state(h, change):
    first = h.publish()
    valid = h.record(first)
    body, signer = valid.body, h.authority.controller
    match change:
        case "identity":
            body = replace(body, did=h.record(salt=b"z" * 32).body.did)
        case "salt":
            body = replace(body, salt=b"z" * 32)
        case "index":
            body = replace(body, index=4)
        case "predecessor":
            body = replace(body, predecessor=bytes(48))
        case "registry":
            body = replace(body, registry_id=b"r" * 32)
        case "signer":
            signer = h.authority.rotated
        case "deactivate-and-rotate":
            body = replace(body, active=0, controller_key=h.authority.rotated.public_key)
    forged = h.signed(body, signer)
    before = h.registry.snapshot()
    assert h.registry.append(encode_did_record(forged), first.version) not in {
        DIDStatus.COMMITTED,
        DIDStatus.CONFIRMED,
    }
    assert h.registry.snapshot() == before


def test_substituted_genesis_key_and_signature_do_not_authorise(h):
    good = h.record()
    bad = h.signed(
        replace(good.body, controller_key=h.authority.rotated.public_key), h.authority.rotated
    )
    assert h.registry.append(encode_did_record(bad), None) is DIDStatus.INCONSISTENT
    bad = h.signed(good.body, h.authority.rotated)
    assert h.registry.append(encode_did_record(bad), None) is DIDStatus.UNAUTHORISED
    assert h.registry.snapshot() == ()


@pytest.mark.parametrize("field", [0, 1, 2, 3, 4, 5])
def test_authenticated_but_inconsistent_read_fields(h, field):
    h.publish()

    def change(reply):
        values = list(decode_record(reply.message, "did-read"))
        values[field] = (
            encode_record("did-chain", ()) if field == 5 else (b"\x01" if field == 4 else b"wrong")
        )
        return h.reply(encode_record("did-read", values))

    h.transport.transform = change
    assert h.resolver.resolve(h.pp, h.did).status is DIDStatus.INCONSISTENT


def test_full_chain_validated_and_historical_endpoint_must_match(h):
    first = h.publish()
    assert h.rotate() is DIDStatus.CONFIRMED
    latest = h.registry.snapshot()[0][1][-1]

    def change(reply):
        values = list(decode_record(reply.message, "did-read"))
        # Valid outer signature cannot make this wrong predecessor/endpoint valid.
        values[5] = encode_record("did-chain", (encode_did_record(latest),))
        return h.reply(encode_record("did-read", values))

    h.transport.transform = change
    assert h.resolver.resolve(h.pp, h.did).status is DIDStatus.INCONSISTENT
    h.transport.transform = lambda r: r
    wrong_digest = first.version[:8] + bytes(48)
    assert h.resolver.resolve(h.pp, h.did, b"\x01" + wrong_digest).status is DIDStatus.UNKNOWN


def test_wrong_registry_key_stale_nonce_and_unsigned_answer(h):
    h.publish()
    cached = h.registry.read(h.did, b"\x00", b"old" + bytes(29))
    h.transport.transform = lambda _: cached
    assert h.resolver.resolve(h.pp, h.did).status is DIDStatus.INCONSISTENT
    h.transport.transform = lambda r: RegistryReply(r.message, bytes(3309))
    assert h.resolver.resolve(h.pp, h.did).status is DIDStatus.INCONSISTENT
    h.transport.transform = lambda r: r
    wrong = ReferenceDIDResolver(
        replace(h.config, registry_public_key=h.authority.rotated.public_key), h.transport
    )
    assert wrong.resolve(h.pp, h.did).status is DIDStatus.INCONSISTENT


def test_snapshots_are_immutable_and_do_not_alias_mutable_state(h):
    h.publish()
    before = h.registry.snapshot()
    resolved = h.resolver.resolve(h.pp, h.did)
    with pytest.raises(FrozenInstanceError):
        resolved.chain[0].body.active = 0
    with pytest.raises(TypeError):
        before[0][1][0] = None
    with pytest.raises(FrozenInstanceError):
        resolved.document.version = bytes(56)
    assert h.rotate() is DIDStatus.CONFIRMED
    assert len(before[0][1]) == 1 and len(h.registry.snapshot()[0][1]) == 2


def test_concurrent_authorised_successors_have_one_atomic_winner(h, monkeypatch):
    first = h.publish()
    left = h.record(first)
    right = h.record(first, key=h.authority.rotated.public_key)
    import pqdid.did_state as module

    barrier, original = Barrier(2), module._transition

    def together(*args):
        original(*args)
        barrier.wait(timeout=3)

    monkeypatch.setattr(module, "_transition", together)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(h.registry.append, encode_did_record(r), first.version)
            for r in (left, right)
        ]
        results = [f.result(timeout=5) for f in futures]
    assert results.count(DIDStatus.COMMITTED) == 1 and results.count(DIDStatus.CONFLICT) == 1
    assert h.registry.snapshot()[0][1] in ((first, left), (first, right))


def test_read_linearises_before_overlapping_write_and_no_cache(h):
    first = h.publish()
    second = h.record(first)

    def commit(_message, _context):
        h.signer.hook = None
        assert h.registry.append(encode_did_record(second), first.version) is DIDStatus.COMMITTED

    h.signer.hook = commit
    overlap = h.resolver.resolve(h.pp, h.did)
    later = h.resolver.resolve(h.pp, h.did)
    assert overlap.chain == (first,) and later.chain == (first, second)
    assert h.transport.reads[-1][2] != h.transport.reads[-2][2]


@pytest.mark.parametrize(
    "failure,status",
    [
        (SigningResult(SigningStatus.UNSUPPORTED), DIDStatus.UNSUPPORTED),
        (SigningResult(SigningStatus.EXHAUSTED), DIDStatus.EXHAUSTED),
        (SigningResult(SigningStatus.FAILED), DIDStatus.UNAVAILABLE),
        (True, DIDStatus.UNAVAILABLE),
        (SigningResult(SigningStatus.SIGNED, bytes(3309)), DIDStatus.UNAUTHORISED),
    ],
)
def test_signing_failures_no_success(h, failure, status):
    h.signer.hook = lambda *_: failure
    assert h.resolver.resolve(h.pp, h.did).status is status
    assert h.registry.snapshot() == () and h.controller.publish() is status


@pytest.mark.parametrize(
    "failure,status",
    [(OSError("controlled"), DIDStatus.UNAVAILABLE), (MemoryError(), DIDStatus.EXHAUSTED)],
)
def test_transport_failure_and_resource_propagation(h, monkeypatch, failure, status):
    def fail(*_):
        raise failure

    monkeypatch.setattr(h.transport, "read", fail)
    assert h.resolver.resolve(h.pp, h.did).status is status
    if status is DIDStatus.EXHAUSTED:
        with pytest.raises(MemoryError):
            IssuanceDIDAdapter(h.resolver).current(h.pp, h.did)
    else:
        assert IssuanceDIDAdapter(h.resolver).current(h.pp, h.did) is None


def test_sampler_exhaustion_uses_existing_bounded_expansion(h, monkeypatch):
    record = h.record()

    def exhausted(_):
        raise bounded_mldsa._SamplerExhausted("RejNTTPoly", 1026)

    monkeypatch.setattr(bounded_mldsa, "_expand_a", exhausted)
    assert h.registry.append(encode_did_record(record), None) is DIDStatus.EXHAUSTED
    assert h.registry.snapshot() == ()
    assert h.resolver.resolve(h.pp, h.did).status is DIDStatus.EXHAUSTED


def test_store_nonce_and_byte_limits_fail_closed(authority):
    h = DIDHarness(authority, limits=DIDLimits(records=1))
    first = h.publish()
    assert (
        h.registry.append(encode_did_record(h.record(first)), first.version) is DIDStatus.EXHAUSTED
    )
    assert h.registry.snapshot()[0][1] == (first,)
    other = h.record(salt=b"other" + bytes(27))
    assert h.registry.append(encode_did_record(other), None) is DIDStatus.EXHAUSTED
    assert h.registry.append(bytes(MAX_RECORD_BYTES + 1), None) is DIDStatus.EXHAUSTED
    h.transport.transform = lambda _: RegistryReply(bytes(MAX_READ_BYTES + 1), bytes(3309))
    assert h.resolver.resolve(h.pp, h.did).status is DIDStatus.EXHAUSTED
    resolver = ReferenceDIDResolver(h.config, h.registry, limits=DIDLimits(reads=1))
    assert resolver.resolve(h.pp, h.did).status is DIDStatus.ACTIVE
    assert resolver.resolve(h.pp, h.did).status is DIDStatus.EXHAUSTED


def test_chain_count_admission_before_decoding(h):
    def excessive(reply):
        values = list(decode_record(reply.message, "did-read"))
        values[4] = b"\x00"
        values[5] = (9).to_bytes(4, "big") + b"did-chain" + (33).to_bytes(4, "big")
        return h.reply(encode_record("did-read", values))

    h.transport.transform = excessive
    assert h.resolver.resolve(h.pp, h.did).status is DIDStatus.EXHAUSTED


def test_nonce_reuse_bounded_draws_and_missing_signer(h):
    class Repeated:
        def __init__(self):
            self.calls = 0

        def nonce(self):
            self.calls += 1
            return bytes(32)

    source = Repeated()
    resolver = ReferenceDIDResolver(
        h.config, h.registry, nonces=source, limits=DIDLimits(nonce_draws=2)
    )
    assert resolver.resolve(h.pp, h.did).status is DIDStatus.UNKNOWN
    assert resolver.resolve(h.pp, h.did).status is DIDStatus.EXHAUSTED and source.calls == 3
    registry = ReferenceDIDRegistry(h.config)
    with pytest.raises(DIDError) as caught:
        registry.read(h.did, b"\x00", bytes(32))
    assert caught.value.status is DIDStatus.UNSUPPORTED
    controller = ReferenceDIDController(h.resolver, h.authority.controller.public_key, b"s" * 32)
    assert controller.publish() is DIDStatus.UNSUPPORTED and controller.snapshot().pending is None


def test_busy_admission_and_controller_operation_serialisation(h, monkeypatch):
    enter, release = Event(), Event()
    original = h.transport.read

    def hold(*args):
        enter.set()
        assert release.wait(timeout=3)
        return original(*args)

    monkeypatch.setattr(h.transport, "read", hold)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(h.controller.publish)
        assert enter.wait(timeout=3)
        assert h.controller.publish() is DIDStatus.BUSY
        release.set()
        assert future.result(timeout=5) is DIDStatus.CONFIRMED
    assert h.registry._slots.acquire(False) and h.registry._slots.acquire(False)
    try:
        assert h.registry.append(b"", None) is DIDStatus.BUSY
        with pytest.raises(DIDError) as caught:
            h.registry.read(h.did, b"\x00", bytes(32))
        assert caught.value.status is DIDStatus.BUSY
    finally:
        h.registry._slots.release()
        h.registry._slots.release()


@pytest.mark.parametrize("metadata", [(0, 1), (2, 0), (True, 0), [1, 0]])
def test_unsupported_metadata_never_submits(h, metadata):
    assert h.controller.publish(metadata) is DIDStatus.UNSUPPORTED
    assert h.transport.writes == [] and h.transport.reads == []


def test_reply_loss_recovery_keeps_committed_rotation_and_keys(h, monkeypatch):
    h.publish()
    original = h.transport.append

    def lose(*args):
        assert original(*args) is DIDStatus.COMMITTED
        raise OSError("controlled lost reply after commit")

    monkeypatch.setattr(h.transport, "append", lose)
    assert h.rotate() is DIDStatus.UNAVAILABLE
    pending = h.controller.snapshot().pending
    assert pending is not None and len(h.registry.snapshot()[0][1]) == 2
    assert h.controller.publish() is DIDStatus.CONFLICT
    monkeypatch.setattr(h.transport, "append", original)
    assert h.controller.recover() is DIDStatus.CONFIRMED
    assert len(h.transport.writes) == 2  # Recovery confirmed, did not resend.
    assert h.controller.snapshot().public_key == h.authority.rotated.public_key
    assert h.controller.publish((0, 0)) is DIDStatus.CONFIRMED


def test_pending_resends_identical_bytes_only_while_predecessor_current(h, monkeypatch):
    original = h.transport.append
    captured = []

    def lost_before(*args):
        captured.append(args)
        raise TimeoutError("controlled loss before commit")

    monkeypatch.setattr(h.transport, "append", lost_before)
    assert h.controller.publish() is DIDStatus.UNAVAILABLE
    monkeypatch.setattr(h.transport, "append", original)
    assert h.controller.recover() is DIDStatus.CONFIRMED
    assert h.transport.writes == captured


def test_pending_conflict_retires_attempt_without_adopting_other_key(h, monkeypatch):
    first = h.publish()
    original = h.transport.append
    monkeypatch.setattr(h.transport, "append", lambda *_: DIDStatus.UNAVAILABLE)
    assert h.rotate() is DIDStatus.UNAVAILABLE
    competing = h.record(first)
    assert h.registry.append(encode_did_record(competing), first.version) is DIDStatus.COMMITTED
    monkeypatch.setattr(h.transport, "append", original)
    assert h.controller.recover() is DIDStatus.CONFLICT
    state = h.controller.snapshot()
    assert state.pending is None and state.public_key == first.body.controller_key
    assert state.version == first.version and h.controller.publish() is DIDStatus.CONFLICT


def test_pending_confirmation_after_later_deactivation(h, monkeypatch):
    first = h.publish()
    original = h.transport.append

    def commit_then_deactivate(encoded, expected):
        assert original(encoded, expected) is DIDStatus.COMMITTED
        rotated = decode_did_record(encoded)
        inactive = h.record(
            rotated, active=0, key=h.authority.rotated.public_key, signer=h.authority.rotated
        )
        assert (
            h.registry.append(encode_did_record(inactive), rotated.version) is DIDStatus.COMMITTED
        )
        raise TimeoutError()

    monkeypatch.setattr(h.transport, "append", commit_then_deactivate)
    assert h.rotate() is DIDStatus.UNAVAILABLE
    assert h.controller.snapshot().version == first.version
    assert h.controller.recover() is DIDStatus.CONFIRMED
    assert h.controller.snapshot().version[:8] == (1).to_bytes(8, "big")
    assert h.controller.publish() is DIDStatus.DEACTIVATED


@pytest.mark.parametrize("operation", ["rotate", "deactivate"])
def test_pending_issuance_fails_when_current_controller_state_changes(h, operation):
    issue, _ = h.issuance()
    challenge, submission = issue.pending()
    assert challenge.approved_attributes == issue.attributes
    assert (
        h.rotate() if operation == "rotate" else h.controller.publish((0, 0))
    ) is DIDStatus.CONFIRMED
    assert issue.issuer.finish(issue.request.session, submission).status is IssueStatus.UNAUTHORISED
    assert issue.issuer.snapshot().certifications == ()


@pytest.mark.parametrize("disclose", [False, True])
def test_issuance_two_independent_verifiers_and_hidden_did_boundary(h, disclose):
    issue, provider = h.issuance()
    _, submission, issued = issue.issue()
    wallet = HolderAcceptance(h.pp, issue.secret, issue.attributes, submission.statement)
    assert wallet.accept(issued).status is IssueStatus.ACCEPTED
    witness = AuthenticationWitness(
        issue.secret,
        issue.attributes,
        42,
        issued.credential.certificate.signature,
        issued.checkpoint.path,
    )
    assert h.rotate() is DIDStatus.CONFIRMED
    assert h.controller.publish((0, 0)) is DIDStatus.CONFIRMED
    current_epoch = issue.manager.snapshot().state.epoch
    assert current_epoch == 0  # DID rotation/deactivation did not revoke credentials.
    indices = (h.pp.schema.did_index, h.pp.schema.version_index) if disclose else (3,)
    policy = make_policy(h.pp.schema, tuple(sorted(indices)), ())
    h.transport.reads.clear()
    for index in range(2):
        harness = Harness(h.authority, index=index, policy=policy)
        harness.verifier.provider = provider
        harness.request = harness.verifier.create_challenge(
            session=b"new-session",
            policy=policy,
            expires_at=100,
            require_did_state=disclose,
        )
        assert harness.request is not None
        harness.session = b"new-session"
        statement = replace(
            harness.statement,
            state=harness.request.state,
            context=harness.request.context,
            disclosed=policy.disclosed,
            disclosed_attributes=project_attributes(
                h.pp.schema, issue.attributes, policy.disclosed
            ),
        )
        presentation, ok = harness.relation_presentation(statement, witness)
        assert ok and harness.verify(presentation) is Decision.ACCEPTED
    if disclose:
        assert len(h.transport.reads) == 2
        assert all(
            did == h.did and selector == b"\x01" + issue.request.version
            for did, selector, _ in h.transport.reads
        )
    else:
        assert h.transport.reads == []  # No hidden DID lookup or current-control proof.
    assert wallet.snapshot().credential == issued.credential


def test_lifecycle_provider_cannot_substitute_authority_parameters(h):
    class Substitute:
        def instance(self, expected):
            return replace(expected, issuer_public_key=h.authority.rotated.public_key)

        def current(self, *_):
            pytest.fail("substituted parameters must be rejected before current read")

    provider = DIDLifecycleProvider(h.resolver, Substitute())
    assert provider.instance(h.pp) is None and provider.current(h.pp, bytes(32)) is None
    assert h.transport.reads == []


@pytest.mark.parametrize("ack", [True, DIDStatus.CONFIRMED, DIDStatus.COMMITTED])
def test_acknowledgement_without_authenticated_occurrence_never_succeeds(h, monkeypatch, ack):
    monkeypatch.setattr(h.transport, "append", lambda *_: ack)
    assert h.controller.publish() is DIDStatus.UNAVAILABLE
    assert h.controller.snapshot().version is None and h.controller.snapshot().pending is not None
    assert h.registry.snapshot() == ()


@pytest.mark.parametrize("encoded", [b"", b"not-a-record", bytearray(64)])
def test_malformed_record_rejected_before_commit(h, encoded):
    assert h.registry.append(encoded, None) is DIDStatus.INVALID
    assert h.registry.snapshot() == ()


def test_complete_maximum_retained_history_and_lower_resolver_admission(h):
    previous = None
    for _ in range(32):
        record = h.record(previous)
        assert (
            h.registry.append(encode_did_record(record), previous.version if previous else None)
            is DIDStatus.COMMITTED
        )
        previous = record
    answer = h.resolver.resolve(h.pp, h.did)
    assert answer.status is DIDStatus.ACTIVE and len(answer.chain) == 32
    assert tuple(r.body.index for r in answer.chain) == tuple(range(32))
    extra = h.record(previous)
    assert h.registry.append(encode_did_record(extra), previous.version) is DIDStatus.EXHAUSTED
    restricted = ReferenceDIDResolver(h.config, h.registry, limits=DIDLimits(records=31))
    assert restricted.resolve(h.pp, h.did).status is DIDStatus.EXHAUSTED


def test_registry_failure_does_not_leak_private_inputs_or_make_current_claim(h, monkeypatch):
    issue, provider = h.issuance()
    # No private value is an argument to this transport: only DID, selector and nonce.
    private = issue.secret
    assert all(private not in part for call in h.transport.reads for part in call)
    assert private not in repr(h.controller.snapshot()).encode()
    assert private not in repr(h.registry.snapshot()).encode()
    assert not hasattr(h.registry, "holder_secret")
    old = issue.request.version
    assert h.rotate() is DIDStatus.CONFIRMED
    assert provider.resolve_did(h.did, old).version == old
    assert IssuanceDIDAdapter(h.resolver).current(h.pp, h.did).resolution.version != old
    assert issue.begin().status is IssueStatus.UNAUTHORISED  # Stale approval cannot migrate.


def test_historical_selector_cannot_receive_current_chain(h):
    first = h.publish()
    assert h.rotate() is DIDStatus.CONFIRMED
    full = encode_record(
        "did-chain", tuple(encode_did_record(r) for r in h.registry.snapshot()[0][1])
    )

    def substitute(reply):
        values = list(decode_record(reply.message, "did-read"))
        values[5] = full
        return h.reply(encode_record("did-read", values))

    h.transport.transform = substitute
    assert h.resolver.resolve(h.pp, h.did, b"\x01" + first.version).status is DIDStatus.INCONSISTENT


@pytest.mark.parametrize("limit", [0, 33, True])
def test_invalid_local_limits_do_not_activate(limit):
    with pytest.raises(EncodingError):
        DIDLimits(records=limit)
