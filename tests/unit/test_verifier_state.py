"""Reference-model tests, not real proof verification or PQ-DAA acceptance."""

import inspect
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.codec import EncodingError
from pqdid.policy import Policy, Range, make_policy
from pqdid.schema import decode_attributes, project_attributes
from pqdid.statements import encode_context
from pqdid.verifier_state import (
    REQUEST_CONTEXT,
    Decision,
    InMemoryChallengeStore,
    Presentation,
    ProofVerdict,
    ReferenceVerifier,
    Registration,
    UnsupportedProofVerifier,
    build_current_message,
)

from .binding_merkle_reference import record
from .relation_cases import auth_case, path
from .verifier_state_cases import Harness, TestAuthority, valid_resolution


@pytest.fixture(scope="module")
def authority():
    result = TestAuthority()
    yield result
    result.close()


@pytest.fixture
def h(authority):
    return Harness(authority)


def test_real_request_signature_exact_current_encoding_and_replay(h):
    ctx = h.request.context
    assert bounded_verify_mldsa65(
        h.verifier.request_public_key,
        encode_context(h.pp, ctx),
        h.request.signature,
        context=REQUEST_CONTEXT,
    )
    r = h.request.state
    independent = record(
        "current",
        h.pp.suite,
        h.authority.metadata,
        bytes(32),
        record("rstate", r.namespace, r.epoch.to_bytes(8, "big"), r.root, r.signature),
    )
    assert build_current_message(h.pp, bytes(32), r) == independent
    presentation, outcome = h.relation_presentation(h.statement, h.authority.witness)
    assert outcome and h.verify(presentation).accepted
    assert h.verify(presentation) is Decision.UNKNOWN
    assert h.store.pending(ctx.nonce) is None
    assert not h.provider.resolve_calls


def test_two_distinct_verifiers_and_invoking_session(authority):
    first, second = Harness(authority, 0), Harness(authority, 1)
    assert first.store is not second.store
    assert first.request.context.nonce == second.request.context.nonce
    presentation = first.model_presentation()
    assert second.verify(presentation, context=first.request.context) is Decision.MISMATCH
    assert first.verify(presentation, session=b"other-invoking-session") is Decision.MISMATCH
    assert first.verify(presentation).accepted
    assert second.verify().accepted


def test_simultaneous_submissions_accept_at_most_once(h):
    gate = Barrier(2, timeout=5)
    h.adapter.before_verdict = gate.wait
    presentation = h.model_presentation()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: h.verify(presentation), range(2)))
    assert sorted(result.value for result in results) == sorted(
        [Decision.ACCEPTED.value, Decision.CONSUMED.value]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("audience", b"other-audience"),
        ("session", b"other-session"),
        ("nonce", b"X" * 32),
        ("expires_at", 101),
        ("issuer_reference", b"other-issuer"),
        ("suite", b"other-suite"),
    ],
)
def test_altered_context_never_redefines_expected_statement(h, field, value):
    assert not h.verify(context=replace(h.request.context, **{field: value})).accepted
    assert not h.adapter.calls
    assert h.store.pending(h.request.context.nonce) is not None


@pytest.mark.parametrize("kind", ["policy", "root", "epoch", "namespace"])
def test_policy_and_state_context_mutations(h, kind):
    ctx = h.request.context
    if kind == "policy":
        changed = replace(
            ctx, policy=make_policy(h.pp.schema, ctx.policy.disclosed, (Range(4, 1, 5),))
        )
    else:
        field, value = {
            "root": ("root", bytes(48)),
            "epoch": ("epoch", 8),
            "namespace": ("namespace", b"N" * 32),
        }[kind]
        changed = replace(ctx, state_reference=replace(ctx.state_reference, **{field: value}))
    assert not h.verify(context=changed).accepted
    assert not h.adapter.calls
    assert h.verify().accepted


@pytest.mark.parametrize("kind", ["mask", "values", "proof", "mutable-proof", "empty", "oversize"])
def test_disclosure_and_opaque_proof_admission(h, kind):
    p = h.model_presentation()
    if kind == "mask":
        p = replace(p, disclosed=())
    elif kind == "values":
        values = bytearray(p.disclosed_attributes)
        values[12] = 4  # Canonical range value 4 rather than certified 3.
        p = replace(p, disclosed_attributes=bytes(values))
    else:
        p = replace(
            p,
            proof={
                "proof": b"altered",
                "mutable-proof": bytearray(p.proof),
                "empty": b"",
                "oversize": b"x" * 65,
            }[kind],
        )
        h.verifier.proof_byte_limit = 64
    assert not h.verify(p).accepted
    assert h.store.pending(h.request.context.nonce) is not None


@pytest.mark.parametrize(
    "verdict", [ProofVerdict.INVALID, ProofVerdict.UNSUPPORTED, True, 1, "valid"]
)
def test_only_exact_proof_verdict_is_accepted(h, verdict):
    h.adapter.override = verdict
    assert not h.verify().accepted
    assert h.store.pending(h.request.context.nonce) is not None
    h.adapter.override = None
    assert h.verify().accepted


def test_default_and_explicit_absent_backend_fail_closed(h):
    verifier = ReferenceVerifier(
        parameters=h.pp,
        audience=h.audience,
        request_public_key=h.verifier.request_public_key,
        clock=h.clock,
        store=h.store,
        provider=h.provider,
    )
    assert isinstance(verifier.proof_verifier, UnsupportedProofVerifier)
    assert (
        verifier.verify(
            session=h.session, context=h.request.context, presentation=h.model_presentation()
        )
        is Decision.UNSUPPORTED
    )
    assert verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100) is None
    assert h.store.pending(h.request.context.nonce) is not None


@pytest.mark.parametrize("source", ["proof", "current", "trust"])
def test_dependency_failure_does_not_consume(h, source):
    def fail(*args):
        raise RuntimeError("controlled unavailable dependency")

    if source == "proof":
        h.adapter.before_verdict = fail
    elif source == "current":
        h.provider.current = fail
    else:
        h.provider.instance = fail
    assert h.verify() is Decision.FAILURE
    assert h.store.pending(h.request.context.nonce) is not None


@pytest.mark.parametrize(
    "kind", ["unavailable", "malformed", "nonce", "signature", "state-signature", "role"]
)
def test_current_state_authentication_failures(h, kind):
    def damage(reply):
        if kind == "unavailable":
            return None
        if kind == "malformed":
            return (reply.state, reply.signature)
        if kind == "nonce":
            return replace(reply, nonce=b"Z" * 32)
        if kind == "signature":
            return replace(reply, signature=bytes(3309))
        if kind == "state-signature":
            bad_state = replace(reply.state, signature=bytes(3309))
            return h.authority.reply(reply.nonce, bad_state)
        return h.authority.reply(reply.nonce, reply.state, context=REQUEST_CONTEXT)

    h.provider.transform_reply = damage
    assert not h.verify().accepted
    assert h.store.pending(h.request.context.nonce) is not None


@pytest.mark.parametrize("kind", ["absent", "issuer-key", "manager-key", "namespace"])
def test_trusted_instance_cannot_be_replaced(h, kind):
    h.provider.instance_value = (
        None
        if kind == "absent"
        else replace(
            h.pp,
            **{
                "issuer-key": {"issuer_public_key": bytes(1952)},
                "manager-key": {"revocation_public_key": bytes(1952)},
                "namespace": {"namespace": b"Q" * 32},
            }[kind],
        )
    )
    assert h.verify() is Decision.TRUST
    assert not h.adapter.calls


def test_old_valid_witness_and_proof_result_rejected_after_state_superseded(h):
    p, valid = h.relation_presentation(h.statement, h.authority.witness)
    assert valid
    h.provider.current_state = h.authority.states["updated"]
    assert h.verify(p) is Decision.STATE
    assert h.store.pending(h.request.context.nonce) is not None


@pytest.mark.parametrize("rid,expected", [(42, False), (43, True)])
def test_current_root_revoked_and_surviving_same_witness(authority, rid, expected):
    h = Harness(authority)
    h.provider.current_state = authority.states["updated"]
    request = h.verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100)
    assert request is not None
    _, original, witness = auth_case(f"alpha-{rid}-old-002c")
    statement = replace(original, parameters=h.pp, context=request.context, state=request.state)
    witness = replace(witness, path=path(rid, "updated"))
    p, valid = h.relation_presentation(statement, witness)
    assert valid is expected
    assert h.verify(p, context=request.context).accepted is expected


@pytest.mark.parametrize(
    "event,expected",
    [
        ("state-during-proof", Decision.STATE),
        ("expiry-during-proof", Decision.EXPIRED),
        ("state-after-final-read", Decision.ACCEPTED),
        ("expiry-after-final-read", Decision.EXPIRED),
    ],
)
def test_deterministic_state_and_expiry_interleavings(h, event, expected):
    def advance():
        if event.startswith("state"):
            h.provider.current_state = h.authority.states["updated"]
        else:
            h.clock.value = 100

    if event.endswith("proof"):
        h.adapter.before_verdict = advance
    else:
        h.provider.after_read = advance
    assert h.verify() is expected
    assert (h.store.pending(h.request.context.nonce) is None) is expected.accepted


@pytest.mark.parametrize("now,expected", [(99, True), (100, False), (101, False)])
def test_strict_expiry_boundary(h, now, expected):
    h.clock.value = now
    assert h.verify().accepted is expected


def test_atomic_complete_record_recheck_and_session(h):
    original = h.store.pending(h.request.context.nonce)
    changed = replace(original, require_did_state=True)
    assert h.store.consume(changed, h.session, h.clock) is Decision.CONSUMED
    assert h.store.consume(original, b"wrong-session", h.clock) is Decision.MISMATCH
    assert h.store.pending(original.context.nonce) == original
    assert h.store.consume(original, h.session, h.clock).accepted


def test_creation_resamples_used_nonce_and_keeps_failed_signing_reservation(h):
    old = h.request.context.nonce
    sequence = iter([b"R" * 32, old, b"S" * 32])
    h.nonces.nonce = lambda: next(sequence)
    fresh = h.verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100)
    assert fresh.context.nonce == b"S" * 32
    h.nonces.nonce = lambda: b"F" * 32

    class BadSigner:
        def sign(self, message, context):
            return bytes(3309)

    h.verifier.signer = BadSigner()
    assert h.verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100) is None
    assert h.store.pending(b"F" * 32) is not None


def test_creation_capacity_expiry_collision_exhaustion_and_store_audience(h):
    h.store.capacity = 1
    assert h.verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100) is None
    h.store.capacity = 100
    h.clock.value = 100
    assert h.verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100) is None
    h.clock.value = 99
    h.nonces.nonce = lambda: h.request.context.nonce
    assert h.verifier.create_challenge(session=h.session, policy=h.policy, expires_at=100) is None
    stored = h.store.pending(h.request.context.nonce)
    assert h.store.register(stored, h.clock) is Registration.DUPLICATE
    with pytest.raises(EncodingError):
        InMemoryChallengeStore(b"other").register(stored, h.clock)


@pytest.mark.parametrize(
    "kind", ["hidden", "valid", "unauthenticated", "wrong-version", "wrong-document", "missing"]
)
def test_optional_DID_resolution_uses_only_certified_disclosed_inputs(authority, kind):
    if kind == "hidden":
        h = Harness(authority)
        assert (
            h.verifier.create_challenge(
                session=h.session, policy=h.policy, expires_at=100, require_did_state=True
            )
            is None
        )
        assert not h.provider.resolve_calls
        return
    policy = Policy((1, 2, 3, 4, 6), ())
    h = Harness(authority, did=True, policy=policy)
    witness = authority.witness
    h.statement = replace(
        h.statement,
        disclosed_attributes=project_attributes(h.pp.schema, witness.attributes, policy.disclosed),
    )
    values = decode_attributes(h.pp.schema, witness.attributes)
    result = valid_resolution(values[0], values[1])
    if kind == "unauthenticated":
        result = replace(result, authenticated=False)
    elif kind == "wrong-version":
        result = replace(result, version=b"V" * 56)
    elif kind == "wrong-document":
        result = replace(result, document=b'{"id":"other"}')
    h.provider.resolution = None if kind == "missing" else result
    p, valid = h.relation_presentation(h.statement, witness)
    assert valid
    assert h.verify(p).accepted is (kind == "valid")
    assert h.provider.resolve_calls == [(values[0], values[1])]


def test_resource_failure_propagates_without_consumption_and_public_only_API(h):
    def fail():
        raise MemoryError("synthetic allocation failure")

    h.adapter.before_verdict = fail
    with pytest.raises(MemoryError):
        h.verify()
    assert h.store.pending(h.request.context.nonce) is not None
    assert list(inspect.signature(ReferenceVerifier.verify).parameters) == [
        "self",
        "session",
        "context",
        "presentation",
    ]
    assert list(inspect.signature(h.adapter.verify).parameters) == ["statement", "proof"]
    assert list(Presentation.__dataclass_fields__) == ["disclosed", "disclosed_attributes", "proof"]
