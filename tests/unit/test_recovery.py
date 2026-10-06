"""Guarded deterministic admission policy tests, not real crash/restart protection."""

from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace

import pytest

from pqdid import recovery
from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.did_state import DIDStatus, encode_did_record
from pqdid.issuance import IssueStatus, SessionPhase
from pqdid.recovery import Admission, Dependencies, KeyHandle, RecoveryUnavailable
from pqdid.recovery_records import RecoveryLimits, Role, checkpoint_digest
from pqdid.revocation_state import ManagerStatus
from pqdid.verifier_state import Decision

from .did_state_cases import DIDAuthority
from .lifecycle_review_cases import LifecycleHarness
from .recovery_cases import (
    KEY,
    NEXT_KEY,
    FixtureRecoveryAuthority,
    binding,
    gate,
    issuer_checkpoint,
    manager_checkpoint,
    role_case,
    verifier_checkpoint,
    verifier_deps,
)
from .revocation_state_cases import RecordingSigner


@pytest.fixture(scope="module")
def authority():
    value = DIDAuthority()
    yield value
    value.close()


@pytest.fixture
def h(authority):
    return LifecycleHarness(authority)


def denied(service, method="snapshot", *args, **kwargs):
    with pytest.raises(RecoveryUnavailable, match="recovered operation unavailable"):
        getattr(service, method)(*args, **kwargs)


def test_stale_allocation_cannot_resume_even_with_same_authentic_root(h):
    stale = manager_checkpoint(h)
    h.certify()
    current = manager_checkpoint(h)
    assert stale.state.state == current.state.state
    oracle = FixtureRecoveryAuthority(current)
    service = gate(h.pp, stale, Dependencies(signer=h.issue.manager._signer), oracle)
    denied(service, "current", h.pp, b"n" * 32)
    assert service.admit(stale) is Admission.REJECTED
    denied(service, "reserve_identifier", h.issue.manager.snapshot().state.reference)
    denied(service, "instance", h.pp)
    assert h.issue.manager.snapshot().allocated_count == 43
    recovered = gate(h.pp, current, Dependencies(signer=h.issue.manager._signer), oracle)
    assert recovered.admit(current) is Admission.ADMITTED
    result = recovered.reserve_identifier(h.issue.manager.snapshot().state.reference)
    assert result.status is ManagerStatus.ALLOCATED and result.identifier == 43


def test_lost_consumption_never_reaccepts_through_recovered_interfaces(h):
    h.certify()
    v, presentation, valid = h.presentation()
    assert valid
    stale = verifier_checkpoint(v)
    assert v.verify(presentation) is Decision.ACCEPTED
    current = verifier_checkpoint(v)
    oracle = FixtureRecoveryAuthority(current)
    bad = gate(h.pp, stale, verifier_deps(v), oracle)
    assert bad.admit(stale) is Admission.REJECTED
    denied(bad, "verify", session=v.session, context=v.request.context, presentation=presentation)
    denied(bad, "create_challenge", session=v.session, policy=v.policy, expires_at=100)
    good = gate(h.pp, current, verifier_deps(v), oracle)
    assert good.admit(current) is Admission.ADMITTED
    assert (
        good.verify(session=v.session, context=v.request.context, presentation=presentation)
        is Decision.UNKNOWN
    )
    # Fresh challenge succeeds independently; old records were NOT discarded.
    fresh = good.create_challenge(session=b"new-session", policy=v.policy, expires_at=101)
    assert fresh is not None and fresh.context.nonce != v.request.context.nonce
    statement = replace(v.statement, context=fresh.context, state=fresh.state)
    fresh_presentation, valid = v.relation_presentation(statement, h.witness)
    assert (
        valid
        and good.verify(
            session=b"new-session", context=fresh.context, presentation=fresh_presentation
        )
        is Decision.ACCEPTED
    )


@pytest.mark.parametrize(
    "evidence", ["missing", "untrusted", "different-binding", "already-granted"]
)
def test_missing_untrusted_or_unavailable_evidence_fails_closed(h, evidence):
    record = manager_checkpoint(h)
    oracle = None if evidence == "missing" else FixtureRecoveryAuthority(record)
    if evidence == "untrusted":
        oracle.authority_id = b"U" * 32
    elif evidence == "different-binding":
        oracle.latest = replace(oracle.latest, checkpoint_digest=b"0" * 32)
    elif evidence == "already-granted":
        oracle.granted = True
    service = gate(h.pp, record, authority=oracle)
    assert service.admit(record) is Admission.REJECTED
    denied(service)


@pytest.mark.parametrize(
    "damage",
    [
        "namespace",
        "instance",
        "role",
        "suite",
        "parameters",
        "version",
        "missing",
        "mutable",
        "corrupt",
        "counter",
        "unordered",
        "oversized",
        "work",
        "records",
        "nodes",
    ],
)
def test_preflight_and_invalid_checkpoint_never_partially_admit(h, damage, monkeypatch):
    record = manager_checkpoint(h)
    oracle = FixtureRecoveryAuthority(record)
    candidate, limits = record, RecoveryLimits()
    if damage in {"namespace", "suite", "parameters"}:
        values = list(decode_record(record.parameters, "parameters"))
        index = {"namespace": 2, "suite": 0, "parameters": 3}[damage]
        values[index] = b"X" * len(values[index])
        candidate = replace(record, parameters=encode_record("parameters", tuple(values)))
    elif damage == "instance":
        candidate = replace(record, service_id=b"I" * 32)
    elif damage == "role":
        candidate = replace(record, role=Role.ISSUER)
    elif damage == "version":
        candidate = replace(record, version=2)
    elif damage == "missing":
        candidate = replace(record, state=None)
    elif damage == "mutable":
        candidate = replace(record, state=replace(record.state, revoked=[]))
    elif damage == "corrupt":
        candidate = replace(record, state=replace(record.state, state=record.state.state[:-1]))
    elif damage == "counter":
        candidate = replace(record, state=replace(record.state, allocated_count=(1 << 20) + 1))
    elif damage == "unordered":
        candidate = replace(
            record, state=replace(record.state, consumed_nonces=(b"b" * 32, b"a" * 32))
        )
    elif damage == "oversized":
        candidate = replace(record, parameters=b"x" * 65537)
    elif damage == "work":
        limits = replace(limits, work=1)
    elif damage == "records":
        limits = replace(limits, records=1)
    else:
        limits = replace(limits, nodes=1)
    if damage in {"oversized", "work", "records", "nodes"}:

        def expensive_forbidden(*args, **kwargs):
            pytest.fail("expensive work before recovery admission bounds")

        monkeypatch.setattr(recovery.rev, "ReferenceRevocationManager", expensive_forbidden)
    service = gate(h.pp, record, authority=oracle, limits=limits)
    assert service.admit(candidate) is Admission.REJECTED
    denied(service)
    assert service._service is None
    assert not oracle.granted
    # A rejected facade cannot be silently overwritten or retried with current data.
    with pytest.raises(RecoveryUnavailable):
        service.admit(record)


@pytest.mark.parametrize(
    "role", [Role.MANAGER, Role.ISSUER, Role.REGISTRY, Role.RESOLVER, Role.CONTROLLER, Role.HOLDER]
)
def test_current_complete_role_admission_and_real_operations(h, role):
    h.certify()
    record, deps = role_case(h, role)
    oracle = FixtureRecoveryAuthority(record)
    service = gate(h.pp, record, deps, oracle)
    assert service.admission is Admission.QUARANTINED
    assert service.admit(record) is Admission.ADMITTED and oracle.granted
    if role is Role.MANAGER:
        assert service.snapshot() == h.issue.manager.snapshot()
        assert service.read_current(b"n" * 32).status is ManagerStatus.CURRENT
    elif role is Role.ISSUER:
        assert service.snapshot() == h.issue.issuer.snapshot()
        assert service.finish(h.issue.request.session, h.submission).status is IssueStatus.REPLAY
        assert service.begin(h.issue.request, h.challenge.state).status is IssueStatus.REPLAY
    elif role is Role.REGISTRY:
        assert service.snapshot() == h.did.registry.snapshot()
        assert service.read(h.did.did, b"\x00", b"n" * 32) is not None
    elif role is Role.RESOLVER:
        assert service.resolve(h.pp, h.did.did).status is DIDStatus.ACTIVE
    elif role is Role.CONTROLLER:
        assert service.snapshot() == h.did.controller.snapshot()
        assert service.publish((0, 0)) is DIDStatus.CONFIRMED
    else:
        assert service.snapshot() == h.issued and service.checkpoint() == h.issued.checkpoint
        assert service.accept(h.issued).status is IssueStatus.REPLAY
    with pytest.raises(RecoveryUnavailable):
        service.admit(record)
    assert service.admission is Admission.ADMITTED
    with pytest.raises(FrozenInstanceError):
        record.version = 2
    assert "secret" not in repr(record) and not hasattr(service, "store")


def test_current_verifier_with_expired_challenge_uses_live_clock(h):
    h.certify()
    v, presentation, valid = h.presentation()
    assert valid
    record = verifier_checkpoint(v)
    v.clock.value = v.request.context.expires_at
    service = gate(h.pp, record, verifier_deps(v), FixtureRecoveryAuthority(record))
    assert service.admit(record) is Admission.ADMITTED
    assert (
        service.verify(session=v.session, context=v.request.context, presentation=presentation)
        is Decision.EXPIRED
    )


@pytest.mark.parametrize("event", ["advanced", "memory", "io", "lease-exit"])
def test_authority_advances_or_fails_during_admission_no_state_escapes(h, event):
    record = manager_checkpoint(h)
    oracle = FixtureRecoveryAuthority(record)
    service = gate(h.pp, record, authority=oracle)

    def observe():
        assert service.admission is Admission.VALIDATING
        denied(service)
        denied(service, "current", h.pp, b"n" * 32)
        if event == "advanced":
            h.issue.manager.reserve_identifier(h.issue.manager.snapshot().state.reference)
            oracle.latest = binding(manager_checkpoint(h))
        elif event == "memory":
            raise MemoryError("TEST-ONLY")
        elif event == "io":
            raise OSError("TEST-ONLY")

    oracle.before = observe
    if event == "lease-exit":
        oracle.exit_error = OSError
    assert service.admit(record) is Admission.REJECTED
    assert service._service is None
    denied(service)


def test_full_manager_history_and_witness_pairs_restored(h):
    h.certify()
    base = h.issue.manager.snapshot()
    h.revoke()
    record = manager_checkpoint(h, base)
    service = gate(
        h.pp, record, Dependencies(signer=h.issue.manager._signer), FixtureRecoveryAuthority(record)
    )
    assert service.admit(record) is Admission.ADMITTED
    assert service.snapshot() == h.issue.manager.snapshot()
    page = service.updates(h.pp.namespace, 0, 1)
    assert page.status is ManagerStatus.PAGE and page.page.records == record.state.history
    assert (
        service.registered_witness(42, service.snapshot().state.reference).status
        is ManagerStatus.WITNESS
    )


@pytest.mark.parametrize("damage", ["history", "revoked", "nonces", "base"])
def test_manager_missing_or_inconsistent_records_rejected_even_by_favourable_oracle(h, damage):
    h.certify()
    base = h.issue.manager.snapshot()
    h.revoke()
    record = manager_checkpoint(h, base)
    edits = {
        "history": {"history": ()},
        "revoked": {"revoked": ()},
        "nonces": {"consumed_nonces": ()},
        "base": {"base_revoked": (41,)},
    }
    record = replace(record, state=replace(record.state, **edits[damage]))
    service = gate(h.pp, record, authority=FixtureRecoveryAuthority(record))
    assert service.admit(record) is Admission.REJECTED
    denied(service)


@pytest.mark.parametrize(
    "damage",
    [
        "missing-certification",
        "missing-nonce",
        "reservation",
        "pending-data",
        "claimed",
        "preparing",
    ],
)
def test_issuer_incomplete_or_interrupted_checkpoint_quarantined(h, damage):
    h.certify()
    record, deps = role_case(h, Role.ISSUER)
    row = record.state.sessions[0]
    if damage == "missing-certification":
        state = replace(record.state, certifications=())
    elif damage == "missing-nonce":
        state = replace(record.state, used_nonces=())
    elif damage == "reservation":
        state = replace(record.state, allocated_floor=42)
    else:
        row = (
            replace(row, challenge=None)
            if damage == "pending-data"
            else replace(
                row, phase=SessionPhase.CLAIMED if damage == "claimed" else SessionPhase.PREPARING
            )
        )
        state = replace(record.state, sessions=(row,))
    record = replace(record, state=state)
    service = gate(h.pp, record, deps, FixtureRecoveryAuthority(record))
    assert service.admit(record) is Admission.REJECTED
    denied(service, "finish", h.issue.request.session, h.submission)
    assert len(h.issue.issuer.snapshot().certifications) == 1


def test_complete_pending_issuer_can_finish_after_admission(h):
    challenge, submission = h.issue.pending()
    record = issuer_checkpoint(h)
    _, deps = role_case(h, Role.ISSUER)
    service = gate(h.pp, record, deps, FixtureRecoveryAuthority(record))
    assert service.admit(record) is Admission.ADMITTED
    result = service.finish(h.issue.request.session, submission)
    assert result.status is IssueStatus.CERTIFIED
    assert result.issued.checkpoint.state == challenge.state


def test_pending_controller_retains_exact_attempt_and_independent_key_handles(h):
    h.certify()
    record, deps = role_case(h, Role.CONTROLLER)
    previous = h.did.registry.snapshot()[0][1][-1]
    pending = h.did.record(previous, key=h.authority.rotated.public_key)
    record = replace(
        record,
        state=replace(
            record.state, pending=encode_did_record(pending), pending_signer_handle=NEXT_KEY
        ),
    )
    deps = replace(
        deps,
        keys=(
            *deps.keys,
            KeyHandle(
                NEXT_KEY, h.authority.rotated.public_key, RecordingSigner(h.authority.rotated)
            ),
        ),
    )
    service = gate(h.pp, record, deps, FixtureRecoveryAuthority(record))
    assert service.admit(record) is Admission.ADMITTED
    assert service.publish() is DIDStatus.CONFLICT
    assert service.recover() is DIDStatus.CONFIRMED
    assert service.snapshot().public_key == h.authority.rotated.public_key
    assert h.did.transport.writes[-1][0] == record.state.pending


@pytest.mark.parametrize("damage", ["missing-key", "bad-chain", "wrong-registry", "mixed-holder"])
def test_did_and_holder_consistency_cannot_be_bypassed_by_freshness_oracle(h, damage):
    h.certify()
    role = Role.HOLDER if damage == "mixed-holder" else Role.CONTROLLER
    record, deps = role_case(h, role)
    if damage == "missing-key":
        deps = replace(deps, keys=(KeyHandle(KEY, b"wrong", deps.keys[0].signer),))
    elif damage == "bad-chain":
        record = replace(
            record, state=replace(record.state, history=(record.state.history[0][:-1],))
        )
    elif damage == "wrong-registry":
        record = replace(record, state=replace(record.state, registry_id=b"W" * 32))
    else:
        record = replace(
            record,
            state=replace(
                record.state, current_witness=replace(record.state.current_witness, identifier=43)
            ),
        )
    service = gate(h.pp, record, deps, FixtureRecoveryAuthority(record))
    assert service.admit(record) is Admission.REJECTED
    denied(service)


def test_container_identity_is_not_evidence_and_preserves_immutable_bytes(h):
    record = manager_checkpoint(h)
    digest = checkpoint_digest(record)
    assert digest == checkpoint_digest(replace(record))
    assert digest != checkpoint_digest(
        replace(record, state=replace(record.state, allocated_count=1))
    )
    assert gate(h.pp, record).admit(record) is Admission.REJECTED
    with pytest.raises(EncodingError):
        checkpoint_digest(replace(record, parameters=bytearray(record.parameters)))


@pytest.mark.parametrize("role", list(Role))
def test_strict_field_schema_including_empty_collections(h, role):
    h.certify()
    if role is Role.VERIFIER:
        v, _, valid = h.presentation()
        assert valid
        record, deps = verifier_checkpoint(v), verifier_deps(v)
    else:
        record, deps = role_case(h, role)
    fields = {
        Role.MANAGER: "revoked",
        Role.ISSUER: "certifications",
        Role.VERIFIER: "challenges",
        Role.REGISTRY: "histories",
        Role.RESOLVER: "used_nonces",
        Role.CONTROLLER: "history",
        Role.HOLDER: "current_witness",
    }
    # Empty bytes are not an empty tuple or an absent required witness. Dataclass
    # annotations alone do not enforce this; check before decoding/crypto.
    damaged = replace(record, state=replace(record.state, **{fields[role]: b""}))
    with pytest.raises(EncodingError, match="incorrect recovery field type"):
        checkpoint_digest(damaged)
    service = gate(h.pp, record, deps, FixtureRecoveryAuthority(record))
    assert service.admit(damaged) is Admission.REJECTED
    good = gate(h.pp, record, deps, FixtureRecoveryAuthority(record))
    assert good.admit(record) is Admission.ADMITTED


def test_total_byte_limit_precedes_any_reconstruction(h, monkeypatch):
    record = manager_checkpoint(h)

    def forbidden(*args, **kwargs):
        pytest.fail("expensive work before total byte admission")

    monkeypatch.setattr(recovery.rev, "ReferenceRevocationManager", forbidden)
    limits = replace(RecoveryLimits(), bytes=len(record.parameters))
    service = gate(h.pp, record, limits=limits, authority=FixtureRecoveryAuthority(record))
    assert service.admit(record) is Admission.REJECTED


def test_adapter_cannot_suppress_failed_admission_into_incomplete_success(h):
    class SuppressingFixtureAuthority:
        @contextmanager
        def exclusive(self, requested):
            try:
                yield None
            except EncodingError:
                pass  # Deliberately faulty TEST-ONLY context-manager adapter.

    record = manager_checkpoint(h)
    service = gate(h.pp, record, authority=SuppressingFixtureAuthority())
    assert service.admit(record) is Admission.REJECTED
    assert service._service is None
    denied(service)
