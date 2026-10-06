"""24 individual integration cases; synthetic verdicts, injected faults, no new crash claim."""

import json
import os
import socket
import tempfile
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Lock, Thread

import pytest
from durable_verification_cases import Rig, material

from pqdid import bounded_mldsa_sign as core
from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.durable_verification import BoundedDurableVerifier
from pqdid.persistence import sqlite_store
from pqdid.persistence.codec import Unavailable
from pqdid.persistence.sqlite_store import digest
from pqdid.signing_adapters import ManagerSigningAdapter
from pqdid.statements import encode_context
from pqdid.verifier_state import REQUEST_CONTEXT, Decision, ProofVerdict
from tests.unit.test_signing_adapters import Gate

D = Path(__file__).resolve().parents[2] / "docs/data/s2_durable_verifier_lifecycle_integration_1"
ROWS = []


@pytest.fixture(scope="module")
def synthetic():
    return material()


@pytest.fixture
def rig(synthetic, request):
    with tempfile.TemporaryDirectory(prefix="verifier-flow-") as directory:
        value = Rig(Path(directory), synthetic)
        try:
            yield value
        finally:
            try:
                state = value.summary()
            except Unavailable as error:
                state = {"admission_unavailable": str(error)}
            ROWS.append({"case": request.node.name, "durable_after": state, **value.notes})
            (D / ("case-evidence-" + os.environ["PQDID_PILOT_RUN"] + ".json")).write_text(
                json.dumps(ROWS, indent=2) + "\n"
            )


@pytest.mark.parametrize("index", [0, 1])
def test_success_independent_verifiers(rig, index, monkeypatch):
    def forbidden(*args):
        raise AssertionError("hidden-DID resolution attempted")

    monkeypatch.setattr(rig.providers[index], "resolve_did", forbidden)
    request = rig.requests[index]
    assert bounded_verify_mldsa65(
        rig.keys[index + 2].public_key,
        encode_context(rig.pp, request.context),
        request.signature,
        context=REQUEST_CONTEXT,
    )
    assert rig.requests[0].context.nonce == rig.requests[1].context.nonce  # Separate namespaces.
    assert rig.verify(index) is Decision.ACCEPTED
    assert rig.consumed() == ([1, 0] if index == 0 else [0, 1])


@pytest.mark.parametrize("mode", ["wrong-audience", "cross-presentation"])
def test_cross_verifier(rig, mode):
    if mode == "wrong-audience":
        result = rig.verify(1, context=rig.requests[0].context)
        assert result is Decision.MISMATCH
    else:
        # B's X has never been approved by its exact synthetic adapter.
        result = rig.verify(1, presentation=rig.presentation(0))
        assert result is Decision.PROOF
    assert rig.consumed() == [0, 0]


@pytest.mark.parametrize("field", ["session", "policy", "issuer"])
def test_stored_context_mismatch(rig, field):
    ctx = rig.requests[0].context
    value = {
        "session": b"other-session",
        "policy": replace(ctx.policy, clauses=()),
        "issuer": bytes([ctx.issuer_reference[0] ^ 1]) + ctx.issuer_reference[1:],
    }
    name = "issuer_reference" if field == "issuer" else field
    expected = Decision.PUBLIC if field == "issuer" else Decision.MISMATCH
    assert rig.verify(context=replace(ctx, **{name: value[field]})) is expected
    assert rig.consumed() == [0, 0]


@pytest.mark.parametrize("when", ["initial", "final"])
def test_strict_expiry(rig, when, monkeypatch):
    if when == "initial":
        rig.clock.value = 100
    else:
        current = rig.providers[0].current

        def expire(*args):
            reply = current(*args)
            rig.clock.value = 100
            return reply

        monkeypatch.setattr(rig.providers[0], "current", expire)
    assert rig.verify() is Decision.EXPIRED
    assert rig.consumed() == [0, 0]


def test_public_disclosure_rejected(rig):
    bad = replace(rig.presentation(), disclosed_attributes=b"noncanonical")
    assert rig.verify(presentation=bad) is Decision.PUBLIC
    assert rig.consumed() == [0, 0]


@pytest.mark.parametrize("proof", ["normal-missing", "invalid"])
def test_proof_boundary(rig, proof):
    if proof == "normal-missing":
        rig.deps[0] = replace(rig.deps[0], proof_verifier=None)
        rig.reopen(0, rig.verifiers[0].ticket)
        expected = Decision.UNSUPPORTED
    else:
        rig.proofs[0].override = ProofVerdict.INVALID
        expected = Decision.PROOF
    assert rig.verify() is expected
    assert rig.consumed() == [0, 0]


@pytest.mark.parametrize(
    "mode", ["unauthenticated", "inconsistent-state", "before-read", "after-read"]
)
def test_boundary_current_state(rig, mode, monkeypatch):
    current = rig.providers[0].current
    if mode == "before-read":
        rig.revoke()
    else:

        def changed(*args):
            reply = current(*args)
            if mode == "after-read":
                rig.revoke()  # Ordered after authenticated read/retrieval, before consumption.
                return reply
            if mode == "unauthenticated":
                return replace(reply, signature=bytes(3309))
            invalid = replace(reply.state, signature=bytes(3309))
            key = rig.keys[1]
            signed = ManagerSigningAdapter(key, authorisation=Gate(key)).current(
                rig.pp, reply.nonce, invalid
            )
            return replace(reply, state=invalid, signature=signed.signature)

        monkeypatch.setattr(rig.providers[0], "current", changed)
    expected = Decision.ACCEPTED if mode == "after-read" else Decision.STATE
    assert rig.verify() is expected
    assert rig.consumed() == ([1, 0] if mode == "after-read" else [0, 0])
    rig.notes["freshness"] = mode + "; synthetic proof only, not a private relation check"


def test_boundary_restart_replay(rig):
    assert rig.verify() is Decision.ACCEPTED
    retained = rig.verifiers[0].ticket
    rig.reopen(0, retained)
    assert rig.verify() is Decision.UNKNOWN
    assert rig.verify(1) is Decision.ACCEPTED
    assert rig.consumed() == [1, 1]


def test_boundary_concurrent_submissions(rig, monkeypatch):
    first = rig.verifiers[0]
    second = BoundedDurableVerifier(
        rig.stores[0], rig.permits[0], first.ticket, signing_key=rig.keys[2]
    )
    barrier, serial = Barrier(2, timeout=3), Lock()
    monkeypatch.setattr(rig.proofs[0], "before_verdict", barrier.wait)
    current = rig.providers[0].current

    def ordered(*args):
        with serial:
            return current(*args)

    monkeypatch.setattr(rig.providers[0], "current", ordered)
    presentation, results, errors = rig.presentation(), [], []

    def submit(owner):
        try:
            results.append(
                owner.verify(
                    session=b"session", context=rig.requests[0].context, presentation=presentation
                )
            )
        except Exception as error:
            errors.append(type(error).__name__)

    threads = [Thread(target=submit, args=(owner,)) for owner in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert all(not thread.is_alive() for thread in threads) and not errors
    assert sorted(r.value for r in results) == sorted(
        [Decision.ACCEPTED.value, Decision.CONSUMED.value]
    )
    assert rig.consumed() == [1, 0]
    rig.notes["concurrent_results"] = [r.value for r in results]


@pytest.mark.parametrize("point", ["rows-before-commit", "commit-before-ack"])
def test_boundary_consumption_interruption(rig, point, monkeypatch):
    original = sqlite_store.SQLiteStore._write
    previous = rig.verifiers[0].ticket
    retained = []

    def write(store, *args):
        if store.key.role.value != "verifier" or args[6] != b"CONSUMED":
            return original(store, *args)

        def fail(at):
            if at == point:
                if point == "commit-before-ack":
                    retained.append(store._load(args[0])[0])
                raise Unavailable("injected-" + point)

        with monkeypatch.context() as patch:
            patch.setattr(sqlite_store, "_fault", fail)
            return original(store, *args)

    with monkeypatch.context() as patch:
        patch.setattr(sqlite_store.SQLiteStore, "_write", write)
        assert rig.verify() is Decision.FAILURE
    committed = point == "commit-before-ack"
    assert rig.consumed() == ([1, 0] if committed else [0, 0])
    if committed:
        with pytest.raises(Unavailable, match="stale-head"):
            rig.reopen(0, previous)
        rig.reopen(0, retained[0])
        assert rig.verify() is Decision.UNKNOWN
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with sender, receiver:
            sender.setblocking(False)
            receiver.setblocking(False)
            op = digest((b"consume", rig.requests[0].context.nonce))
            with pytest.raises(Unavailable, match="not-releasable"):
                rig.stores[0].publish(rig.permits[0], retained[0], op, b"recipient", sender)
            with pytest.raises(BlockingIOError):
                receiver.recv(65536)
    else:
        rig.reopen(0, previous)
        assert rig.verifiers[0].snapshot()[1].state.challenges[0].consumed is False
    rig.notes["fault_model"] = "injected exception " + point + "; not a process crash"


def test_boundary_writer_replaced_during_proof(rig, monkeypatch):
    def fence():
        rig.stores[0].acquire(b"admin", b"f" * 32, rig.verifiers[0].ticket, b"replacement")

    monkeypatch.setattr(rig.proofs[0], "before_verdict", fence)
    assert rig.verify() is Decision.FAILURE
    assert rig.consumed() == [0, 0]
    assert rig.summary()["verifiers"][0]["generation"] == 2


def test_boundary_inconsistent_recovery(rig):
    head = rig.verifiers[0].ticket
    with pytest.raises(Unavailable):
        rig.reopen(0, replace(head, checkpoint=bytes(32)))
    # Live configuration also binds recovered audience and public request identity.
    rig.deps[0] = replace(rig.deps[0], audience=b"audience-B")
    with pytest.raises(Unavailable, match="service-binding"):
        rig.reopen(0, head)
    assert rig.consumed() == [0, 0]


def test_boundary_request_signing_failure(rig, monkeypatch):
    original = core.bounded_sign_mldsa65

    def sign(key, message, *, role):
        if role == "request":
            raise core.BoundedMLDSAError(core.Failure.ENTROPY_FAILURE)
        return original(key, message, role=role)

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    request = rig.verifiers[0].create_challenge(
        session=b"second", policy=rig.original.context.policy, expires_at=100
    )
    assert request is None
    rows = rig.verifiers[0].snapshot()[1].state.challenges
    assert len(rows) == 2 and all(not row.consumed for row in rows)
    rig.notes["fault_model"] = "test-only request entropy failure; durable reservation retained"


def test_boundary_stale_manager(rig):
    rig.ms.acquire(b"admin", b"f" * 32, rig.manager.ticket, b"replacement")
    assert rig.verify() is Decision.FAILURE
    assert rig.consumed() == [0, 0]
