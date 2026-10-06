"""Twenty-four individually reported manager integration cases, no primitive reruns."""

import hashlib
import json
import os
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from bounded_manager_cases import CURRENT, OP, Material, Rig, channel

from pqdid import bounded_mldsa_sign as core
from pqdid.bounded_manager import BoundedDurableManager
from pqdid.codec import EncodingError
from pqdid.persistence import sqlite_store
from pqdid.persistence.codec import Unavailable, decode, encode
from pqdid.persistence.records import HeadTicket
from pqdid.recovery_records import Role, checkpoint_digest
from pqdid.revocation_state import ManagerStatus
from pqdid.statements import decode_state
from pqdid.witness_updates import decode_update

EVIDENCE = Path(__file__).resolve().parents[2] / "docs/data/s2_bounded_manager_durable_release_1"
ROWS = []


@pytest.fixture(scope="module")
def material():
    return Material()


@pytest.fixture
def rig(material, request):
    with tempfile.TemporaryDirectory(prefix="bounded-manager-") as directory:
        value = Rig(Path(directory), material)
        try:
            yield value
        finally:
            try:
                state = value.summary()
            except (Unavailable, EncodingError) as error:
                state = {"admission_unavailable": str(error)}
            ROWS.append({"case": request.node.name, "durable_after": state, **value.notes})
            (EVIDENCE / ("case-evidence-" + os.environ["PQDID_PILOT_RUN"] + ".json")).write_text(
                json.dumps(ROWS, indent=2) + "\n"
            )


def count_signs(monkeypatch):
    original, calls = core.bounded_sign_mldsa65, []

    def sign(key, message, *, role):
        calls.append(role)
        return original(key, message, role=role)

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    return calls


def empty_socket(right):
    with pytest.raises(BlockingIOError):
        right.recv(65536)


def unchanged(rig, before):
    assert rig.summary() == before
    with channel() as (left, right):
        with pytest.raises(Unavailable, match="missing-outcome"):
            rig.owner.retrieve_committed(OP, left)
        empty_socket(right)


def test_revocation_restart_public_history_exact_redelivery(rig, monkeypatch):
    calls = count_signs(monkeypatch)
    outcome = rig.owner.revoke(OP, rig.request)
    assert outcome.decision == b"REVOKED" and outcome.response == b""
    assert calls == ["state", "update"]
    owner = rig.fresh(outcome.ticket)
    ticket, cp, _ = owner.snapshot()
    assert cp.state.allocated_count == 2 and cp.state.revoked == (0,)
    assert cp.state.consumed_nonces == (rig.request.nonce,) and len(cp.state.history) == 1
    page = owner.updates(rig.pp.namespace, 0, 1)
    assert page.status is ManagerStatus.PAGE and page.page.records == cp.state.history
    assert page.page.complete and ticket == outcome.ticket
    with channel() as (left, right):
        assert owner.retrieve_committed(OP, left) == b"REDELIVERY"
        first = right.recv(65536)
        assert decode(first) == (cp.state.state, cp.state.history[0])
        assert decode_update(rig.pp, cp.state.history[0]).new_state == decode_state(
            rig.pp, cp.state.state
        )
        assert owner.retrieve_committed(OP, left) == b"REDELIVERY"
        assert right.recv(65536) == first
    assert calls == ["state", "update"] and owner.ticket == outcome.ticket
    rig.notes["redelivery_signatures"] = 0


def test_current_restart_exact_redelivery(rig, monkeypatch):
    calls = count_signs(monkeypatch)
    outcome = rig.owner.read_current(CURRENT, b"n" * 32)
    assert outcome.decision == b"CURRENT" and outcome.response == b""
    owner = rig.fresh(outcome.ticket)
    assert owner.snapshot()[1].state.history == ()
    with channel() as (left, right):
        owner.retrieve_committed(CURRENT, left)
        first = right.recv(65536)
        nonce, state, signature = decode(first)
        assert (
            nonce == b"n" * 32
            and state == owner.snapshot()[1].state.state
            and len(signature) == 3309
        )
        owner.retrieve_committed(CURRENT, left)
        assert right.recv(65536) == first
    assert calls == ["current"]


def test_rows_before_commit_failure_is_absent(rig, monkeypatch):
    before, calls = rig.summary(), count_signs(monkeypatch)

    def fault(point):
        if point == "rows-before-commit":
            raise Unavailable("simulated-before-commit")

    with monkeypatch.context() as patch:
        patch.setattr(sqlite_store, "_fault", fault)
        with pytest.raises(Unavailable, match="simulated-before-commit"):
            rig.owner.revoke(OP, rig.request)
    unchanged(rig, before)
    assert calls == ["state", "update"]
    rig.notes["fault_model"] = "simulated exception after all rows, before COMMIT"


def test_after_commit_unobserved_response_requires_explicit_head(rig, monkeypatch):
    calls, retained = count_signs(monkeypatch), {}

    def fault(point):
        if point == "commit-before-ack":
            retained["ticket"] = rig.store.inspect(b"writer")[0]
            raise Unavailable("simulated-lost-ack")

    with monkeypatch.context() as patch:
        patch.setattr(sqlite_store, "_fault", fault)
        with pytest.raises(Unavailable, match="simulated-lost-ack"):
            rig.owner.revoke(OP, rig.request)
    assert rig.owner.ticket == rig.initial_ticket and rig.summary()["epoch"] == 1
    with pytest.raises(Unavailable, match="stale-head"):
        rig.fresh(rig.initial_ticket)
    recovered = rig.fresh(retained["ticket"])
    with channel() as (left, right):
        recovered.retrieve_committed(OP, left)
        first = right.recv(65536)
        recovered.retrieve_committed(OP, left)
        assert right.recv(65536) == first
    assert calls == ["state", "update"]
    rig.notes["fault_model"] = "simulated lost ack; trusted test coordinator retains committed head"


def test_stale_head_rejected_before_signing(rig, monkeypatch):
    peer = rig.fresh(rig.initial_ticket)
    peer.reserve(b"a" * 32, b"I" * 32, b"i" * 32, rig.state.reference)
    before, calls = rig.summary(), count_signs(monkeypatch)
    with pytest.raises(Unavailable, match="stale-head"):
        rig.owner.revoke(OP, rig.request)
    assert rig.summary() == before and calls == []


def test_fencing_during_signing_discards_material(rig, monkeypatch):
    original, calls = core.bounded_sign_mldsa65, []

    def sign(key, message, *, role):
        calls.append(role)
        result = original(key, message, role=role)
        rig.replace_writer()
        return result

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    with pytest.raises(Unavailable, match="manager-signing-failed"):
        rig.owner.revoke(OP, rig.request)
    state = rig.summary()
    assert calls == ["state"] and state["generation"] == 2
    assert state["epoch"] == state["history"] == state["consumed_nonces"] == 0
    with channel() as (left, right):
        with pytest.raises(Unavailable, match="fenced-writer"):
            rig.owner.retrieve_committed(OP, left)
        empty_socket(right)


@pytest.mark.parametrize("race", ["allocation", "replacement"])
def test_revalidate_at_commit(rig, monkeypatch, race):
    original, calls = rig.owner._commit, count_signs(monkeypatch)

    def commit(*args):
        if race == "allocation":
            peer = rig.fresh(rig.initial_ticket)
            peer.reserve(b"a" * 32, b"I" * 32, b"i" * 32, rig.state.reference)
        else:
            rig.replace_writer()
        return original(*args)

    monkeypatch.setattr(rig.owner, "_commit", commit)
    with pytest.raises(Unavailable, match="stale-head|fenced-writer"):
        rig.owner.revoke(OP, rig.request)
    state = rig.summary()
    assert calls == ["state", "update"] and state["epoch"] == 0 and state["history"] == 0
    assert state["allocated"] == (3 if race == "allocation" else 2)
    assert state["consumed_nonces"] == 0


def test_invalid_issuer_signature_never_signs(rig, monkeypatch):
    before, calls = rig.summary(), count_signs(monkeypatch)
    request = replace(rig.request, signature=bytes(3309))
    with pytest.raises(Unavailable, match="invalid-issuer-authorisation"):
        rig.owner.revoke(OP, request)
    unchanged(rig, before)
    assert calls == []


def test_withdrawn_write_authority_never_signs_or_publishes(rig, monkeypatch):
    before, calls = rig.summary(), count_signs(monkeypatch)
    rig.policy.write_enabled = False
    with pytest.raises(Unavailable, match="unauthorised"):
        rig.owner.revoke(OP, rig.request)
    with channel() as (left, right):
        with pytest.raises(Unavailable, match="unauthorised"):
            rig.owner.retrieve_committed(OP, left)
        empty_socket(right)
    assert rig.summary() == before and calls == []


@pytest.mark.parametrize(
    "role,failure,expected",
    [
        ("state", core.Failure.ENTROPY_FAILURE, "signing-failed"),
        ("update", core.Failure.ATTEMPTS_EXHAUSTED, "resource-exhausted"),
        ("current", core.Failure.RELEASE_REJECTED, "signing-failed"),
    ],
)
def test_manager_signing_failure_has_no_durable_outcome(rig, monkeypatch, role, failure, expected):
    before, original, calls = rig.summary(), core.bounded_sign_mldsa65, []

    def sign(key, message, *, role: str):
        calls.append(role)
        if role == target:
            raise core.BoundedMLDSAError(failure)
        return original(key, message, role=role)

    target = role
    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    with pytest.raises(Unavailable, match=expected):
        if role == "current":
            rig.owner.read_current(OP, b"n" * 32)
        else:
            rig.owner.revoke(OP, rig.request)
    unchanged(rig, before)
    assert calls == (["state", "update"] if role == "update" else [role])
    rig.notes["fault_model"] = (
        "test-only core error boundary; primitive paths reused from prior package"
    )


@pytest.mark.parametrize("field", ["service", "role", "instance"])
def test_manager_configuration_cannot_cross_authority(rig, field):
    selected = rig.material.manager_key
    if field == "service":
        selected = replace(selected, service_id=b"X" * 32)
    elif field == "role":
        selected = replace(selected, authority_role=Role.ISSUER)
    else:
        selected = replace(selected, parameters=replace(rig.pp, namespace=b"X" * 32))
    before = rig.summary()
    with pytest.raises((Unavailable, EncodingError)):
        BoundedDurableManager(rig.store, rig.permit, rig.initial_ticket, signing_key=selected)
    assert rig.summary() == before


def semantic_corruption(rig, field):
    """TEST ONLY internally rehashed bad checkpoint, to exercise semantic admission."""
    ticket, cp, _ = rig.store.inspect(b"writer")
    cp = replace(cp, state=replace(cp.state, **{field: ()}))
    cp_digest = checkpoint_digest(cp)
    with sqlite3.connect(rig.store._path) as connection:
        row = connection.execute("SELECT * FROM heads WHERE seq=?", (ticket.sequence,)).fetchone()
        op = connection.execute("SELECT * FROM operations WHERE id=?", (row[4],)).fetchone()
        head = sqlite_store.digest(
            (
                row[0],
                row[2],
                cp_digest,
                sqlite_store.digest(op),
                row[5],
                row[6],
                rig.store._identity,
            )
        )
        connection.execute("INSERT INTO checkpoints VALUES (?,?)", (cp_digest, encode(cp)))
        connection.execute(
            "UPDATE heads SET digest=?,checkpoint=? WHERE seq=?", (head, cp_digest, row[0])
        )
    return HeadTicket(ticket.sequence, head, cp_digest, ticket.generation)


@pytest.mark.parametrize("field", ["history", "consumed_nonces"])
def test_semantically_incomplete_recovery_denied(rig, field):
    rig.owner.revoke(OP, rig.request)
    false_anchor = semantic_corruption(rig, field)
    with pytest.raises(Unavailable, match="checkpoint-admission"):
        rig.fresh(false_anchor)
    rig.notes["fault_model"] = (
        "synthetic semantic corruption with rehashed bad head; not rollback protection"
    )


def test_missing_checkpoint_recovery_denied(rig):
    outcome = rig.owner.revoke(OP, rig.request)
    with sqlite3.connect(rig.store._path) as connection:
        connection.execute("DELETE FROM checkpoints WHERE digest=?", (outcome.ticket.checkpoint,))
    with pytest.raises(Unavailable, match="missing-reference"):
        rig.fresh(outcome.ticket)
    rig.notes["fault_model"] = "isolated missing checkpoint row; no protected project file changed"


@pytest.mark.parametrize("change", ["superseded-current", "fenced-writer"])
def test_obsolete_publication_denied(rig, monkeypatch, change):
    rig.owner.read_current(CURRENT, b"n" * 32)
    if change == "superseded-current":
        rig.owner.revoke(OP, rig.request)
    else:
        rig.replace_writer()
    calls = count_signs(monkeypatch)
    with channel() as (left, right):
        with pytest.raises(Unavailable, match=change):
            rig.owner.retrieve_committed(CURRENT, left)
        empty_socket(right)
    assert calls == []


def test_repeated_mutation_requires_retrieval_without_resigning(rig, monkeypatch):
    rig.owner.revoke(OP, rig.request)
    before, calls = rig.summary(), count_signs(monkeypatch)
    with pytest.raises(Unavailable, match="already-committed-use-retrieval"):
        rig.owner.revoke(OP, rig.request)
    assert calls == [] and rig.summary() == before


@pytest.mark.parametrize("point", ["rows-before-commit", "commit-before-ack"])
def test_real_process_crash(rig, monkeypatch, point):
    command = [
        sys.executable,
        str(Path(__file__).with_name("bounded_manager_worker.py")),
        str(rig.root),
        point,
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    barrier, usage = None, None
    try:
        assert select.select([process.stdout], [], [], 8)[0], "application deadline"
        raw = process.stdout.readline(4096)
        assert raw, "worker failed before barrier"
        barrier = json.loads(raw)
        assert barrier["barrier"] == point
        process.kill()
        _pid, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        assert process.returncode == -signal.SIGKILL
        assert process.stdout.read(4096) == process.stderr.read(4096) == b""
    finally:
        if process.returncode is None:
            process.kill()
            process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        rig.notes["crash"] = {
            "point": point,
            "barrier": barrier,
            "pid": process.pid,
            "exit": process.returncode,
            "child_ru_maxrss_bytes": None if usage is None else usage.ru_maxrss * 1024,
            "model": "real SIGKILL at application boundary; no power-loss or SQLite-internal fault",
        }
    calls = count_signs(monkeypatch)
    if point == "rows-before-commit":
        recovered = rig.fresh(rig.initial_ticket)
        assert recovered.snapshot()[1].state.history == ()
        assert rig.summary()["epoch"] == rig.summary()["consumed_nonces"] == 0
        with channel() as (left, right):
            with pytest.raises(Unavailable, match="missing-outcome"):
                recovered.retrieve_committed(OP, left)
            empty_socket(right)
    else:
        sequence, digest, checkpoint, generation = barrier["ticket"]
        ticket = HeadTicket(sequence, bytes.fromhex(digest), bytes.fromhex(checkpoint), generation)
        with pytest.raises(Unavailable, match="stale-head"):
            rig.fresh(rig.initial_ticket)
        recovered = rig.fresh(ticket)
        _, cp, _ = recovered.snapshot()
        assert len(cp.state.history) == len(cp.state.consumed_nonces) == 1 and cp.state.revoked == (
            0,
        )
        with channel() as (left, right):
            recovered.retrieve_committed(OP, left)
            first = right.recv(65536)
            assert hashlib.sha256(first).hexdigest() == barrier["response_sha256"]
            assert decode(first) == (cp.state.state, cp.state.history[0])
            recovered.retrieve_committed(OP, left)
            assert right.recv(65536) == first
    assert calls == []
