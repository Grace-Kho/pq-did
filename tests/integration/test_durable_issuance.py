"""24 individually counted integration cases, with explicit synthetic proof acceptance."""

import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from bounded_manager_cases import channel
from durable_issuance_cases import ISSUE, Rig, keys

from pqdid import bounded_mldsa_sign as core
from pqdid.credentials import decode_credential, encode_credential
from pqdid.durable_issuance import DurableIssuance, accept_delivery
from pqdid.issuance import HolderAcceptance, IssueStatus
from pqdid.persistence import sqlite_store
from pqdid.persistence.codec import Unavailable, decode, encode
from pqdid.persistence.records import HeadTicket
from pqdid.statements import decode_state

EVIDENCE = Path(__file__).resolve().parents[2] / "docs/data/s2_durable_issuer_manager_integration_1"
ROWS = []


@pytest.fixture(scope="module")
def material():
    return keys()


@pytest.fixture
def rig(material, request):
    with tempfile.TemporaryDirectory(prefix="issuer-manager-") as directory:
        value = Rig(Path(directory), material)
        try:
            yield value
        finally:
            try:
                state = value.summary()
            except Unavailable as error:
                state = {"admission_unavailable": str(error)}
            ROWS.append({"case": request.node.name, "durable_after": state, **value.notes})
            (EVIDENCE / ("case-evidence-" + os.environ["PQDID_PILOT_RUN"] + ".json")).write_text(
                json.dumps(ROWS, indent=2) + "\n"
            )


def signs(monkeypatch):
    original, calls = core.bounded_sign_mldsa65, []

    def sign(key, message, *, role):
        calls.append(role)
        return original(key, message, role=role)

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    return calls


def delivery(rig):
    with channel() as (left, right):
        assert rig.flow.retrieve(ISSUE, b"recipient", left) == b"REDELIVERY"
        return right.recv(65536)


def no_delivery(rig):
    with channel() as (left, right):
        with pytest.raises(Unavailable):
            rig.flow.retrieve(ISSUE, b"recipient", left)
        with pytest.raises(BlockingIOError):
            right.recv(65536)


def assert_unreleased(rig, phase=b"SIGNING"):
    state = rig.summary()
    assert state["allocated"] == 2 and state["phase"] == phase.decode()
    assert state["certifications"] == 0
    no_delivery(rig)


def test_successful_issuance_and_atomic_holder_acceptance(rig, monkeypatch):
    submission = rig.pending()
    calls = signs(monkeypatch)
    result = rig.flow.finish(ISSUE, submission)
    assert result.decision == b"CERTIFIED" and result.response == b""
    payload = delivery(rig)
    assert accept_delivery(rig.holder, payload).status is IssueStatus.ACCEPTED
    accepted = rig.holder.snapshot()
    assert accept_delivery(rig.holder, payload).status is IssueStatus.REPLAY
    assert rig.holder.snapshot() is accepted and accepted.credential.revocation_identifier == 1
    assert calls.count("credential") == 1 and rig.summary()["certifications"] == 1


def test_reservation_attachment_interruption_retires_without_reallocation(rig, monkeypatch):
    def fail(*_args):
        raise Unavailable("simulated-after-reservation")

    with monkeypatch.context() as patch:
        patch.setattr(rig.flow._issuer._owner, "attach", fail)
        with pytest.raises(Unavailable, match="simulated-after-reservation"):
            rig.pending()
    assert_unreleased(rig, b"INTENT")
    rig.reopen(*rig.heads())
    assert rig.flow.reconcile(ISSUE).decision == b"RETIRED"
    assert_unreleased(rig, b"RETIRED")
    assert rig.summary()["issuer_floor"] == 2
    rig.notes["fault_model"] = (
        "injected exception between manager reservation and issuer attachment"
    )


def test_certification_ack_interruption_exact_recipient_recovery(rig, monkeypatch):
    submission = rig.pending()
    original, retained = rig.flow._issuer._owner.log_certificate, {}

    def log(*args):
        def fault(point):
            if point == "commit-before-ack":
                retained["heads"] = rig.heads()
                raise Unavailable("simulated-lost-certification-ack")

        with monkeypatch.context() as patch:
            patch.setattr(sqlite_store, "_fault", fault)
            return original(*args)

    monkeypatch.setattr(rig.flow._issuer._owner, "log_certificate", log)
    with pytest.raises(Unavailable, match="simulated-lost-certification-ack"):
        rig.flow.finish(ISSUE, submission)
    no_delivery(rig)  # Caller still has the pre-certification head.
    rig.reopen(*retained["heads"])
    calls = signs(monkeypatch)
    first = delivery(rig)
    assert delivery(rig) == first and calls == []
    assert accept_delivery(rig.holder, first).status is IssueStatus.ACCEPTED
    assert rig.summary()["allocated"] == 2 and rig.summary()["certifications"] == 1
    rig.notes["fault_model"] = (
        "injected lost ack; trusted coordinator retained exact committed heads"
    )


def test_complete_pending_resumes_with_same_nonce_and_identifier(rig):
    submission = rig.pending()
    rig.reopen(*rig.heads())
    assert rig.flow.reconcile(ISSUE).decision == b"PENDING"
    challenge = rig.flow.challenge(ISSUE)
    assert challenge.statement(submission.statement.binding) == submission.statement
    rig.flow.finish(ISSUE, submission)
    assert accept_delivery(rig.holder, delivery(rig)).status is IssueStatus.ACCEPTED
    assert rig.summary()["nonces"] == 1 and rig.summary()["allocated"] == 2


@pytest.mark.parametrize("conflicting", [False, True])
def test_duplicate_or_conflicting_begin_has_no_second_reservation(rig, conflicting):
    rig.pending()
    before = rig.summary()
    request = replace(rig.h.request, session=b"other") if conflicting else rig.h.request
    with pytest.raises(Unavailable, match="operation-conflict"):
        rig.flow.begin(ISSUE, request, rig.state, b"recipient")
    assert rig.summary() == before


def test_wrong_recipient_cannot_retrieve_committed_result(rig):
    rig.flow.finish(ISSUE, rig.pending())
    before = rig.summary()
    with channel() as (left, right):
        with pytest.raises(Unavailable, match="wrong-recipient"):
            rig.flow.retrieve(ISSUE, b"wrong-recipient", left)
        with pytest.raises(BlockingIOError):
            right.recv(65536)
    assert rig.summary() == before


def test_wrong_instance_cannot_join_services(rig):
    foreign = replace(rig.h.selected[0], parameters=replace(rig.pp, namespace=b"X" * 32))
    before = rig.summary()
    with pytest.raises(ValueError):
        DurableIssuance(
            rig.issuer_store, rig.ip, rig.flow.ticket, manager=rig.manager, signing_key=foreign
        )
    assert rig.summary() == before


def test_mismatched_reservation_mapping_blocks_attachment(rig, monkeypatch):
    original = rig.port.reservation

    def mismatched(*args):
        request, payload = original(*args)
        return (b"X" * 32, *request[1:]), payload

    with monkeypatch.context() as patch:
        patch.setattr(rig.port, "reservation", mismatched)
        with pytest.raises(Unavailable, match="reservation-conflict"):
            rig.pending()
    assert_unreleased(rig, b"INTENT")
    assert rig.flow.reconcile(ISSUE).decision == b"RETIRED"
    assert rig.summary()["allocated"] == 2


def test_mismatched_credential_field_preserves_empty_holder(rig):
    rig.flow.finish(ISSUE, rig.pending())
    record = decode(delivery(rig))
    credential = decode_credential(rig.pp, record.credential)
    tampered = replace(
        record, credential=encode_credential(rig.pp, replace(credential, revocation_identifier=0))
    )
    assert accept_delivery(rig.holder, encode(tampered)).status is not IssueStatus.ACCEPTED
    assert rig.holder.snapshot() is None and rig.summary()["certifications"] == 1


def test_stale_issuer_generation_blocks_finish(rig, monkeypatch):
    submission = rig.pending()
    rig.issuer_store.acquire(b"admin", b"x" * 32, rig.flow.ticket, b"replacement")
    calls = signs(monkeypatch)
    with pytest.raises(Unavailable):
        rig.flow.finish(ISSUE, submission)
    assert calls == [] and rig.summary()["phase"] == "PENDING"
    assert rig.summary()["allocated"] == 2 and rig.summary()["certifications"] == 0


def test_stale_manager_authority_blocks_issuer_recovery(rig):
    rig.pending()
    issuer_ticket = rig.flow.ticket
    rig.manager_store.acquire(b"admin", b"x" * 32, rig.manager.ticket, b"replacement")
    with pytest.raises(Unavailable, match="checkpoint-admission"):
        DurableIssuance(
            rig.issuer_store,
            rig.ip,
            issuer_ticket,
            manager=rig.manager,
            signing_key=rig.h.selected[0],
        )
    no_delivery(rig)


def test_missing_cross_service_reservation_fails_reconciliation(rig, monkeypatch):
    rig.pending()
    before = rig.summary()
    with monkeypatch.context() as patch:
        patch.setattr(rig.port, "reservation", lambda *_args: None)
        with pytest.raises(Unavailable, match="missing-or-conflicting-manager-record"):
            rig.flow.reconcile(ISSUE)
    assert rig.summary() == before
    rig.notes["fault_model"] = (
        "injected unavailable manager reservation evidence; no reconstruction"
    )


@pytest.mark.parametrize("identifier", [1, 0])
def test_revocation_before_final_read_aborts_issuance(rig, identifier):
    submission = rig.pending()
    rig.revoke(identifier)
    with pytest.raises(Unavailable, match="certification-failed"):
        rig.flow.finish(ISSUE, submission)
    assert_unreleased(rig)
    assert rig.flow.reconcile(ISSUE).decision == b"RETIRED"
    assert rig.summary()["epoch"] == 1


def test_revocation_after_ordered_read_does_not_imply_current_eligibility(rig, monkeypatch):
    submission = rig.pending()
    original = core.bounded_sign_mldsa65

    def sign(key, message, *, role):
        if role == "credential":
            rig.revoke(1)  # Final witness read already happened; no cross-store lock.
        return original(key, message, role=role)

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    rig.flow.finish(ISSUE, submission)
    assert accept_delivery(rig.holder, delivery(rig)).status is IssueStatus.ACCEPTED
    accepted, manager = rig.holder.snapshot(), rig.manager.snapshot()[1].state
    assert accepted.checkpoint.state.epoch == 0 and decode_state(rig.pp, manager.state).epoch == 1
    assert 1 in manager.revoked and rig.summary()["certifications"] == 1
    rig.notes["claim"] = (
        "accepted original issuance checkpoint; NOT currently non-revoked/authenticated"
    )


@pytest.mark.parametrize("mode", ["normal-unsupported", "synthetic-rejected"])
def test_proof_boundary_rejects_without_certification(rig, mode):
    submission = rig.pending()
    if mode == "normal-unsupported":
        rig.deps = replace(rig.deps, proof_verifier=None)
        rig.issuer_store._deps = rig.deps
    else:
        submission = replace(submission, proof=b"UNAPPROVED")
    with pytest.raises(Unavailable, match="certification-failed"):
        rig.flow.finish(ISSUE, submission)
    assert_unreleased(rig)
    assert rig.flow.reconcile(ISSUE).decision == b"RETIRED"


def test_credential_signing_failure_retains_reservation(rig, monkeypatch):
    submission = rig.pending()
    original = core.bounded_sign_mldsa65

    def sign(key, message, *, role):
        if role == "credential":
            raise core.BoundedMLDSAError(core.Failure.ENTROPY_FAILURE)
        return original(key, message, role=role)

    monkeypatch.setattr(core, "bounded_sign_mldsa65", sign)
    with pytest.raises(Unavailable, match="certification-failed"):
        rig.flow.finish(ISSUE, submission)
    assert_unreleased(rig)
    assert rig.flow.reconcile(ISSUE).decision == b"RETIRED"


def test_required_certification_commit_failure_is_not_releasable(rig, monkeypatch):
    submission = rig.pending()
    original = rig.flow._issuer._owner.log_certificate

    def log(*args):
        def fail(point):
            if point == "rows-before-commit":
                raise Unavailable("simulated-log-commit-failure")

        with monkeypatch.context() as patch:
            patch.setattr(sqlite_store, "_fault", fail)
            return original(*args)

    monkeypatch.setattr(rig.flow._issuer._owner, "log_certificate", log)
    with pytest.raises(Unavailable, match="simulated-log-commit-failure"):
        rig.flow.finish(ISSUE, submission)
    assert_unreleased(rig)
    assert rig.flow.reconcile(ISSUE).decision == b"RETIRED"
    rig.notes["fault_model"] = "injected rows-before-certification-COMMIT exception"


def test_holder_rejects_different_intended_state_atomically(rig):
    submission = rig.pending()
    rig.flow.finish(ISSUE, submission)
    rig.revoke(0)
    state = decode_state(rig.pp, rig.manager.snapshot()[1].state.state)
    holder = HolderAcceptance(
        rig.pp, rig.h.secret, rig.h.attributes, replace(submission.statement, state=state)
    )
    assert accept_delivery(holder, delivery(rig)).status is IssueStatus.MISMATCH
    assert holder.snapshot() is None and rig.summary()["certifications"] == 1


def test_enqueued_but_unacknowledged_delivery_is_exact_redelivery(rig, monkeypatch):
    rig.flow.finish(ISSUE, rig.pending())
    calls = signs(monkeypatch)

    def fault(point):
        if point == "enqueue-before-return":
            raise Unavailable("simulated-unobserved-ack")

    with channel() as (left, right):
        with monkeypatch.context() as patch:
            patch.setattr(sqlite_store, "_fault", fault)
            with pytest.raises(Unavailable, match="simulated-unobserved-ack"):
                rig.flow.retrieve(ISSUE, b"recipient", left)
        first = right.recv(65536)
    assert delivery(rig) == first and calls == [] and rig.summary()["allocated"] == 2
    assert accept_delivery(rig.holder, first).status is IssueStatus.ACCEPTED


@pytest.mark.parametrize("mode", ["reservation", "certification"])
def test_real_process_crash(rig, monkeypatch, mode):
    if mode == "certification":
        rig.pending()
    rig.prepare_worker()
    command = [
        sys.executable,
        str(Path(__file__).with_name("durable_issuance_worker.py")),
        str(rig.root),
        mode,
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    facts, usage = None, None
    try:
        assert select.select([process.stdout], [], [], 10)[0], "barrier deadline"
        line = process.stdout.readline(4096)
        assert line, "worker exited before barrier"
        facts = json.loads(line)
        assert facts["barrier"] == mode
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
            "mode": mode,
            "pid": process.pid,
            "exit": process.returncode,
            "barrier": facts,
            "child_ru_maxrss_bytes": None if usage is None else usage.ru_maxrss * 1024,
        }

    def ticket(values):
        return HeadTicket(values[0], bytes.fromhex(values[1]), bytes.fromhex(values[2]), values[3])

    rig.reopen(ticket(facts["heads"]["manager"]), ticket(facts["heads"]["issuer"]))
    calls = signs(monkeypatch)
    if mode == "reservation":
        assert_unreleased(rig, b"INTENT")
        assert rig.flow.reconcile(ISSUE).decision == b"RETIRED"
        assert_unreleased(rig, b"RETIRED")
    else:
        assert rig.flow.reconcile(ISSUE).decision == b"CERTIFIED"
        first = delivery(rig)
        assert hashlib.sha256(first).hexdigest() == facts["response_sha256"]
        assert delivery(rig) == first
        assert accept_delivery(rig.holder, first).status is IssueStatus.ACCEPTED
    assert calls == [] and rig.summary()["allocated"] == 2
