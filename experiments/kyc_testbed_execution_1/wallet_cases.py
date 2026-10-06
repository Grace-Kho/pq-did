"""24 literal holder checks; faults are test-process-only, stores always disposable."""

import os
import sqlite3
from dataclasses import replace
from pathlib import Path

from pqdid.codec import EncodingError
from pqdid.persistence.codec import Unavailable
from pqdid.verifier_state import ProofVerdict, UnsupportedProofVerifier
from pqdid.witness_updates import UpdateStatus

from . import wallet as w


def denied(fn):
    try:
        fn()
    except Unavailable, EncodingError, ValueError, OSError:
        return
    raise AssertionError("expected rejection")


def run(number, root, fixture):
    root.mkdir(mode=0o700)
    path = root / "wallet.sqlite3"
    owner = b"H" * 32
    wallet = w.Wallet.create(fixture.pp, path, owner, fixture.accepted, fixture.secret)
    before, snapshot = wallet.head, wallet.snapshot()
    reopened = w.Wallet(fixture.pp, path, owner)
    plan = wallet.prepare_recovery(before, snapshot.state)
    detail = {"contract": "holder-private; independent owner ticket", "failure_mode": None}
    if number == 1:
        assert wallet.snapshot() == snapshot and before.sequence == before.generation == 1
    elif number == 2:
        assert reopened.head is None
        admitted = reopened.prepare_recovery(before, fixture.states[0])
        assert reopened.commit(admitted) == admitted.after
        assert reopened.snapshot() == snapshot and reopened.head.generation == 2
    elif number == 3:
        assert reopened.snapshot(before) == snapshot and reopened.head is None
        assert snapshot.credential.certificate.signature == fixture.credential.certificate.signature
    elif number == 4:
        outcome, update = wallet.prepare_update(before, fixture.states[1], fixture.records)
        assert outcome.status is UpdateStatus.UPDATED and update is not None
        assert wallet.snapshot() == snapshot
        wallet.commit(update)
        new = wallet.snapshot()
        assert new.state == fixture.states[1] and new.witness.path == fixture.expected_path
        assert new.credential == snapshot.credential and wallet.head.sequence == 2
    elif number == 5:
        wallet.commit(plan)
        denied(lambda: reopened.snapshot(before))
        assert wallet.snapshot() == snapshot
    elif number == 6:
        denied(lambda: w.Wallet(fixture.pp, path, b"X" * 32).snapshot(before))
    elif number == 7:
        denied(
            lambda: w.Wallet(replace(fixture.pp, namespace=b"X" * 32), path, owner).snapshot(before)
        )
    elif number == 8:
        stale = wallet.prepare_update(before, fixture.states[0], ())[1]
        reopened.commit(plan)
        denied(lambda: wallet.commit(stale))
        assert reopened.snapshot() == snapshot
    elif number == 9:
        denied(lambda: reopened.prepare_recovery(before, fixture.states[1]))
    elif number == 10:
        denied(lambda: reopened.prepare_recovery(before, replace(snapshot.state, root=bytes(48))))
    elif number in (11, 12, 13, 14):
        changes = {
            11: {"attributes": bytes(1024)},
            12: {"revocation_identifier": 43},
            13: {"holder_secret": bytes(32)},
            14: {"signature": bytes(3309)},
        }[number]
        bad = replace(snapshot, witness=replace(snapshot.witness, **changes))
        denied(lambda: wallet._payload(bad))
        assert wallet.snapshot() == snapshot
    elif number == 15:
        with sqlite3.connect(path) as c:
            c.execute("UPDATE wallet SET payload=?", (b"PQL1-truncated",))
        denied(lambda: reopened.snapshot(before))
    elif number == 16:
        with path.open("r+b") as f:
            f.truncate(40)
        denied(lambda: reopened.snapshot(before))
    elif number in (17, 18):
        point = "before-commit" if number == 17 else "after-commit-before-response"

        def fault(actual):
            if actual == point:
                raise OSError("synthetic local interruption")

        original = w._fault
        w._fault = fault
        try:
            denied(lambda: wallet.commit(plan))
        finally:
            w._fault = original
        expected = before if number == 17 else plan.after
        assert reopened.snapshot(expected) == snapshot
        if number == 18:
            assert wallet.head is None
            denied(lambda: reopened.snapshot(before))
        detail["failure_mode"] = "simulated exception " + point
    elif number in (19, 20):
        point = "before-commit" if number == 19 else "after-commit-before-response"
        pid = os.fork()
        if pid == 0:

            def crash(actual):
                if actual == point:
                    os._exit(77)

            w._fault = crash
            wallet.commit(plan)
            os._exit(78)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 77
        expected = before if number == 19 else plan.after
        assert reopened.snapshot(expected) == snapshot
        detail["failure_mode"] = "actual child os._exit(77) " + point
    elif number == 21:
        retained = path.read_bytes()
        wallet.commit(plan)
        path.write_bytes(retained)
        denied(lambda: reopened.snapshot(plan.after))
    elif number == 22:
        with sqlite3.connect(path) as c:
            c.execute("DELETE FROM wallet")
        denied(lambda: reopened.snapshot(before))
    elif number == 23:
        side = Path(str(path) + "-wal")
        side.write_bytes(b"unexpected")
        denied(lambda: reopened.snapshot(before))
        side.unlink()
    elif number == 24:
        assert UnsupportedProofVerifier().verify(None, b"synthetic") is ProofVerdict.UNSUPPORTED
        assert wallet.snapshot() == snapshot
    else:
        raise AssertionError("unregistered case")
    if number in (6, 7, 9, 10):
        assert wallet.snapshot() == snapshot
    detail["store_bytes"] = sum(p.stat().st_size for p in root.iterdir())
    detail["result"] = "specified state and acceptance/rejection assertions passed"
    return detail
