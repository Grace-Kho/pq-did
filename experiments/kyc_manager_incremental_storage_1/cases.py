"""Individually counted isolated manager/migration fixtures with real signatures."""

import os
import secrets
import shutil
import socket
import sqlite3
from dataclasses import replace

from experiments.kyc_issuer_incremental_storage_1.cases import rejected
from experiments.kyc_issuer_incremental_storage_1.integration import upgrade as issuer_upgrade
from experiments.kyc_manager_incremental_storage_1 import store as m
from experiments.kyc_testbed_execution_1.application import Application
from pqdid.bounded_manager import BoundedDurableManager
from pqdid.persistence.codec import decode, encode
from pqdid.persistence.records import HeadTicket
from pqdid.recovery_records import checkpoint_digest
from pqdid.statements import decode_state


def fixture(root):
    app = Application.create(root)
    issuer_upgrade(app)
    app.issue()
    other = app.scenario.add_holder()
    app.scenario.revoke(other.credential.identifier)
    return app


def clone(source, root):
    root.mkdir(mode=0o700)
    path = root / "authority.sqlite3"
    shutil.copyfile(source._path, path)
    path.chmod(0o600)
    return type(source)(path, source.key, dependencies=source._deps, authorisation=source._policy)


def owner(store, permit, ticket, app):
    return BoundedDurableManager(store, permit, ticket, signing_key=app.scenario.trusted[b"M"])


def predict(store, args):
    c, ticket, cp, entries, op, request, decision, response, gen, writer = args
    nodes = {}
    er = m.intern(tuple(sorted(entries.items())), nodes)
    refs = tuple(m.intern(x, nodes) for x in (request, decision, response))
    hd = m.new_head(
        store._identity,
        ticket.sequence + 1,
        ticket.digest,
        checkpoint_digest(cp),
        op,
        refs,
        gen,
        er,
        writer,
    )
    return HeadTicket(ticket.sequence + 1, hd, checkpoint_digest(cp), gen)


def faulted(store, point, action, actual_exit=False):
    original = store._write
    captured = []

    def wrapped(*args):
        captured.append(predict(store, args))
        return original(*args)

    store._write = wrapped
    if actual_exit:
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)

            def fault(where):
                if where == point:
                    os.write(write, encode(captured[-1].record()))
                    os._exit(73)

            m._fault = fault
            try:
                action()
            except BaseException:
                os._exit(74)
            os._exit(75)
        os.close(write)
        data = os.read(read, 1024)
        os.close(read)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 73
        result = HeadTicket(*decode(data))
    else:

        def fault(where):
            if where == point:
                raise RuntimeError("injected commit interruption")

        m._fault = fault
        try:
            action()
        except RuntimeError:
            pass
        else:
            raise AssertionError("fault not reached")
        finally:
            m._fault = lambda _: None
        result = captured[-1]
    store._write = original
    return result


def migrate_fault(old, permit, plan, point, actual_exit):
    if actual_exit:
        pid = os.fork()
        if pid == 0:
            m._fault = lambda where: os._exit(73) if where == point else None
            try:
                m.ManagerStore.migrate(old, b"admin", permit, plan)
            except BaseException:
                os._exit(74)
            os._exit(75)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 73
    else:

        def fail(where):
            if where == point:
                raise RuntimeError("migration interruption")

        m._fault = fail
        try:
            m.ManagerStore.migrate(old, b"admin", permit, plan)
        except RuntimeError:
            pass
        else:
            raise AssertionError("missing migration fault")
        finally:
            m._fault = lambda _: None


def run(i, root, app):
    s = app.scenario
    old = clone(s.manager_store, root)
    before = s.manager.ticket
    permit = s.manager_permit
    original = old.inspect(b"writer")
    plan = m.ManagerStore.migration_plan(old, b"admin", before, permit)
    if 2 <= i <= 5:
        point = "rows-before-commit" if i in (2, 4) else "commit-before-ack"
        migrate_fault(old, permit, plan, point, i in (4, 5))
        if i in (2, 4):
            assert old.inspect(b"writer") == original
        else:
            new = m.ManagerStore(
                old._path, old.key, dependencies=old._deps, authorisation=old._policy
            )
            assert (
                new.admit(m.WriterPermit(permit.principal, plan.after.generation), plan.after)
                == plan.after
            )
            assert new.inspect(b"writer")[1:] == original[1:]
        return dict(interruption=point, actual_exit=i in (4, 5), preserved=True)
    if i == 6:
        old.acquire(b"admin", secrets.token_bytes(32), before, b"writer")
        rejected(lambda: m.ManagerStore.migrate(old, b"admin", permit, plan))
        return dict(stale_migration_rejected=True)
    new, permit, head = m.ManagerStore.migrate(old, b"admin", permit, plan)
    manager = owner(new, permit, head, app)
    if i == 1:
        for _ in range(3):
            recovered = owner(new, permit, head, app)
            assert recovered.snapshot()[1:] == original[1:]
        assert new.inspect(b"writer")[1:] == original[1:]
    elif i == 7:
        rejected(lambda: old.admit(s.manager_permit, before))
        rejected(lambda: new.admit(s.manager_permit, head))
    elif i in (8, 9, 10, 11):
        op = secrets.token_bytes(32)
        nonce = secrets.token_bytes(32)
        point = "rows-before-commit" if i in (8, 10) else "commit-before-ack"
        expected = faulted(new, point, lambda: manager.read_current(op, nonce), i in (10, 11))
        ticket = head if i in (8, 10) else expected
        recovered = owner(new, permit, ticket, app)
        assert recovered.snapshot()[1:] == original[1:]
        with new._connection() as c:
            _, _, _, _, ops = new._load(c)
            assert (op in ops) == (i in (9, 11))
            if op in ops:
                assert decode(ops[op][2])[0] == nonce
        return dict(
            interruption=point,
            actual_exit=i in (10, 11),
            committed=i in (9, 11),
            head=ticket.record()[0],
            unchanged_manager_state=True,
        )
    elif i == 12:
        original_commit = manager._commit
        newhead = []

        def race(*args):
            permit2, ticket2 = new.acquire(b"admin", secrets.token_bytes(32), head, b"writer")
            newhead.append((permit2, ticket2))
            return original_commit(*args)

        manager._commit = race
        rejected(lambda: manager.read_current(secrets.token_bytes(32), secrets.token_bytes(32)))
        assert owner(new, *newhead[0], app).snapshot()[1:] == original[1:]
    elif 13 <= i <= 17:
        with sqlite3.connect(new._path) as c:
            if i == 13:
                nodes = {}
                key = m.intern(original[1].state.history[0], nodes)
                c.execute("DELETE FROM nodes WHERE digest=?", (key,))
            elif i == 14:
                root = c.execute(
                    "SELECT root FROM checkpoints WHERE digest=?", (head.checkpoint,)
                ).fetchone()[0]
                c.execute(
                    "UPDATE checkpoints SET root=? WHERE digest=?", (b"z" * 32, head.checkpoint)
                )
                assert root != b"z" * 32
            elif i == 15:
                c.execute("UPDATE heads SET digest=? WHERE seq=?", (b"z" * 32, head.sequence))
            elif i == 16:
                c.execute(
                    "UPDATE nodes SET data=? WHERE digest=(SELECT digest FROM nodes LIMIT 1)",
                    (b"malformed",),
                )
            elif i == 17:
                c.execute("DELETE FROM operations WHERE id=?", (plan.operation,))
        rejected(lambda: manager.snapshot())
    elif i == 18:
        rejected(lambda: owner(new, permit, before, app))
        wrong = m.ManagerStore(
            new._path,
            replace(new.key, authority_id=b"X" * 32),
            dependencies=new._deps,
            authorisation=new._policy,
        )
        rejected(lambda: wrong.inspect(b"writer"))
    elif i == 19:
        op = secrets.token_bytes(32)
        nonce = secrets.token_bytes(32)
        manager.read_current(op, nonce)

        def no_sign(*args):
            raise AssertionError("redelivery resigned")

        manager._candidate = no_sign
        values = []
        for _ in range(2):
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with a, b:
                a.setblocking(False)
                b.setblocking(False)
                manager.retrieve_committed(op, a)
                values.append(b.recv(65536))
        assert values[0] == values[1] and decode(values[0])[0] == nonce
    elif i == 20:
        issuer = s.issuer
        before_issuer = issuer.journal.ticket
        first = issuer.retrieve(s.last_operation, b"holder")
        rejected(lambda: issuer.retrieve(s.last_operation, b"other"))
        assert (
            issuer.retrieve(s.last_operation, b"holder") == first
            and issuer.journal.ticket == before_issuer
        )
    elif i == 21:
        assert original[1].state.consumed_nonces == manager.snapshot()[1].state.consumed_nonces
        assert original[1].state.allocated_count == manager.snapshot()[1].state.allocated_count
        key = next(iter(original[2]))
        args = original[2][key][0]
        rejected(
            lambda: manager.reserve(
                secrets.token_bytes(32),
                args[0],
                args[1],
                decode_state(s.pp, original[1].state.state).reference,
            )
        )
        assert manager.snapshot()[1:] == original[1:]
    elif i == 22:
        # Exact representation regression; not a valid eight-record cryptographic chain.
        cp = replace(
            original[1], state=replace(original[1].state, history=original[1].state.history * 8)
        )
        assert sum(map(len, cp.state.history)) == 89296
        reason = rejected(lambda: encode(cp))
        assert reason == "payload-cap"
        nodes = {}
        root = m.intern(cp, nodes)
        assert m.unpack(root, nodes, {}) == cp
        rejected(lambda: new._validate(cp))  # Storage support never bypasses semantic admission.
        return dict(
            old_failure=reason, storage_roundtrip=True, invalid_duplicated_history_rejected=True
        )
    elif i == 23:
        rejected(lambda: m.intern(bytes(65536), {}))
    elif i == 24:
        with old._path.open("rb") as f:
            assert f.read(16) == b"SQLite format 3\0"
        with new._connection() as c:
            assert (
                c.execute("SELECT count(*) FROM heads WHERE format=0").fetchone()[0]
                == before.sequence
            )
            for op, request, decision, response in c.execute("SELECT * FROM operations"):
                assert len(op) == 32 and all(len(x) == 32 for x in (request, decision, response))
        assert original[1].state.history == manager.snapshot()[1].state.history
    elif i in (25, 26):
        from experiments.kyc_milestone_1.baseline.scenario import _OwnerGate
        from pqdid.revocation_state import RevocationRequest
        from pqdid.signing_adapters import IssuerSigningAdapter

        state = decode_state(s.pp, original[1].state.state)
        req = RevocationRequest(0, state.reference, secrets.token_bytes(32), bytes(3309))
        key = s.trusted[b"I"]
        sig = IssuerSigningAdapter(key, authorisation=_OwnerGate(key)).revocation_request(s.pp, req)
        req = replace(req, signature=sig.signature)
        operation = secrets.token_bytes(32)
        point = "rows-before-commit" if i == 25 else "commit-before-ack"
        expected = faulted(new, point, lambda: manager.revoke(operation, req), True)
        recovered = owner(new, permit, head if i == 25 else expected, app)
        after = recovered.snapshot()[1]
        if i == 25:
            assert after == original[1]
            with new._connection() as c:
                assert operation not in new._load(c)[4]
        else:
            assert len(after.state.history) == len(original[1].state.history) + 1
            assert req.nonce in after.state.consumed_nonces and 0 in after.state.revoked
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with a, b:
                a.setblocking(False)
                b.setblocking(False)
                recovered.retrieve_committed(operation, a)
                raw = b.recv(65536)
            assert decode(raw) == (after.state.state, after.state.history[-1])
            rejected(lambda: recovered.revoke(secrets.token_bytes(32), req))
        return dict(
            actual_process_exit=True,
            interruption=point,
            committed=i == 26,
            history_records=len(after.state.history),
            public_result_released_only_if_committed=True,
        )
    else:
        raise AssertionError(i)
    return dict(
        check=i,
        preserved_allocations=original[1].state.allocated_count,
        preserved_nonces=len(original[1].state.consumed_nonces),
        history_records=len(original[1].state.history),
        schema=2,
        expected_state_asserted=True,
    )
