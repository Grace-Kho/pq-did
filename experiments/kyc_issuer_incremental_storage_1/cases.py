"Counted storage fixtures; synthetic records never assert cryptographic acceptance."

import hashlib
import os
import sqlite3
import tarfile
from dataclasses import replace

from experiments.kyc_issuer_incremental_storage_1 import journal as v2
from experiments.kyc_issuer_incremental_storage_1 import run as guard
from experiments.kyc_milestone_1.baseline import storage as v1
from pqdid.codec import EncodingError
from pqdid.persistence.codec import Unavailable, encode


def rejected(fn):
    try:
        fn()
    except (Unavailable, EncodingError, sqlite3.IntegrityError) as error:
        return str(error)
    raise AssertionError("unexpected acceptance")


def row(number=1):
    session = number.to_bytes(32)
    value = (
        b"INTENT",
        session,
        hashlib.sha256(b"nonce" + session).digest(),
        b"k" * 1952,
        b"a" * 1024,
        b"holder",
        None,
        None,
        None,
    )
    return hashlib.sha256(b"baseline-issue" + session).digest(), value


def add(j, number=1):
    op, value = row(number)
    j.transition("intent", lambda rows: rows.update({op: value}))
    return op, value


def advance(j, op, value):
    reserved = (b"RESERVED", *value[1:6], int.from_bytes(value[1]), b"p" * 960, b"s" * 3427)
    j.transition("reservation", lambda rows: rows.update({op: reserved}))
    signing = (b"SIGNING", *reserved[1:])
    j.transition("claim", lambda rows: rows.update({op: signing}))
    certified = (b"CERTIFIED", *signing[1:], b"c" * 11019)
    j.transition("certification", lambda rows: rows.update({op: certified}))
    return certified


def fresh(path):
    v1.directory(path, create=True)
    return v1.IssuerJournal.create(path / "issuer.sqlite3", b"I" * 32)


def migration(old):
    return v2.IssuerJournal.migration_plan(old.path, old.identity, old.ticket, old.generation)


def reopen(j, expected=None):
    expected = j.ticket if expected is None else expected
    return v2.IssuerJournal(j.path, j.identity, expected, expected[1])


def crash(point, fn):
    pid = os.fork()
    if pid == 0:
        v2._fault = lambda where: os._exit(73) if where == point else None
        try:
            fn()
        except BaseException:
            os._exit(74)
        os._exit(75)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 73


def archived(path):
    old = guard.P / "docs/data/kyc_testbed_execution_1"
    manifest = guard.read(old / "failed-R-1-4-inventory.json")
    archive = old / "failed-R-1-4.tar.xz"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == manifest["archive_sha256"]
    names = manifest["files"]
    with tarfile.open(archive, "r:xz") as tar:
        entries = tar.getmembers()
        files = [m for m in entries if m.isfile()]
        assert {m.name for m in files} == set(names)
        assert all(m.isfile() or m.isdir() for m in entries)
        for member in files:
            info = names[member.name]
            assert member.size == info["bytes"]
            data = tar.extractfile(member).read(member.size + 1)
            assert hashlib.sha256(data).hexdigest() == info["sha256"]
            if member.name == "issuer/issuer.sqlite3":
                v1.directory(path, create=True)
                target = path / "issuer.sqlite3"
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
    with sqlite3.connect(target) as c:
        identity, seq, gen, head = c.execute(
            "SELECT identity,seq,generation,head FROM meta"
        ).fetchone()
    # Admission is from the independently sealed archive, NOT an arbitrary store's own head.
    return v1.IssuerJournal(target, identity, (seq, gen, head), gen)


def run(number, path):
    if number in (1, 2):
        old = archived(path)
        rows = old.snapshot()
        before = old.ticket
        op, value = next((k, v) for k, v in rows.items() if v[0] == b"SIGNING")
        attempted = (b"CERTIFIED", *value[1:], b"c" * 11019)
        if number == 1:
            reason = rejected(
                lambda: old.transition("certification", lambda r: r.update({op: attempted}))
            )
            assert old.snapshot() == rows and old.ticket == before
            return dict(
                expected_rejection=reason,
                rows=len(rows),
                individual_bytes=[len(encode(v)) for v in rows.values()],
                phase="SIGNING retained; synthetic attempted outcome never delivered",
                archive_verified=True,
            )
        plan = migration(old)
        j = v2.IssuerJournal.migrate(plan)
        assert j.snapshot() == rows and j.ticket == plan.after
        j.transition("certification", lambda r: r.update({op: attempted}))
        assert j.snapshot()[op] == attempted and j.ticket[0] == before[0] + 2
        return dict(
            rows=len(rows),
            retained_ids=sorted(v[6] for v in rows.values()),
            payload_bytes=sum(len(encode(v)) for v in j.snapshot().values()),
            synthetic_storage_only=True,
            archive_unchanged=True,
        )
    old = fresh(path)
    if number not in (3,):
        op, value = add(old)
    else:
        op, value = row()
    plan = migration(old)
    before = old.snapshot()
    if number in (4, 5, 6, 7):
        point = "migration-" + ("before" if number in (4, 6) else "after") + "-commit"
        if number in (6, 7):
            crash(point, lambda: v2.IssuerJournal.migrate(plan))
        else:

            def fail(where):
                if where == point:
                    raise RuntimeError("simulated interruption")

            v2._fault = fail
            try:
                v2.IssuerJournal.migrate(plan)
            except RuntimeError:
                pass
            else:
                raise AssertionError("fault not reached")
            finally:
                v2._fault = lambda _: None
        if number in (4, 6):
            recovered = v1.IssuerJournal(old.path, old.identity, old.ticket, old.generation)
            assert recovered.snapshot() == before
        else:
            recovered = reopen(old, plan.after)
            assert recovered.snapshot() == before
            rejected(lambda: v1.IssuerJournal(old.path, old.identity, old.ticket, old.generation))
        return dict(
            interruption=point,
            actual_process_exit=number in (6, 7),
            expected_recovery_version=1 if number in (4, 6) else 2,
            rows=len(before),
        )
    if number == 8:
        add(old, 2)
        reason = rejected(lambda: v2.IssuerJournal.migrate(plan))
        assert len(old.snapshot()) == 2
        return dict(expected_rejection=reason, version=1)
    j = v2.IssuerJournal.migrate(plan)
    if number == 3:
        assert j.snapshot() == {}
    elif number == 9:
        for _ in range(3):
            assert reopen(j).snapshot() == before
        assert j.ticket == plan.after
    elif number == 10:
        rejected(lambda: old.transition("intent", lambda r: r.update({row(2)[0]: row(2)[1]})))
        assert j.snapshot() == before
    elif number == 11:
        stale = reopen(j)
        j = j.fence()
        rejected(stale.snapshot)
        rejected(lambda: add(stale, 2))
        assert j.snapshot() == before and j.generation == plan.after[1] + 1
    elif number in (12, 13, 14, 15):
        prepared = j.prepare("intent", lambda rows: rows.update({row(2)[0]: row(2)[1]}))
        point = "commit-" + ("before" if number in (12, 14) else "after") + "-commit"
        if number in (14, 15):
            crash(point, lambda: j.commit(prepared))
        else:

            def fail(where):
                if where == point:
                    raise RuntimeError("simulated interruption")

            v2._fault = fail
            try:
                j.commit(prepared)
            except RuntimeError:
                pass
            else:
                raise AssertionError("fault not reached")
            finally:
                v2._fault = lambda _: None
        expected = prepared.before if number in (12, 14) else prepared.after
        recovered = reopen(j, expected)
        assert len(recovered.snapshot()) == (1 if number in (12, 14) else 2)
        return dict(
            interruption=point,
            actual_process_exit=number in (14, 15),
            committed=expected == prepared.after,
            rows=len(recovered.snapshot()),
            prepared_ticket_retained_before_commit=True,
        )
    elif number == 16:
        prepared = j.prepare("intent", lambda rows: rows.update({row(2)[0]: row(2)[1]}))
        replacement = j.fence()
        rejected(lambda: j.commit(prepared))
        assert replacement.snapshot() == before
    elif number == 17:
        first = j.prepare("intent", lambda rows: rows.update({row(2)[0]: row(2)[1]}))
        peer = reopen(j)
        second = peer.prepare("intent", lambda rows: rows.update({row(3)[0]: row(3)[1]}))
        j.commit(first)
        rejected(lambda: peer.commit(second))
        assert row(3)[0] not in j.snapshot()
    elif number == 18:
        prepared = j.prepare("intent", lambda rows: rows.update({row(2)[0]: row(2)[1]}))
        rejected(lambda: j.commit(replace(prepared, data=encode(row(3)[1]))))
        assert j.snapshot() == before
    elif 19 <= number <= 25:
        with sqlite3.connect(j.path) as c:
            if number == 19:
                c.execute("DELETE FROM v2_records")
            elif number == 20:
                # SQL enforces duplicate primary keys independently of the head chain.
                rejected(lambda: c.execute("INSERT INTO v2_records SELECT * FROM v2_records"))
            elif number == 21:
                c.execute("UPDATE v2_records SET data=?", (b"bad PQL1",))
            elif number == 22:
                c.execute("DELETE FROM v2_events")
            elif number == 23:
                c.execute("UPDATE v2_events SET root=?", (b"z" * 32,))
            elif number == 24:
                c.execute("UPDATE v2_meta SET head=?", (b"z" * 32,))
            elif number == 25:
                c.execute("DELETE FROM v2_legacy_heads WHERE seq=1")
        if number == 20:
            assert j.snapshot() == before
        else:
            rejected(j.snapshot)
    elif number == 26:
        other = list(row(2)[1])
        other[2] = value[2]
        rejected(
            lambda: j.transition("intent", lambda rows: rows.update({row(2)[0]: tuple(other)}))
        )
        assert j.snapshot() == before
    elif number == 27:
        for n in range(2, 6):
            add(j, n)
        collected = []
        cursor = b""
        while True:
            head, values, done = j.page(expected=j.ticket, after=cursor, limit=2)
            assert head == j.ticket
            collected.extend(values)
            if done:
                break
            cursor = values[-1][0]
        assert [k for k, _ in collected] == sorted(j.snapshot()) and len(collected) == 5
        return dict(records=5, pages=3, duplicates=0, missing=0)
    elif number == 28:
        head, values, _ = j.page(expected=j.ticket, limit=1)
        add(j, 2)
        rejected(lambda: j.page(expected=head, after=values[-1][0]))
        rejected(lambda: j.page(expected=j.ticket, limit=5))
    elif number == 29:
        advance(j, op, value)
        for n in range(2, 6):
            op2, val2 = add(j, n)
            advance(j, op2, val2)
        assert sum(len(encode(v)) for v in j.snapshot().values()) > 65536
        assert len(reopen(j).snapshot()) == 5
        return dict(
            rows=5,
            payload_bytes=sum(len(encode(v)) for v in j.snapshot().values()),
            db_bytes=j.path.stat().st_size,
            max_record_bytes=max(len(encode(v)) for v in j.snapshot().values()),
        )
    elif number == 30:
        attempted = (b"CERTIFIED", *value[1:], b"credential")
        rejected(lambda: j.transition("certification", lambda rows: rows.update({op: attempted})))
        rejected(lambda: j.transition("intent", lambda rows: rows.clear()))
        assert j.snapshot() == before
    elif number == 31:
        rejected(lambda: reopen(j, plan.before))
        rejected(lambda: v2.IssuerJournal(j.path, b"J" * 32, j.ticket, j.generation))
        assert j.snapshot() == before
    elif number == 32:
        rejected(
            lambda: j.transition(
                "intent",
                lambda rows: rows.update(
                    {row(2)[0]: (*row(2)[1][:5], b"x" * 65536, None, None, None)}
                ),
            )
        )
        assert j.snapshot() == before
    elif number == 33:
        for n in range(2, 6):
            add(j, n)
        cursor = plan.before[0]
        events = []
        pages = 0
        while True:
            head, page, done = j.history_page(expected=j.ticket, after=cursor, limit=2)
            assert head == j.ticket
            events.extend(page)
            pages += 1
            if done:
                break
            cursor = page[-1][0]
        assert [e[0] for e in events] == list(range(plan.before[0] + 1, j.ticket[0] + 1))
        assert events[-1][-1] == j.ticket[2] and pages == 3
        rejected(lambda: j.history_page(expected=j.ticket, after=0))
        rejected(lambda: j.history_page(expected=j.ticket, after=cursor, limit=17))
        return dict(events=len(events), pages=pages, missing=0, duplicates=0)
    elif number == 34:
        certified = advance(j, op, value)
        op2, value2 = add(j, 2)
        after = j.snapshot()
        duplicate = (b"RESERVED", *value2[1:6], certified[6], b"p" * 960, b"s" * 3427)
        rejected(lambda: j.transition("reservation", lambda r: r.update({op2: duplicate})))
        assert j.snapshot() == after
    elif number == 35:
        with sqlite3.connect(j.path) as c:
            c.execute("CREATE TABLE unrelated (data BLOB)")
        rejected(j.snapshot)
    else:
        raise AssertionError(number)
    return dict(check=number, rows=len(before), expected_state_asserted=True)
