"""Role-owned SQLite transactions. Public access is authorised; SQL remains private.

Process-crash durability assumes an intact authority database and honest storage.
This module does not sandbox its owner or detect coordinated database rollback.
"""

import hashlib
import os
import socket
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

from pqdid.recovery import Admission, RecoveredService, RecoveryEvidence
from pqdid.recovery_records import checkpoint_digest

from .codec import CAP, Unavailable, decode, encode, require
from .records import MAX_COUNTER, DenyAll, HeadTicket, Outcome, WriterPermit

SETTINGS = {
    "journal_mode": "delete",
    "synchronous": 3,
    "locking_mode": "normal",
    "foreign_keys": 1,
    "read_uncommitted": 0,
    "busy_timeout": 0,
    "temp_store": 2,
    "mmap_size": 0,
    "cache_size": -2048,
    "page_size": 4096,
    "max_page_count": 128,
}
SCHEMA = (
    "CREATE TABLE service (id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB NOT NULL, "
    "generation INTEGER NOT NULL CHECK(generation>=0), writer BLOB NOT NULL, tip INTEGER NOT NULL)",
    "CREATE TABLE checkpoints (digest BLOB PRIMARY KEY CHECK(length(digest)=32), "
    "data BLOB NOT NULL CHECK(length(data)<=65536))",
    "CREATE TABLE operations (id BLOB PRIMARY KEY CHECK(length(id)=32), request BLOB NOT NULL, "
    "decision BLOB NOT NULL, response BLOB NOT NULL CHECK(length(response)<=65536))",
    "CREATE TABLE heads (seq INTEGER PRIMARY KEY CHECK(seq>0), digest BLOB UNIQUE NOT NULL, "
    "previous BLOB NOT NULL, checkpoint BLOB NOT NULL REFERENCES checkpoints(digest), "
    "operation BLOB UNIQUE REFERENCES operations(id), generation INTEGER NOT NULL, "
    "entries BLOB NOT NULL)",
    "CREATE TABLE entries (key BLOB PRIMARY KEY CHECK(length(key)<=256), "
    "data BLOB NOT NULL CHECK(length(data)<=65536))",
)


def digest(value):
    return hashlib.sha256(encode(value)).digest()


def _fault(_point):
    """Inert application boundary, replaced only by the isolated test worker."""


class _Evidence:
    def __init__(self, key, expected):
        self.key, self.expected = key, expected

    @contextmanager
    def exclusive(self, binding):
        require(binding.checkpoint_digest == self.expected)
        yield RecoveryEvidence(self.key.authority_id, binding)


class SQLiteStore:
    def __init__(self, path, key, *, dependencies, authorisation=None):
        self._path, self.key = Path(path), key
        self._identity = encode(key.identity())
        self._deps = dependencies
        self._policy = authorisation if authorisation is not None else DenyAll()

    def _authorise(self, principal, action):
        require(type(principal) is bytes and 1 <= len(principal) <= 256, "principal")
        require(self._policy.allow(self.key, principal, action) is True, "unauthorised")

    def _path_check(self):
        path = self._path
        require(path.is_absolute() and path.resolve() == path, "non-canonical-path")
        for component in (path, *path.parents):
            require(not component.is_symlink(), "symlink-path")
        info, parent = path.lstat(), path.parent.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "not-private-file")
        require(stat.S_IMODE(info.st_mode) == 0o600, "file-permissions")
        require(stat.S_IMODE(parent.st_mode) == 0o700, "directory-permissions")
        require(info.st_uid == os.getuid() == parent.st_uid, "store-owner")
        require(info.st_size <= 512 * 1024, "database-cap")
        total = 0
        for entry in path.parent.iterdir():
            require(not entry.is_symlink() and entry.is_file(), "unexpected-storage-entry")
            require(entry.name in {path.name, path.name + "-journal"}, "unexpected-sidecar")
            size = entry.stat().st_size
            require(size <= 512 * 1024, "sidecar-cap")
            total += size
        require(total <= 1024 * 1024, "store-storage-cap")

    @contextmanager
    def _connection(self, *, creating=False):
        connection = None
        try:
            self._path_check()
            connection = sqlite3.connect(
                self._path.as_uri() + "?mode=rw&cache=private",
                uri=True,
                timeout=0,
                autocommit=True,
            )
            connection.enable_load_extension(False)
            for category, limit in (
                (sqlite3.SQLITE_LIMIT_LENGTH, 256 * 1024),
                (sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16 * 1024),
                (sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 64),
                (sqlite3.SQLITE_LIMIT_ATTACHED, 0),
            ):
                connection.setlimit(category, limit)
                require(connection.getlimit(category) == limit, "sqlite-limit")
            require(
                connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete",
                "unexpected-journal-mode",
            )
            for setting, value in SETTINGS.items():
                connection.execute(f"PRAGMA {setting}={value}")  # Constants only.
                require(
                    connection.execute(f"PRAGMA {setting}").fetchone()[0] == value, "sqlite-setting"
                )
            steps = 0

            def progress():
                nonlocal steps
                steps += 100
                return int(steps >= 100000)

            connection.set_progress_handler(progress, 100)
            if not creating:
                require(connection.execute("PRAGMA user_version").fetchone() == (1,), "schema")
                schema = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"
                ).fetchall()
                require(sorted(row[0] for row in schema) == sorted(SCHEMA), "schema")
            yield connection
        except (sqlite3.Error, OSError) as error:
            # No partial success on BUSY/FULL/I/O/uncertain COMMIT; explicit fresh lookup only.
            raise Unavailable("storage-" + type(error).__name__) from None
        finally:
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                finally:
                    connection.close()

    def _validate(self, checkpoint):
        expected = checkpoint_digest(checkpoint)
        facade = RecoveredService(
            self.key.parameters,
            self.key.role,
            self.key.service_id,
            authority_id=self.key.authority_id,
            authority=_Evidence(self.key, expected),
            dependencies=self._deps,
        )
        require(facade.admit(checkpoint) is Admission.ADMITTED, "checkpoint-admission")
        return expected

    def initialise(self, principal, checkpoint):
        """Explicit trusted bootstrap; failure leaves storage quarantined, never recreated."""
        self._authorise(principal, "initialise")
        payload = encode(checkpoint)
        cp = self._validate(checkpoint)
        require(self._path.parent.is_dir() and not self._path.exists(), "already-initialised")
        fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self._connection(creating=True) as c:
            c.execute("BEGIN IMMEDIATE")
            for statement in SCHEMA:
                c.execute(statement)
            c.execute("PRAGMA user_version=1")
            c.execute("INSERT INTO checkpoints VALUES (?,?)", (cp, payload))
            entries = digest(())
            head = digest((1, b"", cp, b"", 0, entries, self._identity))
            c.execute(
                "INSERT INTO heads VALUES (?,?,?,?,?,?,?)", (1, head, b"", cp, None, 0, entries)
            )
            c.execute("INSERT INTO service VALUES (1,?,0,?,1)", (self._identity, b""))
            c.execute("COMMIT")
        return HeadTicket(1, head, cp, 0)

    def _load(self, c):
        require(c.execute("PRAGMA quick_check").fetchall() == [("ok",)], "integrity")
        require(not c.execute("PRAGMA foreign_key_check").fetchall(), "missing-reference")
        service = c.execute(
            "SELECT identity,generation,writer,tip FROM service WHERE id=1"
        ).fetchone()
        require(service is not None and service[0] == self._identity, "service-binding")
        require(0 <= service[1] <= MAX_COUNTER and 1 <= service[3] <= MAX_COUNTER, "counter")
        operations = c.execute("SELECT id,request,decision,response FROM operations").fetchall()
        heads = c.execute("SELECT * FROM heads ORDER BY seq").fetchall()
        require(len(operations) <= 128 and len(heads) == len(operations) + 1, "row-cap-or-gap")
        ops = {row[0]: row[1:] for row in operations}
        previous = b""
        for seq, head, prev, cp, op, generation, entries_hash in heads:
            require(prev == previous and 1 <= seq <= MAX_COUNTER, "head-chain")
            commitment = b"" if op is None else digest((op, *ops[op]))
            require(
                head
                == digest((seq, prev, cp, commitment, generation, entries_hash, self._identity)),
                "head-digest",
            )
            previous = head
        require(heads[-1][0] == service[3] and heads[-1][5] == service[1], "head-tip")
        rows = c.execute("SELECT key,data FROM entries ORDER BY key").fetchall()
        require(len(rows) <= 128 and digest(tuple(rows)) == heads[-1][6], "entry-integrity")
        payload = c.execute(
            "SELECT data FROM checkpoints WHERE digest=?", (heads[-1][3],)
        ).fetchone()
        require(payload is not None, "missing-checkpoint")
        checkpoint = decode(payload[0])
        require(checkpoint_digest(checkpoint) == heads[-1][3], "checkpoint-digest")
        return (
            HeadTicket(service[3], heads[-1][1], heads[-1][3], service[1]),
            checkpoint,
            {key: decode(data) for key, data in rows},
            service[2],
            ops,
        )

    def inspect(self, principal):
        self._authorise(principal, "read")
        with self._connection() as c:
            c.execute("BEGIN")
            ticket, checkpoint, entries, _, _ = self._load(c)
            self._validate(checkpoint)
            return ticket, checkpoint, entries

    def admit(self, permit, expected):
        self._authorise(permit.principal, "write")
        with self._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            ticket, checkpoint, _, writer, _ = self._load(c)
            require(ticket == expected, "stale-head")
            self._fence(permit, ticket, writer)
            self._validate(checkpoint)
        return ticket

    @staticmethod
    def _fence(permit, ticket, writer):
        require(
            permit.generation > 0
            and permit.generation == ticket.generation
            and permit.principal == writer,
            "fenced-writer",
        )

    def _write(
        self, c, ticket, checkpoint, entries, op, request, decision, response, generation, writer
    ):
        require(ticket.sequence < MAX_COUNTER and generation <= MAX_COUNTER, "counter-exhausted")
        require(c.execute("SELECT count(*) FROM operations").fetchone()[0] < 128, "operation-cap")
        require(len(entries) <= 128, "entry-cap")
        payload, cp = encode(checkpoint), self._validate(checkpoint)
        rows = tuple((key, encode(value)) for key, value in sorted(entries.items()))
        entries_hash = digest(rows)
        require(len(response) <= CAP and len(request) <= CAP, "payload-cap")
        sequence = ticket.sequence + 1
        head = digest(
            (
                sequence,
                ticket.digest,
                cp,
                digest((op, request, decision, response)),
                generation,
                entries_hash,
                self._identity,
            )
        )
        c.execute("INSERT OR IGNORE INTO checkpoints VALUES (?,?)", (cp, payload))
        c.execute("INSERT INTO operations VALUES (?,?,?,?)", (op, request, decision, response))
        c.execute("DELETE FROM entries")
        c.executemany("INSERT INTO entries VALUES (?,?)", rows)
        c.execute(
            "INSERT INTO heads VALUES (?,?,?,?,?,?,?)",
            (sequence, head, ticket.digest, cp, op, generation, entries_hash),
        )
        c.execute(
            "UPDATE service SET generation=?,writer=?,tip=? WHERE id=1",
            (generation, writer, sequence),
        )
        _fault("rows-before-commit")
        c.execute("COMMIT")
        _fault("commit-before-ack")
        return Outcome(op, decision, response, HeadTicket(sequence, head, cp, generation))

    def acquire(self, admin, operation, expected, writer):
        self._authorise(admin, "replace")
        self._authorise(writer, "write")
        require(type(operation) is bytes and len(operation) == 32)
        request = encode((b"grant", admin, expected.record(), writer))
        with self._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            ticket, cp, entries, current_writer, ops = self._load(c)
            if operation in ops:
                require(ops[operation][0] == request, "operation-conflict")
                require(
                    ticket.generation == expected.generation + 1 and current_writer == writer,
                    "superseded-grant",
                )
                return WriterPermit(writer, ticket.generation), ticket
            require(ticket == expected and ticket.generation < MAX_COUNTER, "stale-or-exhausted")
            result = self._write(
                c,
                ticket,
                cp,
                entries,
                operation,
                request,
                b"GRANTED",
                b"",
                ticket.generation + 1,
                writer,
            )
            return WriterPermit(writer, result.ticket.generation), result.ticket

    def _transition(self, permit, expected, operation, kind, arguments, prepare):
        self._authorise(permit.principal, "write")
        require(type(operation) is bytes and len(operation) == 32)
        request = encode((kind, permit.principal, expected.record(), arguments))
        _fault("before-begin")
        with self._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            _fault("after-begin")
            ticket, cp, entries, writer, ops = self._load(c)
            self._fence(permit, ticket, writer)
            if operation in ops:
                old_request, decision, response = ops[operation]
                require(old_request == request, "operation-conflict")
                return Outcome(operation, b"ALREADY_COMMITTED", response, ticket, True)
            require(ticket == expected, "stale-head")
            checkpoint, new_entries, decision, response = prepare(cp, dict(entries))
            return self._write(
                c,
                ticket,
                checkpoint,
                new_entries,
                operation,
                request,
                decision,
                response,
                ticket.generation,
                writer,
            )

    def publish(self, permit, expected, operation, recipient, transport):
        """One nonblocking SEQPACKET enqueue under writer lock; no new protocol effect.

        Owner supplies an already authenticated recipient channel. Production policy
        is intentionally absent. Verifier acceptance outcomes cannot be redelivered.
        """
        self._authorise(permit.principal, "write")
        self._authorise(recipient, "retrieve")
        require(type(transport) is socket.socket and not transport.getblocking(), "transport")
        require(
            transport.family == socket.AF_UNIX and transport.type == socket.SOCK_SEQPACKET,
            "transport",
        )
        with self._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            ticket, _, _, writer, ops = self._load(c)
            self._fence(permit, ticket, writer)
            require(ticket == expected, "stale-publication")
            require(operation in ops, "missing-outcome")
            request, decision, response = ops[operation]
            require(decision == b"CERTIFIED", "not-releasable")
            require(decode(request)[3][-1] == recipient, "wrong-recipient")
            _fault("before-enqueue")
            sent = transport.send(response, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            require(sent == len(response), "incomplete-publication")
            _fault("enqueue-before-return")
        return b"REDELIVERY"

    def runtime(self, principal):
        self._authorise(principal, "read")
        with self._connection() as c:
            return {
                "sqlite": sqlite3.sqlite_version,
                "source_id": c.execute("SELECT sqlite_source_id()").fetchone()[0],
                "settings": {name: c.execute(f"PRAGMA {name}").fetchone()[0] for name in SETTINGS},
            }
