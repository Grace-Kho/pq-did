"""Bounded synthetic local persistence; not custody or whole-store rollback defence."""

import hashlib
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

from pqdid.persistence.codec import decode, encode

from .records import CAP, octets, require
from .signing import Key

DATABASE_BYTES = 512 * 1024


def _fault(_point):
    """Inert; isolated tests may replace this module symbol, never a request option."""


def directory(path, *, create=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "canonical-private-path")
    require(all(not p.is_symlink() for p in (path, *path.parents)), "symlink-path")
    if create:
        path.mkdir(mode=0o700, parents=False)
    info = path.stat()
    require(
        stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, "private-directory-mode"
    )
    require(info.st_uid == os.getuid(), "private-directory-owner")
    return path


def private_file(path, maximum=CAP):
    directory(path.parent)
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1,
        "private-regular-file",
    )
    require(
        info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
        "private-file-owner-mode",
    )
    require(info.st_size <= maximum, "private-file-cap")


def read_private(path):
    path = Path(path)
    private_file(path)
    with path.open("rb") as stream:
        value = stream.read(CAP + 1)
    return octets(value)


def write_private(path, payload, *, fresh=False):
    path = Path(path)
    octets(payload)
    directory(path.parent)
    if fresh:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return
    private_file(path)
    temporary = path.with_name(path.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_key(path, key):
    write_private(path, encode((b"synthetic-holder-key-v1", key.public, key.secret)), fresh=True)


def read_key(path):
    from pqdid.bounded_mldsa_sign import reference_public_key_mldsa65

    values = decode(read_private(path))
    require(
        type(values) is tuple and len(values) == 3 and values[0] == b"synthetic-holder-key-v1",
        "key-file-shape",
    )
    reference_public_key_mldsa65(values[2], expected_public_key=values[1])
    return Key(values[1], values[2])


class IssuerJournal:
    """Independent expected ticket/generation required at every transaction/reopen.

    The head covers the complete ordered baseline session set and previous head.
    A trusted operator retains tickets outside this database. File contents alone
    never authorise recovered writes. Faults after COMMIT may leave a stale caller.
    """

    def __init__(self, path, identity, expected, generation):
        self.path, self.identity = Path(path), octets(identity, 32)
        self.ticket, self.generation = expected, generation
        self.snapshot()

    @classmethod
    def create(cls, path, identity):
        path = Path(path)
        directory(path.parent)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        initial = hashlib.sha256(encode((identity, 1, 1, b"", ()))).digest()
        with sqlite3.connect(path, autocommit=True) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB, "
                "seq INTEGER, generation INTEGER, head BLOB, previous BLOB)"
            )
            connection.execute(
                "CREATE TABLE sessions (operation BLOB PRIMARY KEY, data BLOB NOT NULL)"
            )
            connection.execute("CREATE TABLE heads (seq INTEGER PRIMARY KEY, digest BLOB NOT NULL)")
            connection.execute(
                "INSERT INTO meta VALUES (1,?,?,?,?,?)", (identity, 1, 1, initial, b"")
            )
            connection.execute("INSERT INTO heads VALUES (1,?)", (initial,))
            connection.execute("PRAGMA user_version=1")
            connection.execute("COMMIT")
        return cls(path, identity, (1, 1, initial), 1)

    @contextmanager
    def _connection(self):
        private_file(self.path, DATABASE_BYTES)
        entries = list(self.path.parent.iterdir())
        require(
            all(p.name in {self.path.name, self.path.name + "-journal"} for p in entries),
            "issuer-unexpected-sidecar",
        )
        require(sum(p.stat().st_size for p in entries) <= 2 * DATABASE_BYTES, "issuer-storage-cap")
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=rw", uri=True, timeout=0, autocommit=True
        )
        try:
            connection.enable_load_extension(False)
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 256 * 1024)
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            for name, value in (
                ("journal_mode", "delete"),
                ("synchronous", 3),
                ("temp_store", 2),
                ("mmap_size", 0),
                ("max_page_count", 128),
                ("cache_size", -2048),
                ("busy_timeout", 0),
            ):
                connection.execute(f"PRAGMA {name}={value}")
                require(
                    connection.execute(f"PRAGMA {name}").fetchone()[0] == value,
                    "issuer-sqlite-setting",
                )
            require(connection.execute("PRAGMA user_version").fetchone() == (1,), "issuer-schema")
            steps = 0

            def progress():
                nonlocal steps
                steps += 100
                return int(steps >= 100000)

            connection.set_progress_handler(progress, 100)
            yield connection
        finally:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()

    def _load(self, connection):
        meta = connection.execute(
            "SELECT identity,seq,generation,head,previous FROM meta WHERE id=1"
        ).fetchone()
        require(meta is not None and meta[0] == self.identity, "issuer-identity")
        rows = connection.execute(
            "SELECT operation,data FROM sessions ORDER BY operation LIMIT 65"
        ).fetchall()
        require(len(rows) <= 64, "issuer-session-cap")
        records = tuple((octets(op, 32), octets(data)) for op, data in rows)
        expected = hashlib.sha256(
            encode((self.identity, meta[1], meta[2], meta[4], records))
        ).digest()
        require(expected == meta[3], "issuer-content-head")
        require(
            connection.execute("SELECT COUNT(*),MAX(seq) FROM heads").fetchone()
            == (meta[1], meta[1]),
            "issuer-head-sequence",
        )
        require(
            connection.execute("SELECT digest FROM heads WHERE seq=?", (meta[1],)).fetchone()
            == (meta[3],),
            "issuer-head-record",
        )
        if meta[1] > 1:
            require(
                connection.execute(
                    "SELECT digest FROM heads WHERE seq=?", (meta[1] - 1,)
                ).fetchone()
                == (meta[4],),
                "issuer-predecessor",
            )
        ticket = (meta[1], meta[2], meta[3])
        require(ticket == self.ticket and meta[2] == self.generation, "issuer-stale-or-fenced")
        return ticket, {op: decode(data) for op, data in records}

    def snapshot(self):
        with self._connection() as connection:
            return self._load(connection)[1]

    def transition(self, phase, prepare):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            ticket, rows = self._load(connection)
            prepare(rows)
            require(len(rows) <= 64, "issuer-session-cap")
            records = tuple(sorted((octets(k, 32), octets(encode(v))) for k, v in rows.items()))
            seq, generation = ticket[0] + 1, ticket[1]
            head = hashlib.sha256(
                encode((self.identity, seq, generation, ticket[2], records))
            ).digest()
            connection.execute("DELETE FROM sessions")
            connection.executemany("INSERT INTO sessions VALUES (?,?)", records)
            connection.execute(
                "UPDATE meta SET seq=?,head=?,previous=? WHERE id=1", (seq, head, ticket[2])
            )
            connection.execute("INSERT INTO heads VALUES (?,?)", (seq, head))
            _fault(phase + "-before-commit")
            connection.execute("COMMIT")
            _fault(phase + "-after-commit")
        self.ticket = (seq, generation, head)

    def fence(self):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            old, rows = self._load(connection)
            seq, generation = old[0] + 1, old[1] + 1
            records = tuple(sorted((k, encode(v)) for k, v in rows.items()))
            head = hashlib.sha256(
                encode((self.identity, seq, generation, old[2], records))
            ).digest()
            connection.execute(
                "UPDATE meta SET seq=?,generation=?,head=?,previous=? WHERE id=1",
                (seq, generation, head, old[2]),
            )
            connection.execute("INSERT INTO heads VALUES (?,?)", (seq, head))
            connection.execute("COMMIT")
        return IssuerJournal(self.path, self.identity, (seq, generation, head), generation)
