"""Isolated reference holder persistence; not a production wallet.

No proof interface. The trusted local owner retains Head/Plan outside this store.
A store plus its own head is not independent recovery evidence. Synthetic material
only: no encryption-at-rest, erasure, hostile-owner isolation or power-loss claim.
"""

import hashlib
import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from pqdid.credentials import cred_valid, decode_credential, encode_credential
from pqdid.holder_lifecycle import HolderSnapshot, ReferenceHolderLifecycle
from pqdid.parameters import encode_parameters
from pqdid.persistence.codec import CAP, Unavailable, decode, encode, require
from pqdid.persistence.sqlite_store import SETTINGS
from pqdid.statements import decode_state, encode_state
from pqdid.witness_updates import DEFAULT_UPDATE_LIMITS, UpdateStatus, update_authentication_witness
from pqdid.witnesses import decode_auth_witness, encode_auth_witness

SCHEMA = (
    "CREATE TABLE wallet (id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB NOT NULL, "
    "seq INTEGER NOT NULL, generation INTEGER NOT NULL, previous BLOB NOT NULL, "
    "head BLOB NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=65536))"
)
MAX_COUNTER = (1 << 63) - 1


def _fault(_point):
    """Inert; replaced only by the isolated fixture process, never request data."""


def _hash(value):
    return hashlib.sha256(encode(value)).digest()


@dataclass(frozen=True)
class Head:
    identity: bytes
    sequence: int
    generation: int
    digest: bytes

    def __post_init__(self):
        require(type(self.identity) is bytes and len(self.identity) == 32, "head-identity")
        require(type(self.digest) is bytes and len(self.digest) == 32, "head-digest")
        for value in (self.sequence, self.generation):
            require(type(value) is int and 1 <= value <= MAX_COUNTER, "head-counter")


@dataclass(frozen=True, repr=False)
class Plan:
    """Private owner intent retained before COMMIT, allowing exact lost-reply lookup.

    Preparing is not publication or a successful update. Committing revalidates the
    complete transition, counters and current head; this object grants no trust.
    """

    before: Head
    after: Head
    target: object
    records: tuple
    recovery: bool = False


class Wallet:
    def __init__(self, parameters, path, owner_id):
        require(type(owner_id) is bytes and len(owner_id) == 32, "owner-identity")
        self.parameters, self.path = parameters, Path(path)
        self.identity = _hash((b"holder-wallet-v1", encode_parameters(parameters), owner_id))
        self.head = None

    def _paths(self):
        p = self.path
        require(p.is_absolute() and p.resolve() == p, "wallet-path")
        require(all(not x.is_symlink() for x in (p, *p.parents)), "wallet-symlink")
        info = p.parent.stat()
        require(stat.S_ISDIR(info.st_mode), "wallet-parent")
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "owner-mode")
        total = 0
        for entry in p.parent.iterdir():
            require(entry.name in (p.name, p.name + "-journal"), "wallet-sidecar")
            st = entry.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "wallet-regular-file")
            require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600, "file-mode")
            require(st.st_size <= 512 * 1024, "wallet-file-cap")
            total += st.st_size
        require(total <= 1024 * 1024, "wallet-store-cap")

    @contextmanager
    def _connection(self, *, creating=False):
        c = None
        try:
            self._paths()
            c = sqlite3.connect(
                self.path.as_uri() + "?mode=rw&cache=private",
                uri=True,
                timeout=0,
                autocommit=True,
            )
            c.enable_load_extension(False)
            for key, limit in (
                (sqlite3.SQLITE_LIMIT_LENGTH, 256 * 1024),
                (sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16 * 1024),
                (sqlite3.SQLITE_LIMIT_ATTACHED, 0),
            ):
                c.setlimit(key, limit)
                require(c.getlimit(key) == limit, "sqlite-limit")
            require(c.execute("PRAGMA journal_mode").fetchone() == ("delete",), "journal-mode")
            for key, value in SETTINGS.items():
                c.execute(f"PRAGMA {key}={value}")  # Existing fixed policy, no caller SQL.
                require(c.execute(f"PRAGMA {key}").fetchone() == (value,), "sqlite-setting")
            steps = 0

            def progress():
                nonlocal steps
                steps += 100
                return int(steps >= 100000)

            c.set_progress_handler(progress, 100)
            if not creating:
                require(c.execute("PRAGMA user_version").fetchone() == (1,), "wallet-version")
                require(
                    c.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
                    == [(SCHEMA,)],
                    "wallet-schema",
                )
            yield c
        except sqlite3.Error, OSError:
            raise Unavailable("wallet-storage-unavailable") from None
        finally:
            if c is not None:
                try:
                    if c.in_transaction:
                        c.execute("ROLLBACK")
                finally:
                    c.close()

    def _payload(self, value):
        require(type(value) is HolderSnapshot, "snapshot-type")
        credential, witness, state = value.credential, value.witness, value.state
        require(
            witness.attributes == credential.attributes
            and witness.revocation_identifier == credential.revocation_identifier
            and witness.signature == credential.certificate.signature,
            "credential-witness-binding",
        )
        require(
            cred_valid(self.parameters, credential, witness.holder_secret), "credential-invalid"
        )
        checked = update_authentication_witness(self.parameters, witness, state, state, ())
        require(checked.status is UpdateStatus.UPDATED, "snapshot-invalid")
        return encode(
            (
                b"holder-wallet-v1",
                encode_credential(self.parameters, credential),
                encode_auth_witness(self.parameters.schema, witness),
                encode_state(self.parameters, state),
            )
        )

    def _decode(self, data):
        require(type(data) is bytes and len(data) <= CAP, "wallet-payload")
        values = decode(data)
        require(
            type(values) is tuple and len(values) == 4 and values[0] == b"holder-wallet-v1",
            "wallet-payload-shape",
        )
        value = HolderSnapshot(
            decode_credential(self.parameters, values[1]),
            decode_auth_witness(self.parameters.schema, values[2]),
            decode_state(self.parameters, values[3]),
        )
        require(self._payload(value) == data, "wallet-canonical")
        return value

    def _next(self, before, payload, *, recovery=False):
        sequence, generation = before.sequence + 1, before.generation + int(recovery)
        return Head(
            self.identity,
            sequence,
            generation,
            _hash((self.identity, sequence, generation, before.digest, payload)),
        )

    def _load(self, c, expected):
        require(type(expected) is Head and expected.identity == self.identity, "expected-head")
        rows = c.execute(
            "SELECT identity,seq,generation,previous,head,payload FROM wallet WHERE id=1"
        ).fetchall()
        require(len(rows) == 1, "incomplete-wallet")
        identity, seq, generation, previous, head, payload = rows[0]
        actual = Head(identity, seq, generation, head)
        require(actual == expected, "stale-or-fenced-wallet")
        require(type(previous) is bytes and len(previous) in (0, 32), "previous-head")
        require(_hash((identity, seq, generation, previous, payload)) == head, "wallet-head")
        return self._decode(payload)

    @classmethod
    def create(cls, parameters, path, owner_id, accepted, holder_secret):
        value = ReferenceHolderLifecycle(parameters, accepted, holder_secret).snapshot()
        wallet = cls(parameters, path, owner_id)
        payload = wallet._payload(value)
        wallet._paths()
        require(not wallet.path.exists(), "wallet-already-exists")
        fd = os.open(wallet.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        head = Head(wallet.identity, 1, 1, _hash((wallet.identity, 1, 1, b"", payload)))
        with wallet._connection(creating=True) as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute(SCHEMA)
            c.execute("PRAGMA user_version=1")
            c.execute(
                "INSERT INTO wallet VALUES (1,?,?,?,?,?,?)",
                (wallet.identity, 1, 1, b"", head.digest, payload),
            )
            _fault("before-commit")
            c.execute("COMMIT")
        _fault("after-commit-before-response")
        wallet.head = head
        return wallet

    def snapshot(self, expected=None):
        """Exact committed retrieval; no fresh eligibility claim and no auto-admission."""
        with self._connection() as c:
            c.execute("BEGIN")
            return self._load(c, self.head if expected is None else expected)

    def prepare_recovery(self, expected, current_state, records=()):
        """Owner supplies independent head and freshly authenticated expected state.

        A stale wallet does not silently become current. Catch-up must be an explicit
        validated transition under a retained prior head, then this admission step.
        """
        require(type(records) is tuple, "recovery-records")
        value = self.snapshot(expected)
        result = update_authentication_witness(
            self.parameters,
            value.witness,
            value.state,
            current_state,
            records,
            limits=DEFAULT_UPDATE_LIMITS,
        )
        require(result.status is UpdateStatus.UPDATED, "stale-or-invalid-recovered-state")
        new = HolderSnapshot(value.credential, result.witness, result.state)
        return Plan(
            expected,
            self._next(expected, self._payload(new), recovery=True),
            current_state,
            records,
            True,
        )

    def prepare_update(self, expected, target, records):
        require(type(records) is tuple, "update-records")
        value = self.snapshot(expected)
        result = update_authentication_witness(
            self.parameters,
            value.witness,
            value.state,
            target,
            records,
            limits=DEFAULT_UPDATE_LIMITS,
        )
        if result.status is not UpdateStatus.UPDATED:
            return result, None
        new = HolderSnapshot(value.credential, result.witness, result.state)
        return result, Plan(expected, self._next(expected, self._payload(new)), target, records)

    def commit(self, plan):
        require(type(plan) is Plan and type(plan.recovery) is bool, "wallet-plan")
        # All publication candidates remain holder-private. Recheck under the writer lock.
        with self._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            value = self._load(c, plan.before)
            if not plan.recovery:
                require(self.head == plan.before, "inactive-or-fenced-writer")
            require(type(plan.records) is tuple, "plan-records")
            result = update_authentication_witness(
                self.parameters,
                value.witness,
                value.state,
                plan.target,
                plan.records,
                limits=DEFAULT_UPDATE_LIMITS,
            )
            require(result.status is UpdateStatus.UPDATED, "update-rejected")
            value = HolderSnapshot(value.credential, result.witness, result.state)
            payload = self._payload(value)
            require(
                self._next(plan.before, payload, recovery=plan.recovery) == plan.after,
                "plan-binding",
            )
            c.execute(
                "UPDATE wallet SET seq=?,generation=?,previous=?,head=?,payload=? WHERE id=1",
                (
                    plan.after.sequence,
                    plan.after.generation,
                    plan.before.digest,
                    plan.after.digest,
                    payload,
                ),
            )
            _fault("before-commit")
            c.execute("COMMIT")
        self.head = None  # A lost reply cannot leave this instance apparently admitted.
        _fault("after-commit-before-response")
        self.head = plan.after
        return self.head
