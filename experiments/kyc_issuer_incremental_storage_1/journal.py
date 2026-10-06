"""Version-2 local issuer journal, isolated reference implementation.

Per-record PQL1 and all wire limits are unchanged. Ordered leaf digests, never the
aggregate payload set, form the local root. Independent expected tickets remain
mandatory. No hostile-owner, whole-store rollback or power-loss assurance.
"""

import hashlib
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from experiments.kyc_milestone_1.baseline import storage as v1
from experiments.kyc_milestone_1.baseline.records import octets
from pqdid.persistence.codec import Unavailable, decode, encode, require
from pqdid.persistence.sqlite_store import SETTINGS

MAX_ROWS = 64
MAX_EVENTS = 512
PHASES = {b"INTENT", b"RESERVED", b"SIGNING", b"CERTIFIED"}
SCHEMA = (
    (
        "CREATE TABLE v2_meta (id INTEGER PRIMARY KEY CHECK(id=1), identi"
        "ty BLOB NOT NULL, seq INTEGER NOT NULL, generation INTEGER NOT N"
        "ULL, head BLOB NOT NULL, origin_seq INTEGER NOT NULL, origin_gen"
        " INTEGER NOT NULL, anchor BLOB NOT NULL, legacy BLOB NOT NULL)"
    ),
    (
        "CREATE TABLE v2_records (operation BLOB PRIMARY KEY CHECK(length"
        "(operation)=32), data BLOB NOT NULL CHECK(length(data)<=65536), "
        "digest BLOB NOT NULL CHECK(length(digest)=32))"
    ),
    (
        "CREATE TABLE v2_base (operation BLOB PRIMARY KEY CHECK(length(op"
        "eration)=32), digest BLOB NOT NULL CHECK(length(digest)=32))"
    ),
    (
        "CREATE TABLE v2_events (seq INTEGER PRIMARY KEY, previous BLOB N"
        "OT NULL, generation INTEGER NOT NULL, operation BLOB NOT NULL, p"
        "hase TEXT NOT NULL, old BLOB NOT NULL, new BLOB NOT NULL, root B"
        "LOB NOT NULL, count INTEGER NOT NULL, head BLOB NOT NULL)"
    ),
    (
        "CREATE TABLE v2_legacy_heads (seq INTEGER PRIMARY KEY, digest BL"
        "OB NOT NULL CHECK(length(digest)=32))"
    ),
)


def _fault(_point):
    "Test-process-only fault boundary; no request option or production activation."


def hashed(tag, value):
    return hashlib.sha256(b"pqdid/local-issuer-v2/" + tag + b"\0" + encode(value)).digest()


def leaf(operation, data):
    octets(operation, 32)
    octets(data)
    # Framing is explicit, and data is already bounded. No aggregate encode(data).
    h = hashlib.sha256(b"pqdid/local-issuer-v2/leaf\0" + operation + len(data).to_bytes(4))
    h.update(data)
    return h.digest()


def root(leaves):
    require(len(leaves) <= MAX_ROWS, "issuer-session-cap")
    h = hashlib.sha256(b"pqdid/local-issuer-v2/root\0" + len(leaves).to_bytes(4))
    for operation, digest in sorted(leaves.items()):
        h.update(octets(operation, 32))
        h.update(octets(digest, 32))
    return h.digest()


def validate_record(operation, data):
    value = decode(octets(data))
    require(encode(value) == data, "noncanonical-row")
    require(type(value) is tuple and len(value) in (9, 10), "row-shape")
    phase, session, nonce, key, attrs, recipient, rid, path, state = value[:9]
    require(type(phase) is bytes and phase in PHASES, "row-phase")
    octets(session, 32)
    octets(nonce, 32)
    octets(key, 1952)
    octets(attrs, 1024)
    require(type(recipient) is bytes and 1 <= len(recipient) <= 256, "recipient")
    require(operation == hashlib.sha256(b"baseline-issue" + session).digest(), "session-binding")
    require(len(value) == (10 if phase == b"CERTIFIED" else 9), "row-arity")
    if phase == b"INTENT":
        require((rid, path, state) == (None, None, None), "premature-reservation")
    else:
        require(type(rid) is int and 0 <= rid < 1 << 20, "identifier")
        octets(path, 960)
        octets(state, 3427)
    if phase == b"CERTIFIED":
        octets(value[9])
    return value


def validate_set(rows):
    require(len(rows) <= MAX_ROWS, "issuer-session-cap")
    nonces, ids = set(), set()
    for op, value in rows.items():
        validate_record(op, encode(value))
        require(value[2] not in nonces, "duplicate-nonce")
        nonces.add(value[2])
        if value[6] is not None:
            require(value[6] not in ids, "duplicate-identifier")
            ids.add(value[6])


def transition_shape(phase, before, after):
    require(phase in ("intent", "reservation", "claim", "certification"), "transition-phase")
    if phase == "intent":
        require(before is None and after[0] == b"INTENT", "intent-transition")
    else:
        expected = {
            "reservation": (b"INTENT", b"RESERVED"),
            "claim": (b"RESERVED", b"SIGNING"),
            "certification": (b"SIGNING", b"CERTIFIED"),
        }[phase]
        require(before is not None and (before[0], after[0]) == expected, "phase-order")
        require(before[1:6] == after[1:6], "intent-mutation")
        if phase in ("claim", "certification"):
            require(before[1:9] == after[1:9], "reservation-mutation")


def ticket(value):
    require(type(value) is tuple and len(value) == 3, "ticket")
    require(all(type(x) is int and 1 <= x < 1 << 63 for x in value[:2]), "ticket-counter")
    octets(value[2], 32)
    return value


@dataclass(frozen=True, repr=False)
class Prepared:
    before: tuple
    after: tuple
    phase: str
    operation: bytes
    data: bytes
    event: tuple


@dataclass(frozen=True, repr=False)
class Migration:
    path: Path
    identity: bytes
    before: tuple
    after: tuple
    origin: tuple
    event: tuple


class IssuerJournal:
    def __init__(self, path, identity, expected, generation):
        self.path, self.identity = Path(path), octets(identity, 32)
        self.ticket, self.generation = ticket(expected), generation
        require(type(generation) is int and generation == expected[1], "generation")
        self.pending = None
        self.snapshot()

    @staticmethod
    def _legacy_hash(rows):
        h = hashlib.sha256(b"pqdid/local-issuer-v2/legacy\0")
        require(len(rows) <= 8192, "legacy-head-bound")
        for index, (seq, digest) in enumerate(rows, 1):
            require(seq == index, "legacy-head-gap")
            h.update(seq.to_bytes(8))
            h.update(octets(digest, 32))
        return h.digest()

    @staticmethod
    def _event(identity, origin, seq, previous, generation, operation, phase, old, new, leaves):
        ticket((seq, generation, previous))
        state = (seq, previous, generation, operation, phase, old, new, root(leaves), len(leaves))
        digest = hashed(b"head", (identity, origin, *state[:4], phase.encode(), *state[5:]))
        return (*state, digest)

    @classmethod
    def migration_plan(cls, path, identity, expected, generation):
        old = v1.IssuerJournal(path, identity, expected, generation)
        with old._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            _, rows = old._load(c)
            legacy = c.execute("SELECT seq,digest FROM heads ORDER BY seq").fetchall()
            leaves = {}
            for op, value in rows.items():
                data = encode(value)
                validate_record(op, data)
                leaves[op] = leaf(op, data)
            validate_set(rows)
            origin = (expected[0], expected[1], expected[2], cls._legacy_hash(legacy))
            event = cls._event(
                identity,
                origin,
                expected[0] + 1,
                expected[2],
                generation + 1,
                b"",
                "MIGRATE",
                b"",
                b"",
                leaves,
            )
            return Migration(
                Path(path), identity, expected, (event[0], event[2], event[-1]), origin, event
            )

    @classmethod
    def migrate(cls, plan):
        require(type(plan) is Migration, "migration-plan")
        old = v1.IssuerJournal(plan.path, plan.identity, plan.before, plan.before[1])
        with old._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            _, rows = old._load(c)
            legacy = c.execute("SELECT seq,digest FROM heads ORDER BY seq").fetchall()
            origin = (plan.before[0], plan.before[1], plan.before[2], cls._legacy_hash(legacy))
            leaves, records = {}, []
            for op, value in rows.items():
                data = encode(value)
                validate_record(op, data)
                leaves[op] = leaf(op, data)
                records.append((op, data, leaves[op]))
            validate_set(rows)
            event = cls._event(
                plan.identity,
                origin,
                plan.before[0] + 1,
                plan.before[2],
                plan.before[1] + 1,
                b"",
                "MIGRATE",
                b"",
                b"",
                leaves,
            )
            require(
                origin == plan.origin
                and event == plan.event
                and plan.after == (event[0], event[2], event[-1]),
                "migration-input-changed",
            )
            for statement in SCHEMA:
                c.execute(statement)
            c.executemany("INSERT INTO v2_records VALUES (?,?,?)", records)
            c.executemany("INSERT INTO v2_base VALUES (?,?)", sorted(leaves.items()))
            c.executemany("INSERT INTO v2_legacy_heads VALUES (?,?)", legacy)
            c.execute(
                "INSERT INTO v2_meta VALUES (1,?,?,?,?,?,?,?,?)",
                (plan.identity, event[0], event[2], event[-1], *origin),
            )
            c.execute("INSERT INTO v2_events VALUES (?,?,?,?,?,?,?,?,?,?)", event)
            for name in ("meta", "sessions", "heads"):
                c.execute("DROP TABLE " + name)
            c.execute("PRAGMA user_version=2")
            _fault("migration-before-commit")
            c.execute("COMMIT")
            _fault("migration-after-commit")
        return cls(plan.path, plan.identity, plan.after, plan.after[1])

    @contextmanager
    def _connection(self):
        c = None
        try:
            v1.private_file(self.path, v1.DATABASE_BYTES)
            entries = list(self.path.parent.iterdir())
            for p in entries:
                require(p.name in {self.path.name, self.path.name + "-journal"}, "sidecar")
                v1.private_file(p, v1.DATABASE_BYTES)
            require(sum(p.stat().st_size for p in entries) <= 2 * v1.DATABASE_BYTES, "store-cap")
            c = sqlite3.connect(
                self.path.as_uri() + "?mode=rw&cache=private", uri=True, autocommit=True, timeout=0
            )
            c.enable_load_extension(False)
            for category, bound in (
                (sqlite3.SQLITE_LIMIT_LENGTH, 256 * 1024),
                (sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384),
                (sqlite3.SQLITE_LIMIT_ATTACHED, 0),
            ):
                c.setlimit(category, bound)
            for name, value in SETTINGS.items():
                c.execute(f"PRAGMA {name}={value}")
                require(c.execute(f"PRAGMA {name}").fetchone() == (value,), "sqlite-setting")
            require(c.execute("PRAGMA user_version").fetchone() == (2,), "schema-version")
            actual = c.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
            require(sorted(x[0] for x in actual) == sorted(SCHEMA), "schema")
            steps = 0

            def progress():
                nonlocal steps
                steps += 100
                return int(steps >= 100000)

            c.set_progress_handler(progress, 100)
            yield c
        except (sqlite3.Error, OSError) as error:
            raise Unavailable("storage-" + type(error).__name__) from None
        finally:
            if c is not None:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                c.close()

    def _load(self, c):
        require(c.execute("PRAGMA quick_check").fetchall() == [("ok",)], "sqlite-integrity")
        meta = c.execute(
            "SELECT identity,seq,generation,head,origin_seq,origin_gen,anchor"
            ",legacy FROM v2_meta WHERE id=1"
        ).fetchone()
        require(meta is not None and meta[0] == self.identity, "identity")
        require(
            ticket(tuple(meta[1:4])) == self.ticket and meta[2] == self.generation,
            "stale-or-fenced",
        )
        origin = tuple(meta[4:])
        require(
            origin[3]
            == self._legacy_hash(
                c.execute("SELECT seq,digest FROM v2_legacy_heads ORDER BY seq").fetchall()
            ),
            "legacy-integrity",
        )
        legacy_tip = c.execute(
            "SELECT seq,digest FROM v2_legacy_heads ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        require(legacy_tip == (origin[0], origin[2]), "legacy-tip")
        leaves = dict(c.execute("SELECT operation,digest FROM v2_base").fetchall())
        root(leaves)
        events = c.execute("SELECT * FROM v2_events ORDER BY seq LIMIT 513").fetchall()
        require(1 <= len(events) <= MAX_EVENTS, "event-bound")
        previous, seq, generation = origin[2], origin[0], origin[1]
        for index, event in enumerate(events):
            es, prev, gen, op, phase, old, new, rt, count, hd = event
            require(es == seq + 1 and prev == previous, "head-gap")
            if index == 0:
                require(
                    phase == "MIGRATE"
                    and gen == generation + 1
                    and (op, old, new) == (b"", b"", b""),
                    "migration-head",
                )
            elif phase == "FENCE":
                require(gen == generation + 1 and (op, old, new) == (b"", b"", b""), "fence-head")
            else:
                require(
                    phase in ("intent", "reservation", "claim", "certification")
                    and gen == generation,
                    "event-phase",
                )
                require(leaves.get(op, b"") == old, "event-old-record")
                octets(new, 32)
                require((phase == "intent") == (op not in leaves), "event-intent")
                leaves[op] = new
            require(
                event
                == self._event(self.identity, origin, es, prev, gen, op, phase, old, new, leaves),
                "head-integrity",
            )
            previous, seq, generation = hd, es, gen
        require((seq, generation, previous) == self.ticket, "head-tip")
        records, actual, nonces, ids = {}, {}, set(), set()
        for op, data, dg in c.execute(
            "SELECT operation,data,digest FROM v2_records ORDER BY operation LIMIT 65"
        ):
            value = validate_record(op, data)
            require(len(records) < MAX_ROWS and leaf(op, data) == dg, "record-integrity")
            require(value[2] not in nonces, "duplicate-nonce")
            nonces.add(value[2])
            if value[6] is not None:
                require(value[6] not in ids, "duplicate-identifier")
                ids.add(value[6])
            records[op] = value
            actual[op] = dg
        require(actual == leaves, "record-set-integrity")
        return records, origin, leaves, len(events)

    def snapshot(self):
        with self._connection() as c:
            c.execute("BEGIN")
            return self._load(c)[0]

    def page(self, *, expected, after=b"", limit=4):
        require(type(after) is bytes and len(after) in (0, 32), "cursor")
        require(type(limit) is int and 1 <= limit <= 4, "page-bound")
        require(expected == self.ticket, "page-head")
        with self._connection() as c:
            c.execute("BEGIN")
            rows, _, _, _ = self._load(c)
            require(not after or after in rows, "unknown-cursor")
            keys = sorted(k for k in rows if k > after)
            selected = keys[:limit]
            return self.ticket, tuple((k, rows[k]) for k in selected), len(keys) <= limit

    def history_page(self, *, expected, after, limit=16):
        """Local bounded digest history, authenticated at one externally expected head.

        These are local audit metadata, not new network or credential encodings.
        Full payloads are retained as current session outcomes, never in events.
        """
        require(expected == self.ticket, "history-head")
        require(type(after) is int and 0 <= after < 1 << 63, "history-cursor")
        require(type(limit) is int and 1 <= limit <= 16, "history-page-bound")
        with self._connection() as c:
            c.execute("BEGIN")
            _, origin, _, _ = self._load(c)
            require(origin[0] <= after <= self.ticket[0], "history-cursor-range")
            events = tuple(
                c.execute(
                    "SELECT * FROM v2_events WHERE seq>? ORDER BY seq LIMIT ?", (after, limit)
                )
            )
            done = not events or events[-1][0] == self.ticket[0]
            return self.ticket, events, done

    def _prepare(self, c, phase, prepare):
        before, origin, leaves, count = self._load(c)
        require(count < MAX_EVENTS, "event-bound")
        after = dict(before)
        prepare(after)
        require(set(before) <= set(after) and len(after) <= MAX_ROWS, "record-removal-or-cap")
        changed = [op for op, value in after.items() if before.get(op) != value]
        require(len(changed) == 1, "one-record-transition")
        op = changed[0]
        data = encode(after[op])
        validate_record(op, data)
        transition_shape(phase, before.get(op), after[op])
        require(len({v[2] for v in after.values()}) == len(after), "duplicate-nonce")
        ids = [v[6] for v in after.values() if v[6] is not None]
        require(len(ids) == len(set(ids)), "duplicate-identifier")
        old = leaves.get(op, b"")
        new = leaf(op, data)
        leaves[op] = new
        event = self._event(
            self.identity,
            origin,
            self.ticket[0] + 1,
            self.ticket[2],
            self.generation,
            op,
            phase,
            old,
            new,
            leaves,
        )
        return Prepared(self.ticket, (event[0], event[2], event[-1]), phase, op, data, event)

    def prepare(self, phase, prepare):
        with self._connection() as c:
            c.execute("BEGIN")
            return self._prepare(c, phase, prepare)

    def commit(self, plan):
        require(type(plan) is Prepared and plan.before == self.ticket, "prepared-head")

        def apply(rows):
            rows[plan.operation] = decode(plan.data)

        with self._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            require(self._prepare(c, plan.phase, apply) == plan, "prepared-binding")
            c.execute(
                (
                    "INSERT INTO v2_records VALUES (?,?,?) ON CONFLICT(operation) DO "
                    "UPDATE SET data=excluded.data,digest=excluded.digest"
                ),
                (plan.operation, plan.data, plan.event[6]),
            )
            c.execute("INSERT INTO v2_events VALUES (?,?,?,?,?,?,?,?,?,?)", plan.event)
            c.execute("UPDATE v2_meta SET seq=?,generation=?,head=? WHERE id=1", plan.after)
            _fault("commit-before-commit")
            c.execute("COMMIT")
            _fault("commit-after-commit")
        self.ticket = plan.after
        return self.ticket

    def transition(self, phase, prepare):
        self.pending = self.prepare(phase, prepare)
        self.commit(self.pending)
        self.pending = None

    def fence(self):
        with self._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            _, origin, leaves, count = self._load(c)
            require(count < MAX_EVENTS, "event-bound")
            event = self._event(
                self.identity,
                origin,
                self.ticket[0] + 1,
                self.ticket[2],
                self.generation + 1,
                b"",
                "FENCE",
                b"",
                b"",
                leaves,
            )
            after = (event[0], event[2], event[-1])
            c.execute("INSERT INTO v2_events VALUES (?,?,?,?,?,?,?,?,?,?)", event)
            c.execute("UPDATE v2_meta SET seq=?,generation=?,head=? WHERE id=1", after)
            c.execute("COMMIT")
        return type(self)(self.path, self.identity, after, after[1])
