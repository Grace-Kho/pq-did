"""Opt-in local manager schema 2: bounded immutable DAG components, no wire change.

Checkpoint equality and checkpoint_digest retain the original typed meaning. Only
local persistence/head framing changes. Freshness still needs an external ticket.
"""

import hashlib
from contextlib import contextmanager
from dataclasses import dataclass, fields, is_dataclass

from pqdid.persistence.codec import CAP, TYPES, decode, encode, require
from pqdid.persistence.records import MAX_COUNTER, HeadTicket, Outcome, WriterPermit
from pqdid.persistence.sqlite_store import SQLiteStore, digest
from pqdid.recovery_records import Role, checkpoint_digest

MAX_NODES = 4096
SCHEMA = (
    (
        "CREATE TABLE nodes (digest BLOB PRIMARY KEY, kind TEXT NOT NULL,"
        " data BLOB NOT NULL CHECK(length(data)<=65536))"
    ),
    (
        "CREATE TABLE service (id INTEGER PRIMARY KEY CHECK(id=1), "
        "identity BLOB NOT NULL, generation INTEGER NOT NULL, writer BLOB"
        " NOT NULL, tip INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE checkpoints (digest BLOB PRIMARY KEY, root BLOB NOT"
        " NULL REFERENCES nodes(digest))"
    ),
    (
        "CREATE TABLE operations (id BLOB PRIMARY KEY, request BLOB NOT "
        "NULL REFERENCES nodes(digest), decision BLOB NOT NULL REFERENCES"
        " nodes(digest), response BLOB NOT NULL REFERENCES nodes(digest))"
    ),
    (
        "CREATE TABLE heads (seq INTEGER PRIMARY KEY, digest BLOB UNIQUE "
        "NOT NULL, previous BLOB NOT NULL, checkpoint BLOB NOT NULL "
        "REFERENCES checkpoints(digest), operation BLOB UNIQUE REFERENCES"
        " operations(id), generation INTEGER NOT NULL, entries BLOB NOT "
        "NULL, format INTEGER NOT NULL, writer BLOB NOT NULL)"
    ),
    ("CREATE TABLE entries (key BLOB PRIMARY KEY, data BLOB NOT NULL REFERENCES nodes(digest))"),
)


def _fault(_point):
    """Inert local test hook; never controlled by a caller/container."""


def node_hash(kind, data):
    require(kind in ("a", "t", "d") and type(data) is bytes and len(data) <= CAP, "node")
    return hashlib.sha256(
        b"kyc-manager-dag-v2\0" + kind.encode() + len(data).to_bytes(4) + data
    ).digest()


def intern(value, nodes, depth=0):
    require(depth <= 16, "node-depth")
    if type(value) is tuple:
        require(len(value) <= 128, "node-collection")
        kind, data = "t", encode(tuple(intern(v, nodes, depth + 1) for v in value))
    elif is_dataclass(value) and type(value) in TYPES:
        kind, data = (
            "d",
            encode(
                (
                    TYPES.index(type(value)),
                    tuple(intern(getattr(value, f.name), nodes, depth + 1) for f in fields(value)),
                )
            ),
        )
    else:
        kind, data = "a", encode(value)
    key = node_hash(kind, data)
    require(key not in nodes or nodes[key] == (kind, data), "node-collision")
    nodes[key] = (kind, data)
    require(len(nodes) <= MAX_NODES, "node-cap")
    return key


def unpack(key, nodes, cache, active=None, depth=0):
    require(type(key) is bytes and len(key) == 32 and key in nodes and depth <= 16, "missing-node")
    if key in cache:
        return cache[key]
    active = set() if active is None else active
    require(key not in active, "cyclic-node")
    active.add(key)
    kind, data = nodes[key]
    require(node_hash(kind, data) == key, "node-integrity")
    raw = decode(data)
    require(encode(raw) == data, "noncanonical-node")
    if kind == "a":
        require(type(raw) is not tuple and not is_dataclass(raw), "atom-type")
        value = raw
    else:
        refs = raw if kind == "t" else raw[1] if type(raw) is tuple and len(raw) == 2 else None
        require(type(refs) is tuple and len(refs) <= 128, "node-shape")
        values = tuple(unpack(r, nodes, cache, active, depth + 1) for r in refs)
        if kind == "t":
            value = values
        else:
            require(type(raw[0]) is int and 0 <= raw[0] < len(TYPES), "node-type")
            cls = TYPES[raw[0]]
            require(is_dataclass(cls) and len(values) == len(fields(cls)), "node-arity")
            value = cls(*values)
    active.remove(key)
    cache[key] = value
    return value


def new_head(identity, seq, previous, cp, op, refs, generation, entries, writer):
    return digest(
        (
            b"kyc-manager-head-v2",
            seq,
            previous,
            cp,
            op,
            *refs,
            generation,
            entries,
            writer,
            identity,
        )
    )


@dataclass(frozen=True)
class Migration:
    before: HeadTicket
    after: HeadTicket
    operation: bytes
    writer: bytes


class ManagerStore(SQLiteStore):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        require(self.key.role is Role.MANAGER, "manager-only")

    def initialise(self, *args, **kwargs):
        raise NotImplementedError("Explicit v1 bootstrap then admitted v2 migration only")

    @contextmanager
    def _connection(self, *, creating=False):
        # Existing path, SQLite page/VM/settings and memory/storage bounds, unchanged.
        with super()._connection(creating=True) as c:
            if not creating:
                require(c.execute("PRAGMA user_version").fetchone() == (2,), "schema-version")
                actual = c.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
                require(sorted(r[0] for r in actual) == sorted(SCHEMA), "schema")
            yield c

    @staticmethod
    def _nodes(c):
        rows = c.execute("SELECT digest,kind,data FROM nodes LIMIT 4097").fetchall()
        require(len(rows) <= MAX_NODES, "node-cap")
        nodes = {key: (kind, data) for key, kind, data in rows}
        require(
            all(node_hash(kind, data) == key for key, (kind, data) in nodes.items()),
            "node-integrity",
        )
        return nodes

    @staticmethod
    def _save(c, nodes):
        c.executemany(
            "INSERT OR IGNORE INTO nodes VALUES (?,?,?)", ((k, *v) for k, v in nodes.items())
        )
        require(c.execute("SELECT count(*) FROM nodes").fetchone()[0] <= MAX_NODES, "node-cap")

    def _load(self, c):
        require(c.execute("PRAGMA quick_check").fetchall() == [("ok",)], "integrity")
        require(not c.execute("PRAGMA foreign_key_check").fetchall(), "missing-reference")
        nodes = self._nodes(c)
        cache = {}

        def get(r):
            return unpack(r, nodes, cache)

        service = c.execute(
            "SELECT identity,generation,writer,tip FROM service WHERE id=1"
        ).fetchone()
        require(service is not None and service[0] == self._identity, "service-binding")
        _, generation, writer, tip = service
        require(type(generation) is int and 0 <= generation <= MAX_COUNTER, "generation")
        rawops = c.execute("SELECT * FROM operations LIMIT 129").fetchall()
        heads = c.execute("SELECT * FROM heads ORDER BY seq LIMIT 130").fetchall()
        require(len(rawops) <= 128 and len(heads) == len(rawops) + 1, "row-cap-or-gap")
        refs = {r[0]: r[1:] for r in rawops}
        ops = {op: tuple(get(v) for v in rr) for op, rr in refs.items()}
        require(
            all(
                type(op) is bytes
                and len(op) == 32
                and all(type(x) is bytes and len(x) <= CAP for x in values)
                for op, values in ops.items()
            ),
            "operation-shape",
        )
        cps = {}
        for cp, root in c.execute("SELECT digest,root FROM checkpoints LIMIT 130"):
            value = get(root)
            require(checkpoint_digest(value) == cp, "checkpoint-digest")
            cps[cp] = value
        require(len(cps) <= 129, "checkpoint-cap")
        previous = b""
        new_seen = False
        for index, (seq, hd, prev, cp, op, gen, entries, fmt, wr) in enumerate(heads, 1):
            require(seq == index and prev == previous and cp in cps, "head-gap")
            require((index == 1 and op is None) or op in ops, "head-operation")
            if fmt == 0:
                require(not new_seen, "legacy-order")
                commitment = b"" if op is None else digest((op, *ops[op]))
                wanted = digest((seq, prev, cp, commitment, gen, entries, self._identity))
            else:
                require(fmt == 2 and op in ops, "head-format")
                new_seen = True
                wanted = new_head(self._identity, seq, prev, cp, op, refs[op], gen, entries, wr)
                require(type(get(entries)) is tuple, "entry-set")
            require(hd == wanted, "head-digest")
            previous = hd
        require(
            new_seen
            and heads[-1][0] == tip
            and heads[-1][5] == generation
            and heads[-1][8] == writer,
            "head-tip",
        )
        rows = c.execute("SELECT key,data FROM entries ORDER BY key LIMIT 129").fetchall()
        require(
            len(rows) <= 128 and all(type(k) is bytes and 1 <= len(k) <= 256 for k, _ in rows),
            "entry-cap",
        )
        entries = {k: get(v) for k, v in rows}
        require(tuple(sorted(entries.items())) == get(heads[-1][6]), "entry-integrity")
        cp = heads[-1][3]
        return HeadTicket(tip, previous, cp, generation), cps[cp], entries, writer, ops

    def _write(
        self, c, ticket, checkpoint, entries, op, request, decision, response, generation, writer
    ):
        require(ticket.sequence < MAX_COUNTER and generation <= MAX_COUNTER, "counter-exhausted")
        require(c.execute("SELECT count(*) FROM operations").fetchone()[0] < 128, "operation-cap")
        require(
            len(entries) <= 128
            and all(type(x) is bytes and len(x) <= CAP for x in (request, decision, response)),
            "payload-cap",
        )
        cp = self._validate(checkpoint)
        nodes = {}
        cp_root = intern(checkpoint, nodes)
        entry_root = intern(tuple(sorted(entries.items())), nodes)
        refs = tuple(intern(x, nodes) for x in (request, decision, response))
        rows = [(k, intern(v, nodes)) for k, v in sorted(entries.items())]
        # Manager reservations/outcomes are permanent. No deletion or rebinding.
        existing = c.execute("SELECT key,data FROM entries").fetchall()
        require(all((k, r) in rows for k, r in existing), "permanent-entry-change")
        seq = ticket.sequence + 1
        hd = new_head(
            self._identity, seq, ticket.digest, cp, op, refs, generation, entry_root, writer
        )
        self._save(c, nodes)
        c.execute("INSERT OR IGNORE INTO checkpoints VALUES (?,?)", (cp, cp_root))
        c.execute("INSERT INTO operations VALUES (?,?,?,?)", (op, *refs))
        c.executemany("INSERT OR IGNORE INTO entries VALUES (?,?)", rows)
        c.execute(
            "INSERT INTO heads VALUES (?,?,?,?,?,?,?,?,?)",
            (seq, hd, ticket.digest, cp, op, generation, entry_root, 2, writer),
        )
        c.execute(
            "UPDATE service SET generation=?,writer=?,tip=? WHERE id=1", (generation, writer, seq)
        )
        _fault("rows-before-commit")
        c.execute("COMMIT")
        _fault("commit-before-ack")
        return Outcome(op, decision, response, HeadTicket(seq, hd, cp, generation))

    @classmethod
    def migration_plan(cls, old, admin, expected, permit):
        old._authorise(admin, "replace")
        old.admit(permit, expected)
        with old._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            ticket, cp, entries, writer, ops = old._load(c)
            require(ticket == expected and len(ops) < 128, "migration-head-or-cap")
            old._fence(permit, ticket, writer)
            old._validate(cp)
            nodes = {}
            entry_root = intern(tuple(sorted(entries.items())), nodes)
            operation = hashlib.sha256(b"kyc-manager-migration-v2" + ticket.digest).digest()
            require(operation not in ops, "migration-operation")
            request = encode((b"migrate-v2", admin, ticket.record(), writer))
            refs = tuple(intern(x, nodes) for x in (request, b"MIGRATED", b""))
            gen = ticket.generation + 1
            require(gen <= MAX_COUNTER, "generation-exhausted")
            hd = new_head(
                old._identity,
                ticket.sequence + 1,
                ticket.digest,
                ticket.checkpoint,
                operation,
                refs,
                gen,
                entry_root,
                writer,
            )
            return Migration(
                ticket,
                HeadTicket(ticket.sequence + 1, hd, ticket.checkpoint, gen),
                operation,
                writer,
            )

    @classmethod
    def migrate(cls, old, admin, permit, plan):
        require(type(plan) is Migration, "migration-plan")
        old._authorise(admin, "replace")
        new = cls(old._path, old.key, dependencies=old._deps, authorisation=old._policy)
        with old._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            ticket, cp, entries, writer, ops = old._load(c)
            require(ticket == plan.before and writer == plan.writer, "migration-stale")
            old._fence(permit, ticket, writer)
            old._validate(cp)
            nodes = {}
            cp_rows = []
            for dg, payload in c.execute("SELECT digest,data FROM checkpoints"):
                value = decode(payload)
                require(checkpoint_digest(value) == dg, "legacy-checkpoint")
                cp_rows.append((dg, intern(value, nodes)))
            op_rows = [(op, *(intern(x, nodes) for x in values)) for op, values in ops.items()]
            entry_rows = [(k, intern(v, nodes)) for k, v in entries.items()]
            heads = [(*r, 0, b"") for r in c.execute("SELECT * FROM heads ORDER BY seq")]
            service = c.execute("SELECT * FROM service").fetchall()
            for table in ("heads", "operations", "checkpoints", "entries", "service"):
                c.execute("DROP TABLE " + table)
            for statement in SCHEMA:
                c.execute(statement)
            new._save(c, nodes)
            c.executemany("INSERT INTO service VALUES (?,?,?,?,?)", service)
            c.executemany("INSERT INTO checkpoints VALUES (?,?)", cp_rows)
            c.executemany("INSERT INTO operations VALUES (?,?,?,?)", op_rows)
            c.executemany("INSERT INTO entries VALUES (?,?)", entry_rows)
            c.executemany("INSERT INTO heads VALUES (?,?,?,?,?,?,?,?,?)", heads)
            c.execute("PRAGMA user_version=2")
            # Derive and compare the externally retained successor BEFORE COMMIT.
            node_set = {}
            er = intern(tuple(sorted(entries.items())), node_set)
            request = encode((b"migrate-v2", admin, ticket.record(), writer))
            refs = tuple(intern(x, node_set) for x in (request, b"MIGRATED", b""))
            hd = new_head(
                new._identity,
                ticket.sequence + 1,
                ticket.digest,
                ticket.checkpoint,
                plan.operation,
                refs,
                ticket.generation + 1,
                er,
                writer,
            )
            require(
                plan.after
                == HeadTicket(ticket.sequence + 1, hd, ticket.checkpoint, ticket.generation + 1),
                "migration-binding",
            )
            result = new._write(
                c,
                ticket,
                cp,
                entries,
                plan.operation,
                request,
                b"MIGRATED",
                b"",
                ticket.generation + 1,
                writer,
            )
            require(result.ticket == plan.after, "migration-result")
        return new, WriterPermit(writer, plan.after.generation), plan.after
