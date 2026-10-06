"""Real child-process kills at APPLICATION barriers; no power-loss or proof claims."""

import json
import os
import resource
import select
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

import durable_worker as worker
import pytest

from pqdid.persistence.codec import Unavailable, decode, encode
from pqdid.persistence.lifecycle import DurableIssuer, DurableManager, DurableVerifier
from pqdid.persistence.sqlite_store import SQLiteStore
from pqdid.recovery_records import checkpoint_digest
from pqdid.statements import decode_context, encode_auth_statement, encode_state
from pqdid.verifier_state import Decision, StoredChallenge
from tests.unit.did_state_cases import DIDAuthority
from tests.unit.lifecycle_review_cases import LifecycleHarness
from tests.unit.recovery_cases import (
    issued,
    issuer_checkpoint,
    manager_checkpoint,
    verifier_checkpoint,
)

EVIDENCE = Path(__file__).resolve().parents[2] / "docs/data/s2_durable_authority_pilot_1"
CASES = []


@pytest.fixture(scope="module")
def fixtures():
    authority = DIDAuthority()
    try:
        h = LifecycleHarness(authority)
        result = {"manager.fixture": manager_checkpoint(h), "issuer.fixture": issuer_checkpoint(h)}
        h.certify()
        cp = issuer_checkpoint(h)
        result["issued.fixture"] = (cp.state.sessions[0].challenge, issued(h.pp, h.issued))
        for index in (0, 1):
            v, presentation, valid = h.presentation(index)
            assert valid
            checkpoint = verifier_checkpoint(v)
            rows = tuple(
                r
                for r in checkpoint.state.challenges
                if decode_context(h.pp, r.context) == v.request.context
            )
            assert len(rows) == 1
            name = "verifier" + str(index)
            result[name + ".fixture"] = replace(
                checkpoint, state=replace(checkpoint.state, challenges=rows)
            )
            current = authority.reply((1).to_bytes(32), v.request.state)
            result[name + ".public"] = (
                encode_auth_statement(h.pp, v.statement),
                presentation.disclosed,
                presentation.disclosed_attributes,
                presentation.proof,
                encode_state(h.pp, current.state),
                current.signature,
            )
        return {name: encode(value) for name, value in result.items()}
    finally:
        authority.close()


def disk(root):
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


class Case:
    def __init__(self, root, name):
        self.root, self.name = root, name
        self.events, self.children, self.started, self.disk_peak = (
            [],
            [],
            time.monotonic(),
            disk(root),
        )

    def spawn(self, action, role="manager", point="none"):
        assert len([p for p in self.children if p.returncode is None]) < 2
        command = [
            sys.executable,
            str(Path(worker.__file__).resolve()),
            str(self.root),
            action,
            role,
            point,
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.children.append(process)
        process.pilot_command = command
        return process

    def line(self, process):
        assert select.select([process.stdout], [], [], 12)[0], "child application deadline"
        line = process.stdout.readline(8192)
        assert line, process.stderr.read(8192)
        self.disk_peak = max(self.disk_peak, disk(self.root))
        return json.loads(line)

    def finish(self, process, *, kill=False):
        if kill:
            process.kill()
        pid, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        stdout, stderr = process.stdout.read(8192), process.stderr.read(8192)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        self.disk_peak = max(self.disk_peak, disk(self.root))
        self.events.append(
            {
                "command": process.pilot_command,
                "pid": pid,
                "exit": process.returncode,
                "termination": "SIGKILL" if kill else "normal",
                "child_ru_maxrss_bytes": usage.ru_maxrss * 1024,
                "child_user_seconds": usage.ru_utime,
                "child_system_seconds": usage.ru_stime,
                "remaining_stdout": stdout,
                "stderr": stderr,
            }
        )
        assert process.returncode == (-signal.SIGKILL if kill else 0), stderr
        assert not stderr

    def run(self, action, role="manager"):
        process = self.spawn(action, role)
        output = self.line(process)
        self.finish(process)
        self.events[-1]["observed"] = output
        return output["result"]

    def crash(self, action, role, point):
        process = self.spawn(action, role, point)
        barrier = self.line(process)
        assert barrier.get("barrier") == point, barrier
        self.finish(process, kill=True)
        self.events[-1]["barrier"] = barrier

    def close(self):
        for process in self.children:
            if process.returncode is None:
                process.kill()
                process.wait(timeout=2)
        return {
            "case": self.name,
            "wall_seconds": time.monotonic() - self.started,
            "temporary_bytes_observed_peak": self.disk_peak,
            "parent_cumulative_maxrss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            * 1024,
            "events": self.events,
            "fault_model": (
                "application-process-only; no host/power-loss/SQLite-internal interruption"
            ),
        }


@pytest.fixture
def case(fixtures, request):
    with tempfile.TemporaryDirectory(prefix="durable-") as name:
        root = Path(name)
        for filename, payload in fixtures.items():
            (root / filename).write_bytes(payload)
        c = Case(root, request.node.name)
        try:
            yield c
        finally:
            CASES.append(c.close())
            (EVIDENCE / ("case-evidence-" + os.environ["PQDID_PILOT_RUN"] + ".json")).write_text(
                json.dumps(CASES, indent=2) + "\n"
            )


@pytest.mark.parametrize(
    "point,committed",
    [
        ("before-begin", False),
        ("after-begin", False),
        ("rows-before-commit", False),
        ("commit-before-ack", True),
    ],
)
def test_manager_real_crash(case, point, committed):
    worker.initialise(case.root, "manager")
    before = case.run("inspect")
    case.crash("reserve", "manager", point)
    after = case.run("inspect")
    assert after["allocated"] == 42 + committed
    assert after["entries"] == int(committed)
    assert (after["head"] != before["head"]) == committed
    assert after["sequence"] == before["sequence"] + committed


def test_runtime_policy_binding_and_codec(case):
    worker.initialise(case.root, "manager")
    owner = worker.store(case.root, "manager")
    facts = owner.runtime(b"worker")
    assert facts["sqlite"] == sqlite3.sqlite_version
    assert facts["settings"]["journal_mode"] == "delete" and facts["settings"]["synchronous"] == 3
    (EVIDENCE / ("runtime-facts-" + os.environ["PQDID_PILOT_RUN"] + ".json")).write_text(
        json.dumps(facts, indent=2) + "\n"
    )
    closed = SQLiteStore(owner._path, owner.key, dependencies=owner._deps)
    with pytest.raises(Unavailable, match="unauthorised"):
        closed.inspect(b"worker")
    with pytest.raises(Unavailable, match="already-initialised"):
        owner.initialise(b"test-admin", decode((case.root / "manager.fixture").read_bytes()))
    wrong = SQLiteStore(
        owner._path,
        replace(owner.key, service_id=b"X" * 32),
        dependencies=owner._deps,
        authorisation=worker.Operator(),
    )
    with pytest.raises(Unavailable, match="service-binding"):
        wrong.inspect(b"worker")
    cp = decode((case.root / "manager.fixture").read_bytes())
    assert checkpoint_digest(decode(encode(cp))) == checkpoint_digest(cp)
    for invalid in (encode(cp)[:-1], encode(cp) + b"x", b"PQL1(\xff\xff\xff\xff", b"PQL1rx"):
        with pytest.raises(Unavailable):
            decode(invalid)
    with pytest.raises(Unavailable, match="payload-cap"):
        encode(b"x" * 65536)


def test_lost_retry_conflict_stale_checkpoint(case):
    permit, original = worker.initialise(case.root, "manager")
    owner = worker.store(case.root, "manager")
    stale_cp = owner.inspect(b"worker")[1]
    case.crash("reserve", "manager", "commit-before-ack")
    current = owner.inspect(b"worker")[0]
    model = DurableManager(owner, permit, current)
    result = model.reserve(
        worker.OP, b"S" * 32, worker.ISSUE, worker.reference(case.root), prior=original
    )
    assert (
        result.replay
        and result.decision == b"ALREADY_COMMITTED"
        and decode(result.response)[0] == 42
    )
    assert worker.summary(case.root, "manager")["allocated"] == 43
    with pytest.raises(Unavailable, match="operation-conflict"):
        model.reserve(worker.OP, b"S" * 32, b"X" * 32, worker.reference(case.root), prior=original)
    with pytest.raises(Unavailable, match="stale-head"):
        DurableManager(owner, permit, original)
    assert stale_cp.state.state == owner.inspect(b"worker")[1].state.state
    assert checkpoint_digest(stale_cp) != current.checkpoint
    with pytest.raises(Unavailable, match="cross-role"):
        DurableVerifier(owner, permit, current)


@pytest.mark.parametrize("action", ["reserve", "replace"])
def test_two_process_contenders(case, action):
    worker.initialise(case.root, "manager")
    first = case.spawn(action, point="prepared")
    assert case.line(first)["barrier"] == "prepared"
    second = case.spawn(action, point="prepared")
    assert case.line(second)["barrier"] == "prepared"
    for process in (first, second):
        process.stdin.write("go\n")
        process.stdin.flush()
    outcomes = [case.line(p)["result"] for p in (first, second)]
    for process, outcome in zip((first, second), outcomes, strict=True):
        case.finish(process)
        case.events[-1]["observed"] = outcome
    after = case.run("inspect")
    if action == "reserve":
        assert after["allocated"] == 43 and after["entries"] == 1
        assert sum(o.get("decision") == "ALLOCATED" for o in outcomes) == 1
    else:
        assert after["generation"] == 2
        assert any(o.get("generation") == 2 for o in outcomes)


def test_superseded_process_commit_and_busy(case):
    worker.initialise(case.root, "manager")
    old = case.spawn("reserve", point="prepared")
    assert case.line(old)["barrier"] == "prepared"
    assert case.run("replace")["generation"] == 2
    old.stdin.write("go\n")
    old.stdin.flush()
    assert case.line(old)["result"]["unavailable"] == "fenced-writer"
    case.finish(old)
    assert case.run("inspect")["allocated"] == 42
    lock = sqlite3.connect(case.root / "manager/authority.sqlite3", timeout=0, autocommit=True)
    try:
        lock.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        assert "unavailable" in case.run("reserve")
        assert time.monotonic() - started < 2
    finally:
        lock.execute("ROLLBACK")
        lock.close()


@pytest.mark.parametrize("point", ["rows-before-commit", "commit-before-ack"])
def test_verifier_consumption_crash_and_restart(case, point):
    worker.initialise(case.root, "verifier0")
    worker.initialise(case.root, "verifier1")
    case.crash("verify", "verifier0", point)
    after = case.run("inspect", "verifier0")
    committed = point == "commit-before-ack"
    assert after["consumed"] == int(committed)
    expected = Decision.UNKNOWN if committed else Decision.ACCEPTED
    assert case.run("verify", "verifier0")["decision"] == expected.value
    assert case.run("verify", "verifier0")["decision"] == Decision.UNKNOWN.value
    assert case.run("verify", "verifier1")["decision"] == Decision.ACCEPTED.value


def test_verifier_registration_audience_expiry_and_fence(case):
    worker.initialise(case.root, "verifier0")
    worker.initialise(case.root, "verifier1")
    assert case.run("register", "verifier0")["decision"] == "REGISTERED"
    v = worker.facade(case.root, "verifier0")
    other = worker.facade(case.root, "verifier1")
    cp = decode((case.root / "verifier0.fixture").read_bytes())
    pp = v._store.key.parameters
    row = cp.state.challenges[0]
    challenge = StoredChallenge(
        pp, decode_context(pp, row.context), worker.decode_state(pp, row.state), False
    )
    with pytest.raises(Unavailable, match="cross-audience"):
        other.register(b"q" * 32, challenge)
    proof = v._store._deps.proof_verifier
    original = proof.verify

    def expire(statement, token):
        v._store._deps.clock.value = 100
        return original(statement, token)

    proof.verify = expire
    f = decode((case.root / "verifier0.public").read_bytes())
    result = v.verify(
        session=challenge.context.session,
        context=challenge.context,
        presentation=worker.Presentation(f[1], f[2], f[3]),
    )
    assert not result.accepted and worker.summary(case.root, "verifier0")["consumed"] == 0
    v._store._deps.clock.value = 99
    v._store.acquire(b"test-admin", b"x" * 32, v.ticket, b"replacement")
    with pytest.raises(Unavailable):
        v.verify(
            session=challenge.context.session,
            context=challenge.context,
            presentation=worker.Presentation(f[1], f[2], f[3]),
        )


STAGES = ["intent", "reserve", "attach", "pending", "sign", "log", "release"]


@pytest.mark.parametrize(
    "stage,point",
    [
        ("intent", "commit-before-ack"),
        ("reserve", "commit-before-ack"),
        ("attach", "commit-before-ack"),
        ("pending", "commit-before-ack"),
        ("sign", "commit-before-ack"),
        ("log", "rows-before-commit"),
        ("log", "commit-before-ack"),
        ("release", "release-before-publication"),
        ("release", "enqueue-before-return"),
    ],
)
def test_issuer_crash_reconciliation(case, stage, point):
    worker.initialise(case.root, "manager")
    worker.initialise(case.root, "issuer")
    for earlier in STAGES[: STAGES.index(stage)]:
        worker.issue_stage(case.root, earlier)
    role = "manager" if stage == "reserve" else "issuer"
    case.crash("issue-" + stage, role, point)
    before = case.run("inspect", "issuer")
    assert "decision" in case.run("issue-reconcile", "issuer")
    after = case.run("inspect", "issuer")
    certified = STAGES.index(stage) >= 5 and not (stage == "log" and point == "rows-before-commit")
    pending = stage == "pending"
    assert after["certifications"] == int(certified)
    assert after["phases"] == (
        ["CERTIFIED"] if certified else ["PENDING"] if pending else ["RETIRED"]
    )
    assert case.run("inspect")["allocated"] == (42 if stage == "intent" else 43)
    assert before["certifications"] == after["certifications"]
    if certified:
        assert case.run("issue-release", "issuer")["decision"] == "REDELIVERY"
        assert "unavailable" in case.run("issue-log", "issuer")
    elif not pending:
        assert "unavailable" in case.run("issue-sign", "issuer")


def test_issuer_delayed_signature_publication_and_conflicts(case):
    worker.initialise(case.root, "manager")
    worker.initialise(case.root, "issuer")
    for stage in STAGES[:5]:
        worker.issue_stage(case.root, stage)
    old = worker.facade(case.root, "issuer")
    signing_ticket = old.ticket
    _, issued_record = decode((case.root / "issued.fixture").read_bytes())
    permit, ticket = old._store.acquire(b"test-admin", b"x" * 32, old.ticket, b"replacement")
    with pytest.raises(Unavailable, match="fenced-writer"):
        old.log_certificate(b"c" * 32, worker.ISSUE, issued_record, b"recipient", signing_ticket)
    new = DurableIssuer(old._store, permit, ticket)
    with pytest.raises(Unavailable, match="delayed-signature"):
        new.log_certificate(b"c" * 32, worker.ISSUE, issued_record, b"recipient", signing_ticket)
    assert (
        new.reconcile(b"r" * 32, worker.ISSUE, worker.facade(case.root, "manager")).decision
        == b"RETIRED"
    )
    assert worker.summary(case.root, "manager")["allocated"] == 43
    with pytest.raises(Unavailable, match="not-pending"):
        new.claim_signing(b"z" * 32, worker.ISSUE)


def test_publication_current_generation_and_exact_recipient(case):
    worker.initialise(case.root, "manager")
    worker.initialise(case.root, "issuer")
    for stage in STAGES[:6]:
        worker.issue_stage(case.root, stage)
    old = worker.facade(case.root, "issuer")
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setblocking(False)
    right.setblocking(False)
    try:
        with pytest.raises(Unavailable, match="wrong-recipient"):
            old.retrieve_committed(b"c" * 32, b"wrong-recipient", left)
        assert old.retrieve_committed(b"c" * 32, b"recipient", left) == b"REDELIVERY"
        permit, ticket = old._store.acquire(b"test-admin", b"x" * 32, old.ticket, b"replacement")
        packet = right.recv(65536)
        assert decode(packet) == decode((case.root / "issued.fixture").read_bytes())[1]
        with pytest.raises(Unavailable, match="fenced-writer"):
            old.retrieve_committed(b"c" * 32, b"recipient", left)
        new = DurableIssuer(old._store, permit, ticket)
        assert new.retrieve_committed(b"c" * 32, b"recipient", left) == b"REDELIVERY"
        assert right.recv(65536) == packet
        assert worker.summary(case.root, "issuer")["certifications"] == 1
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize(
    "damage", ["missing", "malformed", "checkpoint", "outcome", "schema", "symlink"]
)
def test_recovery_storage_failures_never_bootstrap(case, damage):
    worker.initialise(case.root, "manager")
    assert case.run("reserve")["rid"] == 42
    path = case.root / "manager/authority.sqlite3"
    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_bytes(b"invalid test-only storage")
    elif damage == "symlink":
        target = case.root / "unowned-copy"
        shutil.move(path, target)
        path.symlink_to(target)
    else:
        with sqlite3.connect(path) as c:
            if damage == "checkpoint":
                c.execute("DELETE FROM checkpoints")
            elif damage == "outcome":
                c.execute("DELETE FROM operations")
            else:
                c.execute("PRAGMA user_version=2")
    assert "unavailable" in case.run("inspect")
    if damage == "missing":
        assert not path.exists()


def test_work_storage_and_row_budgets(case):
    _, ticket = worker.initialise(case.root, "manager")
    owner = worker.store(case.root, "manager")
    with pytest.raises(Unavailable, match="storage-OperationalError"):
        with owner._connection() as c:
            c.execute(
                "WITH RECURSIVE t(x) AS (VALUES(0) UNION ALL "
                "SELECT x+1 FROM t WHERE x<1000000) SELECT sum(x) FROM t"
            ).fetchone()
    assert owner.inspect(b"worker")[0] == ticket
    with pytest.raises(Unavailable, match="storage-OperationalError"):
        with owner._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("CREATE TABLE pressure (x BLOB)")
            for _ in range(12):
                c.execute("INSERT INTO pressure VALUES (?)", (b"x" * 65536,))
    assert owner.inspect(b"worker")[0] == ticket
    assert owner._path.stat().st_size <= 524288
    for i in range(127):
        _, ticket = owner.acquire(b"test-admin", i.to_bytes(32), ticket, b"worker")
    with pytest.raises(Unavailable, match="operation-cap"):
        owner.acquire(b"test-admin", b"z" * 32, ticket, b"worker")
    assert owner.inspect(b"worker")[0] == ticket


@pytest.mark.parametrize(
    "action,role,point",
    [
        ("issue-log", "issuer", "signature-ready"),
        ("issue-release", "issuer", "release-before-publication"),
        ("verify", "verifier0", "proof-ready"),
    ],
)
def test_delayed_old_process_at_effect_boundary(case, action, role, point):
    if role == "issuer":
        worker.initialise(case.root, "manager")
        worker.initialise(case.root, "issuer")
        for stage in STAGES[: 5 if action == "issue-log" else 6]:
            worker.issue_stage(case.root, stage)
    else:
        worker.initialise(case.root, role)
    old = case.spawn(action, role, point)
    assert case.line(old)["barrier"] == point
    assert case.run("replace", role)["generation"] == 2
    old.stdin.write("go\n")
    old.stdin.flush()
    outcome = case.line(old)["result"]
    case.finish(old)
    case.events[-1]["observed"] = outcome
    if role == "issuer":
        assert outcome["unavailable"] == "fenced-writer"
        assert case.run("inspect", role)["certifications"] == int(action == "issue-release")
    else:
        assert outcome["decision"] == Decision.FAILURE.value
        assert case.run("inspect", role)["consumed"] == 0


@pytest.mark.parametrize(
    "point,committed", [("rows-before-commit", False), ("commit-before-ack", True)]
)
def test_grant_crash_retains_unused_generation(case, point, committed):
    permit, ticket = worker.initialise(case.root, "manager")
    case.crash("replace", "manager", point)
    after = case.run("inspect")
    assert after["generation"] == 1 + committed
    if committed:
        with pytest.raises(Unavailable):
            DurableManager(worker.store(case.root, "manager"), permit, ticket)
    else:
        assert DurableManager(worker.store(case.root, "manager"), permit, ticket).ticket == ticket


def test_late_reservation_and_missing_cross_store_record(case):
    worker.initialise(case.root, "manager")
    worker.initialise(case.root, "issuer")
    worker.issue_stage(case.root, "intent")
    assert worker.issue_stage(case.root, "reconcile").decision == b"RETIRED"
    # Previously committed outbox request can arrive after retirement: permanently orphaned.
    assert worker.issue_stage(case.root, "reserve").decision == b"ALLOCATED"
    assert case.run("inspect")["allocated"] == 43
    assert case.run("inspect", "issuer")["phases"] == ["RETIRED"]
    with pytest.raises(Unavailable):
        worker.issue_stage(case.root, "attach")
    before = (case.root / "issuer/authority.sqlite3").read_bytes()
    (case.root / "manager/authority.sqlite3").unlink()
    assert "unavailable" in case.run("issue-reconcile", "issuer")
    assert (case.root / "issuer/authority.sqlite3").read_bytes() == before


def test_blocked_publication_preserves_committed_result(case):
    worker.initialise(case.root, "manager")
    worker.initialise(case.root, "issuer")
    for stage in STAGES[:6]:
        worker.issue_stage(case.root, stage)
    owner = worker.facade(case.root, "issuer")
    before = owner.ticket
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setblocking(False)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
    try:
        for _ in range(128):
            try:
                left.send(b"f" * 1024)
            except BlockingIOError:
                break
        else:
            pytest.fail("fixture did not fill bounded socket buffer")
        with pytest.raises(Unavailable, match="storage-BlockingIOError"):
            owner.retrieve_committed(b"c" * 32, b"recipient", left)
        assert owner._store.inspect(b"worker")[0] == before
    finally:
        left.close()
        right.close()


def test_strict_counters_and_operation_limit_preflight(case):
    from pqdid.persistence.records import MAX_COUNTER, HeadTicket, WriterPermit

    for generation in (True, 0, -1, MAX_COUNTER + 1):
        with pytest.raises(Unavailable):
            WriterPermit(b"worker", generation)
    for sequence in (True, 0, MAX_COUNTER + 1):
        with pytest.raises(Unavailable):
            HeadTicket(sequence, b"a" * 32, b"b" * 32, 1)
    permit, ticket = worker.initialise(case.root, "manager")
    owner = worker.store(case.root, "manager")
    _, cp, entries = owner.inspect(b"worker")
    with pytest.raises(Unavailable, match="counter-exhausted"):
        with owner._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            owner._write(
                c,
                replace(ticket, sequence=MAX_COUNTER),
                cp,
                entries,
                b"e" * 32,
                b"request",
                b"decision",
                b"",
                permit.generation,
                permit.principal,
            )
    assert owner.inspect(b"worker")[0] == ticket
