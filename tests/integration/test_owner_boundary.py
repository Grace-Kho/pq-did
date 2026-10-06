"""Bounded IPC access tests using independently started owners and clients, same WSL UID."""

import json
import os
import resource
import select
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

import durable_worker as legacy
import owner_worker as worker
import pytest
from test_durable_authority import fixtures  # noqa: F401 - shared immutable fixture factory

from pqdid.persistence.codec import decode, encode
from pqdid.persistence.owner_auth import ADMIN, ISSUER, MANAGER, OBSERVER, RECIPIENT, VERIFIER
from pqdid.statements import decode_context, encode_context
from pqdid.verifier_state import Decision

EVIDENCE = Path(__file__).resolve().parents[2] / "docs/data/s2_authority_owner_boundary_1"
CASES = []
OP = b"o" * 32
ISSUE = b"i" * 32


class Case:
    def __init__(self, root, name):
        self.root, self.name = root, name
        self.children, self.events, self.owners = [], [], {}
        self.started = time.monotonic()
        self.serial = 0
        self.peak_children = 0
        self.disk_observed = 0

    def sample(self):
        self.disk_observed = max(
            self.disk_observed, sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())
        )

    def spawn(self, *arguments):
        running = sum(p.returncode is None for p in self.children)
        assert running < 4  # Unchanged four-controlled-descendant allowance.
        command = [sys.executable, str(Path(worker.__file__).resolve()), str(self.root), *arguments]
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        process.pilot_command = command
        self.children.append(process)
        self.peak_children = max(self.peak_children, running + 1)
        return process

    def line(self, process):
        assert select.select([process.stdout], [], [], 4)[0], "bounded fixture IPC deadline"
        line = process.stdout.readline(140000)
        assert line, process.stderr.read(8192).decode()
        self.sample()
        if line.startswith(b"RESULT "):
            result = decode(bytes.fromhex(line[7:].decode()))
            self.events.append({"pid": process.pid, **worker.summary(result)})
            return result
        result = json.loads(line)
        self.events.append(result)
        return result

    def finish(self, process, *, kill=False):
        if kill:
            process.kill()
        pid, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        stderr = process.stderr.read(8192)
        self.events.append(
            {
                "pid": pid,
                "command": process.pilot_command,
                "exit": process.returncode,
                "termination": "SIGKILL" if kill else "normal",
                "maxrss_bytes": usage.ru_maxrss * 1024,
                "cpu_seconds": usage.ru_utime + usage.ru_stime,
            }
        )
        assert process.returncode == (-signal.SIGKILL if kill else 0), stderr.decode()
        assert not stderr
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()

    def provision(self, role):
        if not (self.root / role).exists():
            legacy.initialise(self.root, role)
        if (self.root / (role + ".grants")).exists():
            return
        permission = MANAGER if role == "manager" else ISSUER if role == "issuer" else VERIFIER
        grants = [
            (b"admin", os.urandom(32), tuple(sorted(ADMIN)), os.getuid(), os.getgid(), None, None),
            (
                b"writer",
                os.urandom(32),
                tuple(sorted(permission)),
                os.getuid(),
                os.getgid(),
                b"S" * 32 if role == "manager" else None,
                None,
            ),
            (
                b"observer",
                os.urandom(32),
                tuple(sorted(OBSERVER)),
                os.getuid(),
                os.getgid(),
                None,
                None,
            ),
        ]
        if role == "issuer":
            for name, recipient in (
                (b"recipient-a", b"recipient-A"),
                (b"recipient-b", b"recipient-B"),
            ):
                grants.append(
                    (
                        name,
                        os.urandom(32),
                        tuple(RECIPIENT),
                        os.getuid(),
                        os.getgid(),
                        None,
                        recipient,
                    )
                )
        (self.root / (role + ".grants")).write_bytes(encode(tuple(grants)))

    def start(
        self,
        role,
        *,
        writer="owner-1",
        name="s",
        fault_op="none",
        fault_point="none",
        activate=True,
    ):
        self.provision(role)
        (self.root / (role + "-ipc")).mkdir(mode=0o700, exist_ok=True)
        endpoint = self.root / (role + "-ipc") / name
        process = self.spawn("owner", role, writer, str(endpoint), fault_op, fault_point)
        ready = self.line(process)
        assert ready["ready"] and ready["socket_mode"] == "0o600"
        assert (ready["uid"], ready["gid"]) == (os.getuid(), os.getgid())
        self.owners[(role, name)] = process
        if activate:
            prior = self.rpc(role, b"status", principal=b"admin", endpoint=endpoint)[2]
            result = self.rpc(
                role, b"replace", (os.urandom(32), prior), principal=b"admin", endpoint=endpoint
            )
            assert result[0] == b"ADMITTED", result
        return process

    def request_process(
        self,
        role,
        operation,
        args=(),
        *,
        principal=b"writer",
        mode=b"call",
        endpoint=None,
        secret=None,
        scope=None,
    ):
        policy = worker.policy(self.root, role)
        grant = next(p for p in policy._principals if p.name == principal)
        endpoint = endpoint or self.root / (role + "-ipc") / "s"
        self.serial += 1
        filename = "request-" + str(self.serial)
        (self.root / filename).write_bytes(
            encode(
                (
                    os.fsencode(endpoint),
                    policy.scope if scope is None else scope,
                    grant.secret if secret is None else secret,
                    operation,
                    args,
                    mode,
                )
            )
        )
        return self.spawn("client", filename)

    def rpc(self, role, operation, args=(), **options):
        process = self.request_process(role, operation, args, **options)
        result = self.line(process)
        self.finish(process)
        return result

    def head(self, role):
        response = self.rpc(role, b"status", principal=b"observer")
        assert response[0] == b"STATUS", response
        return response[2]

    def reserve_args(self, prior=None):
        cp = decode((self.root / "manager.fixture").read_bytes())
        return OP, prior or self.head("manager"), ISSUE, cp.state.state

    def verify_args(self, role):
        cp = decode((self.root / (role + ".fixture")).read_bytes())
        fixture = decode((self.root / (role + ".public")).read_bytes())
        pp = legacy.store(self.root, role).key.parameters
        context = decode_context(pp, cp.state.challenges[0].context)
        return context.session, cp.state.challenges[0].context, fixture[1], fixture[2], fixture[3]

    def issue(self, *, fault=False):
        self.start("manager")
        self.start(
            "issuer",
            fault_op="retrieve" if fault else "none",
            fault_point="enqueue-before-return" if fault else "none",
        )
        approved, issued = decode((self.root / "issued.fixture").read_bytes())
        reference = decode((self.root / "manager.fixture").read_bytes()).state.state
        result = self.rpc(
            "issuer", b"intent", (ISSUE, self.head("issuer"), b"pilot-session", approved, reference)
        )
        assert result[0:2] == (b"OUTCOME", b"INTENT"), result
        assert self.rpc("manager", b"reserve", self.reserve_args())[1] == b"ALLOCATED"
        for method, op, extra in (
            (b"attach", b"a" * 32, ()),
            (b"pending", b"p" * 32, (b"n" * 32,)),
            (b"claim", b"s" * 32, ()),
        ):
            result = self.rpc("issuer", method, (op, self.head("issuer"), ISSUE, *extra))
            assert result[0] in {b"OUTCOME", b"SIGNING"}, result
        signing = result[1]
        result = self.rpc("issuer", b"certify", (b"c" * 32, signing, ISSUE, issued, signing))
        assert result[0:2] == (b"OUTCOME", b"CERTIFIED") and result[2] == b"", result
        return issued

    def close(self):
        for process in self.children:
            if process.returncode is not None:
                continue
            if process in self.owners.values():
                process.stdin.write(b"stop\n")
                process.stdin.flush()
                result = self.line(process)
                assert "metrics" in result, result
                self.finish(process)
            else:
                self.finish(process, kill=True)
        self.sample()
        return {
            "case": self.name,
            "seconds": time.monotonic() - self.started,
            "temporary_bytes_observed_peak": self.disk_observed,
            "maximum_owned_children": self.peak_children,
            "coordinator_cumulative_maxrss_bytes": resource.getrusage(
                resource.RUSAGE_SELF
            ).ru_maxrss
            * 1024,
            "events": self.events,
        }


@pytest.fixture
def case(fixtures, request):  # noqa: F811 - pytest injects the imported shared fixture.
    with tempfile.TemporaryDirectory(prefix="o") as directory:
        root = Path(directory)
        for name, data in fixtures.items():
            (root / name).write_bytes(data)
        value = Case(root, request.node.name)
        try:
            yield value
        finally:
            record = value.close()
            encoded_log = json.dumps(record, indent=2)
            for path in root.glob("*.grants"):
                for grant in decode(path.read_bytes()):
                    assert grant[1].hex() not in encoded_log
                    for database in root.glob("*/authority.sqlite3"):
                        assert grant[1] not in database.read_bytes()
            CASES.append(record)
            (EVIDENCE / ("cases-" + os.environ["PQDID_PILOT_RUN"] + ".json")).write_text(
                json.dumps(CASES, indent=2) + "\n"
            )


def test_access_permissions_and_read_redaction(case):
    case.start("manager", activate=False)
    assert case.rpc("manager", b"reserve", case.reserve_args())[1] == b"not-admitted"
    for principal in (b"writer", b"observer", b"admin"):
        assert case.rpc("manager", b"status", principal=principal)[0] == b"STATUS"
    prior = case.head("manager")
    assert case.rpc("manager", b"replace", (OP, prior), principal=b"writer")[1] == b"denied"
    assert case.rpc("manager", b"replace", (b"A" * 32, prior), principal=b"admin")[0] == b"ADMITTED"
    assert (
        case.rpc("manager", b"admit", (case.head("manager"),), principal=b"admin")[0] == b"ADMITTED"
    )
    args = case.reserve_args()
    for principal in (b"observer", b"admin"):
        assert case.rpc("manager", b"reserve", args, principal=principal)[1] == b"denied"
    result = case.rpc("manager", b"reserve", args)
    assert result[0:2] == (b"OUTCOME", b"ALLOCATED")
    assert case.rpc("manager", b"reservation", (ISSUE,))[0] == b"RESERVATION"
    assert case.rpc("manager", b"allocation-count") == (b"COUNT", 43)
    status = case.rpc("manager", b"status", principal=b"admin")
    assert len(status) == 4 and status[3] == (43, 0, 0, 0)


@pytest.mark.parametrize("fault", ["missing", "invalid", "scope", "peer", "empty-policy"])
def test_access_authentication_fails_closed(case, fault):
    case.provision("manager")
    if fault in {"peer", "empty-policy"}:
        path = case.root / "manager.grants"
        rows = decode(path.read_bytes())
        rows = (
            ()
            if fault == "empty-policy"
            else tuple(
                (n, s, perms, uid + 1, gid, issuer, recipient)
                for n, s, perms, uid, gid, issuer, recipient in rows
            )
        )
        path.write_bytes(encode(rows))
        # Restore client metadata after the owner loads the negative policy configuration.
        owner = case.start("manager", activate=False)
        if fault == "empty-policy":
            # A credential absent from the owner's empty grant table remains unauthorised.
            rows = (
                (
                    b"writer",
                    os.urandom(32),
                    tuple(MANAGER),
                    os.getuid(),
                    os.getgid(),
                    b"S" * 32,
                    None,
                ),
            )
        path.write_bytes(encode(rows))
        assert owner.returncode is None
    else:
        case.start("manager")
    options = (
        {"secret": b""}
        if fault == "missing"
        else {"secret": b"X" * 32}
        if fault == "invalid"
        else {"scope": b"X" * 32}
        if fault == "scope"
        else {}
    )
    assert case.rpc("manager", b"status", **options) == (b"ERROR", b"denied")


@pytest.mark.parametrize(
    "field", [b"role", b"recipient", b"instance", b"namespace", b"uid", b"pid", b"path", b"sql"]
)
def test_access_forged_fields_and_unsupported_operations(case, field):
    case.start("manager")
    assert case.rpc("manager", b"status", ((field, b"forged"),)) == (b"ERROR", b"bad-request")
    assert case.rpc("manager", field, ()) == (b"ERROR", b"denied")
    assert case.rpc("manager", b"allocation-count") == (b"COUNT", 42)


@pytest.mark.parametrize(
    "wire", ["truncated", "trailing", "oversized", "unsupported-version", "partial", "idle"]
)
def test_access_bounded_frames_and_timeouts(case, wire):
    case.start("manager")
    policy = worker.policy(case.root, "manager")
    grant = next(p for p in policy._principals if p.name == b"writer")
    valid = encode((1, policy.scope, grant.secret, b"status", ()))
    packet = {
        "truncated": valid[:-1],
        "trailing": valid + b"x",
        "oversized": b"x" * 65537,
        "unsupported-version": encode((2, policy.scope, grant.secret, b"status", ())),
        "partial": valid[:2],
        "idle": b"",
    }[wire]
    # The child constructs oversized wire bytes without an oversized fixture container.
    if wire == "oversized":
        packet = b"OVERSIZE"
    response = case.rpc("manager", b"status", packet, mode=b"idle" if wire == "idle" else b"raw")
    assert response[0] == b"ERROR"
    assert case.rpc("manager", b"allocation-count") == (b"COUNT", 42)


def test_lifecycle_operation_identity_and_stale_connected_client(case):
    old = case.start("manager")
    args = case.reserve_args()
    first = case.rpc("manager", b"reserve", args)
    repeated = case.rpc("manager", b"reserve", args)
    assert (
        first[1] == b"ALLOCATED" and repeated[1] == b"ALREADY_COMMITTED" and first[2] == repeated[2]
    )
    assert (
        case.rpc("manager", b"reserve", (*args[:2], b"J" * 32, args[3]))[1] == b"operation-conflict"
    )
    case.start("manager", writer="owner-2", name="t", activate=False)
    prepared = case.request_process(
        "manager", b"reserve", (b"z" * 32, first[3], b"j" * 32, args[3]), mode=b"connected"
    )
    assert case.line(prepared)["connected"]
    replaced = case.rpc(
        "manager",
        b"replace",
        (b"x" * 32, first[3]),
        principal=b"admin",
        endpoint=case.root / "manager-ipc/t",
    )
    assert replaced[0] == b"ADMITTED"
    prepared.stdin.write(b"go\n")
    prepared.stdin.flush()
    assert case.line(prepared)[1] == b"fenced-writer"
    case.finish(prepared)
    assert old.returncode is None
    assert case.rpc("manager", b"allocation-count", endpoint=case.root / "manager-ipc/t") == (
        b"COUNT",
        43,
    )


def test_lifecycle_concurrent_verification_and_two_audiences(case):
    case.start("verifier0")
    args = case.verify_args("verifier0")
    one = case.request_process("verifier0", b"verify", args, mode=b"connected")
    two = case.request_process("verifier0", b"verify", args, mode=b"connected")
    assert case.line(one)["connected"] and case.line(two)["connected"]
    for process in (one, two):
        process.stdin.write(b"go\n")
        process.stdin.flush()
    answers = [case.line(p) for p in (one, two)]
    for process in (one, two):
        case.finish(process)
    assert sorted(r[1] for r in answers) == sorted(
        [Decision.ACCEPTED.value.encode(), Decision.UNKNOWN.value.encode()]
    )
    case.start("verifier1")
    assert (
        case.rpc("verifier1", b"verify", case.verify_args("verifier1"))[1]
        == Decision.ACCEPTED.value.encode()
    )
    p0 = worker.policy(case.root, "verifier0")
    secret = next(p.secret for p in p0._principals if p.name == b"writer")
    assert case.rpc("verifier1", b"status", secret=secret)[1] == b"denied"
    assert case.rpc("verifier0", b"verify", args)[1] == Decision.UNKNOWN.value.encode()
    cp = decode((case.root / "verifier0.fixture").read_bytes())
    row = cp.state.challenges[0]
    pp = legacy.store(case.root, "verifier0").key.parameters
    row = replace(
        row, context=encode_context(pp, replace(decode_context(pp, row.context), nonce=b"Z" * 32))
    )
    assert case.rpc("verifier0", b"register", (OP, case.head("verifier0"), row))[1] == b"REGISTERED"
    assert case.rpc("verifier1", b"register", (OP, case.head("verifier1"), row))[0] == b"ERROR"


def test_lifecycle_recipient_binding_and_redelivery(case):
    issued = case.issue()
    for principal in (b"admin", b"writer", b"observer"):
        assert case.rpc("issuer", b"retrieve", (b"c" * 32,), principal=principal)[1] == b"denied"
    assert (
        case.rpc("issuer", b"retrieve", (b"c" * 32,), principal=b"recipient-b")[1]
        == b"wrong-recipient"
    )
    assert (
        case.rpc("issuer", b"retrieve", (b"c" * 32, b"recipient-A"), principal=b"recipient-b")[1]
        == b"bad-request"
    )
    assert case.rpc("issuer", b"retrieve", (b"c" * 32,), principal=b"recipient-a") == issued
    assert case.rpc("issuer", b"retrieve", (b"c" * 32,), principal=b"recipient-a") == issued
    assert case.rpc("issuer", b"status", principal=b"recipient-a")[1] == b"denied"
    status = case.rpc("issuer", b"status", principal=b"observer")
    assert status[3] == (0, 0, 0, 1)
    result = case.rpc("issuer", b"reconcile", (b"r" * 32, status[2], ISSUE))
    assert result[1] == b"CERTIFIED"


@pytest.mark.parametrize("role,operation", [("manager", b"reserve"), ("verifier0", b"verify")])
def test_lifecycle_owner_crash_after_commit_before_ipc_reply(case, role, operation):
    owner = case.start(role, fault_op=operation.decode(), fault_point="commit-before-ack")
    args = case.reserve_args() if role == "manager" else case.verify_args(role)
    pending = case.request_process(role, operation, args)
    assert case.line(owner)["barrier"] == "commit-before-ack"
    case.finish(owner, kill=True)
    assert case.line(pending)[0] == b"ERROR"
    case.finish(pending)
    # Supervisor removes only the pathname left by its known killed fixture owner.
    (case.root / (role + "-ipc") / "s").unlink()
    case.start(role, activate=False)
    head = case.head(role)
    assert case.rpc(role, b"admit", (head,), principal=b"admin")[0] == b"ADMITTED"
    retry = case.rpc(role, operation, args)
    assert retry[1] == (
        b"ALREADY_COMMITTED" if role == "manager" else Decision.UNKNOWN.value.encode()
    )


def test_lifecycle_unavailable_endpoint_has_no_fallback(case):
    owner = case.start("manager")
    head = case.head("manager")
    case.finish(owner, kill=True)
    assert (
        case.rpc(
            "manager",
            b"reserve",
            (OP, head, ISSUE, decode((case.root / "manager.fixture").read_bytes()).state.state),
        )[0]
        == b"ERROR"
    )
    assert legacy.summary(case.root, "manager")["allocated"] == 42


def test_lifecycle_recipient_lost_delivery_over_real_ipc(case):
    issued = case.issue(fault=True)
    owner = case.owners[("issuer", "s")]
    lost = case.request_process(
        "issuer", b"retrieve", (b"c" * 32,), principal=b"recipient-a", mode=b"lost"
    )
    assert case.line(lost)["sent_without_reading"]
    assert case.line(owner)["barrier"] == "enqueue-before-return"
    case.finish(lost, kill=True)
    owner.stdin.write(b"go\n")
    owner.stdin.flush()
    assert case.rpc("issuer", b"retrieve", (b"c" * 32,), principal=b"recipient-a") == issued
    assert (
        case.rpc("issuer", b"retrieve", (b"a" * 32,), principal=b"recipient-a")[1]
        == b"not-releasable"
    )
    assert case.rpc("issuer", b"status", principal=b"observer")[3][-1] == 1


def test_bounds_connection_capacity_and_processing_deadline(case):
    owner = case.start("manager", fault_op="reserve", fault_point="rows-before-commit")
    assert case.rpc("manager", b"status", mode=b"capacity") == (b"CAPACITY", True)
    prior = case.head("manager")
    request = case.request_process("manager", b"reserve", case.reserve_args(prior))
    assert case.line(owner)["barrier"] == "rows-before-commit"
    assert case.line(request) == (b"ERROR", b"operation-deadline")
    case.finish(request)
    assert case.head("manager") == prior
    assert case.rpc("manager", b"allocation-count") == (b"COUNT", 42)
