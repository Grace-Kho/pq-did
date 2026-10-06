"""Fixed-store owner process boundary around the unchanged durable pilot.

Provisioning, OS isolation and full application approval remain external. This
module is not a daemon installer, raw SQL interface or PQ-DAA authenticator.
"""

import os
import select
import signal
import socket
import time
from contextlib import contextmanager
from types import SimpleNamespace

from pqdid.codec import EncodingError
from pqdid.recovery_records import ApprovedChallenge, ChallengeRecord, IssuedRecord, Role
from pqdid.statements import decode_context, decode_state
from pqdid.verifier_state import Presentation, StoredChallenge

from .codec import Unavailable, require
from .endpoint_policy import EndpointPolicy
from .lifecycle import DurableIssuer, DurableManager, DurableVerifier
from .owner_auth import AuthorityPolicy
from .owner_ipc import (
    ACCEPTS,
    CONNECTIONS,
    IDLE_SECONDS,
    OPERATION_SECONDS,
    OWNER_SECONDS,
    OwnerClient,
    endpoint_path,
    peer_credentials,
    receive,
    send,
)
from .records import HeadTicket, Outcome, WriterPermit
from .sqlite_store import SQLiteStore

ARITY = {
    b"status": 0,
    b"admit": 1,
    b"replace": 2,
    b"reserve": 4,
    b"reservation": 1,
    b"allocation-count": 0,
    b"register": 3,
    b"verify": 5,
    b"intent": 5,
    b"attach": 3,
    b"pending": 4,
    b"claim": 3,
    b"certify": 5,
    b"reconcile": 3,
    b"retrieve": 1,
}
ROLE_OPS = {
    Role.MANAGER: {b"reserve", b"reservation", b"allocation-count"},
    Role.VERIFIER: {b"register", b"verify"},
    Role.ISSUER: {
        b"intent",
        b"attach",
        b"pending",
        b"claim",
        b"certify",
        b"reconcile",
        b"retrieve",
    },
}
COMMON = {b"status", b"admit", b"replace"}
MUTATIONS = {
    b"reserve",
    b"register",
    b"intent",
    b"attach",
    b"pending",
    b"claim",
    b"certify",
    b"reconcile",
}


class RequestDeadline(BaseException):
    """Unwind reference catch-all handlers; never turn a timeout into acceptance."""


def _request_alarm(_number, _frame):
    raise RequestDeadline()


def ticket(value):
    require(type(value) is tuple and len(value) == 4, "bad-request")
    return HeadTicket(*value)


def identifier(value):
    require(type(value) is bytes and len(value) == 32, "bad-request")
    return value


class ContextStore(SQLiteStore):
    """Internal adapter: bind every IPC transition to its authenticated logical caller.

    Existing store format/commit implementation is unchanged. The extra local
    request prefix contains scope/principal, never the capability secret.
    """

    _context = None

    @contextmanager
    def _authenticated(self, principal, scope, prior):
        require(self._context is None, "owner-busy")
        self._context = (principal.name, scope, prior)
        try:
            yield
        finally:
            self._context = None

    def _transition(self, permit, expected, operation, kind, arguments, prepare):
        require(self._context is not None, "missing-caller-context")
        name, scope, prior = self._context
        return super()._transition(
            permit,
            expected if prior is None else prior,
            operation,
            kind,
            ((b"IPC1", scope, name), *arguments),
            prepare,
        )


class ManagerClient:
    """Configured owner-to-owner reader; no manager database or client-selected path.

    The small _store identity adapter is required by the existing reconciliation
    facade. It contains only its pinned public ServiceKey, never a store handle.
    """

    def __init__(self, client: OwnerClient, key, issuer_service):
        require(key.role is Role.MANAGER)
        self._client, self._issuer = client, identifier(issuer_service)
        self._store = SimpleNamespace(key=key)
        self.parameters = key.parameters

    def snapshot(self):
        response = self._client.call(b"allocation-count")
        require(
            type(response) is tuple and len(response) == 2 and response[0] == b"COUNT",
            "manager-unavailable",
        )
        require(type(response[1]) is int and 0 <= response[1] <= 1 << 20, "manager-unavailable")
        return SimpleNamespace(allocated_count=response[1])

    def reservation(self, issuer_service, issue_operation):
        require(issuer_service == self._issuer, "wrong-issuer")
        response = self._client.call(b"reservation", (identifier(issue_operation),))
        require(
            type(response) is tuple and len(response) == 2 and response[0] == b"RESERVATION",
            "manager-unavailable",
        )
        return response[1]


class Owner:
    def __init__(
        self,
        store: ContextStore,
        policy: AuthorityPolicy,
        path,
        writer,
        *,
        manager=None,
        delivery_sessions=(),
        endpoint_policy=None,
    ):
        require(type(store) is ContextStore and store._policy is policy, "owner-configuration")
        require(writer in policy._writers, "owner-configuration")
        require(type(delivery_sessions) is tuple and len(delivery_sessions) <= 64)
        require(all(type(row) is tuple and len(row) == 2 for row in delivery_sessions))
        require(
            all(
                type(s) is bytes and 1 <= len(s) <= 256 and policy.recipient_exists(r)
                for s, r in delivery_sessions
            ),
            "delivery-configuration",
        )
        require(
            len({s for s, _ in delivery_sessions}) == len(delivery_sessions),
            "delivery-configuration",
        )
        require((manager is not None) == (store.key.role is Role.ISSUER), "manager-configuration")
        self._store, self._policy, self._writer = store, policy, writer
        self._path, self._manager, self._delivery = path, manager, dict(delivery_sessions)
        require(
            endpoint_policy is None or type(endpoint_policy) is EndpointPolicy, "endpoint-policy"
        )
        self._endpoint_policy = endpoint_policy
        self._permit = None
        self._facade = None
        self.metrics = {
            "accepted": 0,
            "frames": 0,
            "denied": 0,
            "errors": 0,
            "timeouts": 0,
            "peers": [],
            "responses": 0,
            "connection_peak": 0,
        }

    def _current(self):
        require(self._permit is not None, "not-admitted")
        current, _, _ = self._store.inspect(self._writer)
        kind = {
            Role.MANAGER: DurableManager,
            Role.ISSUER: DurableIssuer,
            Role.VERIFIER: DurableVerifier,
        }
        self._facade = kind[self._store.key.role](self._store, self._permit, current)
        return self._facade

    def _control_reply(self, connection, result):
        with self._store._connection() as c:
            c.execute("BEGIN IMMEDIATE")
            head, _, _, writer, _ = self._store._load(c)
            self._store._fence(self._permit, head, writer)
            require(head == self._facade.ticket, "stale-publication")
            send(connection, result)

    def _dispatch(self, principal, operation, args, connection):
        pp = self._store.key.parameters
        if operation == b"status":
            head, cp, _ = self._store.inspect(self._writer)
            # Counts/head only: no sessions, nonces, attributes, credentials or secrets.
            counts = (
                getattr(cp.state, "allocated_count", 0),
                len(getattr(cp.state, "challenges", ())),
                sum(r.consumed for r in getattr(cp.state, "challenges", ())),
                len(getattr(cp.state, "certifications", ())),
            )
            return b"STATUS", self._policy.scope, head.record(), counts
        if operation in {b"admit", b"replace"}:
            if operation == b"replace":
                permit, head = self._store.acquire(
                    principal.name, identifier(args[0]), ticket(args[1]), self._writer
                )
            else:
                head = ticket(args[0])
                permit = WriterPermit(self._writer, head.generation)
                self._store.admit(permit, head)
            self._permit = permit
            self._current()
            return b"ADMITTED", self._facade.ticket.record()
        facade = self._current()
        prior = ticket(args[1]) if operation in MUTATIONS else None
        if operation in MUTATIONS:
            identifier(args[0])
        with self._store._authenticated(principal, self._policy.scope, prior):
            if operation == b"allocation-count":
                return b"COUNT", facade.snapshot()[1].state.allocated_count
            if operation == b"reservation":
                return b"RESERVATION", facade.reservation(
                    principal.issuer_service, identifier(args[0])
                )
            if operation == b"reserve":
                reference = decode_state(pp, args[3]).reference
                result = facade.reserve(
                    args[0], principal.issuer_service, identifier(args[2]), reference, prior=prior
                )
            elif operation == b"register":
                row = args[2]
                require(type(row) is ChallengeRecord and row.consumed is False, "bad-request")
                result = facade.register(
                    args[0],
                    StoredChallenge(
                        pp,
                        decode_context(pp, row.context),
                        decode_state(pp, row.state),
                        row.require_did_state,
                    ),
                )
            elif operation == b"verify":
                require(
                    type(args[0]) is bytes
                    and type(args[2]) is tuple
                    and all(type(v) is int for v in args[2])
                    and type(args[3]) is bytes
                    and type(args[4]) is bytes,
                    "bad-request",
                )
                decision = facade.verify(
                    session=args[0],
                    context=decode_context(pp, args[1]),
                    presentation=Presentation(args[2], args[3], args[4]),
                )
                return b"DECISION", decision.value.encode()
            elif operation == b"intent":
                require(type(args[2]) is bytes and args[2] in self._delivery, "unapproved-session")
                require(type(args[3]) is ApprovedChallenge, "bad-request")
                result = facade.intent(
                    args[0],
                    args[2],
                    self._delivery[args[2]],
                    args[3],
                    self._manager._store.key.service_id,
                    decode_state(pp, args[4]).reference,
                )
            elif operation in {b"attach", b"reconcile"}:
                method = facade.attach if operation == b"attach" else facade.reconcile
                result = method(args[0], identifier(args[2]), self._manager)
            elif operation == b"pending":
                result = facade.pending(args[0], identifier(args[2]), identifier(args[3]))
            elif operation == b"claim":
                result = facade.claim_signing(args[0], identifier(args[2]))
            elif operation == b"certify":
                require(type(args[3]) is IssuedRecord, "bad-request")
                issue_operation = identifier(args[2])
                entries = facade.snapshot()[2]
                require(issue_operation in entries, "missing-intent")
                recipient = entries[issue_operation][1][1]
                result = facade.log_certificate(
                    args[0], issue_operation, args[3], recipient, ticket(args[4])
                )
            elif operation == b"retrieve":
                require(time.monotonic() <= self._request_deadline, "operation-deadline")
                # Core publish authenticates the immutable recipient and fences socket enqueue.
                facade.retrieve_committed(identifier(args[0]), principal.recipient, connection)
                return None
            else:
                raise Unavailable("unsupported-operation")
        if type(result) is Outcome:
            return (
                b"OUTCOME",
                result.decision,
                result.response,
                result.ticket.record(),
                result.replay,
            )
        require(type(result) is HeadTicket, "unavailable")
        return b"SIGNING", result.record()

    def _handle(self, connection):
        started = time.monotonic()
        self._request_deadline = started + OPERATION_SECONDS
        previous_handler = signal.signal(signal.SIGALRM, _request_alarm)
        signal.setitimer(signal.ITIMER_REAL, OPERATION_SECONDS)
        try:
            peer = peer_credentials(connection)
            request = receive(connection)
            require(type(request) is tuple and len(request) == 5, "bad-request")
            version, scope, secret, operation, args = request
            require(
                type(version) is int and version == 1 and type(operation) is bytes, "bad-request"
            )
            principal = self._policy.authenticate(secret, scope, peer)
            self._policy.authorise(principal, operation)
            require(
                operation in ARITY and operation in COMMON | ROLE_OPS[self._store.key.role],
                "unsupported-operation",
            )
            require(type(args) is tuple and len(args) == ARITY[operation], "bad-request")
            self.metrics["peers"].append((peer, principal.name.hex(), operation.decode("ascii")))
            result = self._dispatch(principal, operation, args, connection)
            if result is not None:
                require(time.monotonic() <= self._request_deadline, "operation-deadline")
                if operation == b"status":
                    send(connection, result)
                else:
                    self._control_reply(connection, result)
            self.metrics["responses"] += 1
        except (
            RequestDeadline,
            Unavailable,
            EncodingError,
            ValueError,
            TypeError,
            KeyError,
            OSError,
        ) as error:
            self.metrics["errors"] += 1
            label = (
                "operation-deadline"
                if type(error) is RequestDeadline
                else str(error)
                if type(error) is Unavailable
                else "bad-request"
            )
            safe = {
                "denied",
                "fenced-writer",
                "stale-head",
                "stale-publication",
                "not-admitted",
                "operation-conflict",
                "superseded-grant",
                "bad-request",
                "malformed-frame",
                "unsupported-operation",
                "wrong-recipient",
                "not-releasable",
                "missing-outcome",
                "operation-deadline",
                "unapproved-session",
                "delayed-signature",
                "not-pending",
            }
            label = label if label in safe else "unavailable"
            self.metrics["denied"] += int(label == "denied")
            try:
                send(connection, (b"ERROR", label.encode()))
            except OSError, Unavailable:
                pass  # Already committed effects remain; no retry or regeneration.
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)

    def serve(self, *, stop_fd=None, ready=None):
        """Bounded event loop. Optional supervisor FD is configured internally, never via IPC."""
        if self._endpoint_policy is not None:
            self._endpoint_policy.bind_identity()
        path = endpoint_path(self._path, exists=False, policy=self._endpoint_policy)
        active = {}
        deadline = time.monotonic() + OWNER_SECONDS
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        bound = None
        try:
            listener.bind(str(path))
            os.chmod(path, 0o600 if self._endpoint_policy is None else 0o660)
            bound = path.stat().st_ino
            endpoint_path(path, exists=True, policy=self._endpoint_policy)
            listener.listen(CONNECTIONS)
            listener.setblocking(False)
            if ready is not None:
                ready()
            while time.monotonic() < deadline and self.metrics["accepted"] < ACCEPTS:
                now = time.monotonic()
                for connection, expires in list(active.items()):
                    if now >= expires:
                        connection.close()
                        del active[connection]
                        self.metrics["timeouts"] += 1
                inputs = [listener, *active]
                if stop_fd is not None:
                    inputs.append(stop_fd)
                readable, _, _ = select.select(
                    inputs, [], [], min(IDLE_SECONDS, max(0, deadline - now))
                )
                if stop_fd is not None and stop_fd in readable:
                    break
                if listener in readable:
                    connection, _ = listener.accept()
                    connection.setblocking(False)
                    self.metrics["accepted"] += 1
                    if len(active) >= CONNECTIONS:
                        connection.close()
                    else:
                        active[connection] = time.monotonic() + IDLE_SECONDS
                        self.metrics["connection_peak"] = max(
                            self.metrics["connection_peak"], len(active)
                        )
                for connection in readable:
                    if connection in active:
                        self.metrics["frames"] += 1
                        try:
                            self._handle(connection)
                        finally:
                            connection.close()
                            del active[connection]
        finally:
            for connection in active:
                connection.close()
            listener.close()
            if bound is not None and path.exists() and path.lstat().st_ino == bound:
                path.unlink()
        return self.metrics
