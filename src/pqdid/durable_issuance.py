"""Isolated reference issuer/manager integration; no distributed transaction or proof.

No permissive proof implementation is defined/imported here. Existing Dependencies
defaults remain unsupported. Positive tests explicitly inject their synthetic verifier.
Private owner dependencies and in-process Python attributes are trusted, not sandboxed.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock
from types import SimpleNamespace

from pqdid import issuance as issue
from pqdid.bounded_manager import BoundedDurableManager
from pqdid.codec import EncodingError
from pqdid.parameters import validate_parameters_structure
from pqdid.persistence.codec import Unavailable, decode, require
from pqdid.persistence.sqlite_store import digest
from pqdid.recovery import _issued, _issuer, _manager
from pqdid.recovery_records import ApprovedChallenge
from pqdid.schema import decode_attributes
from pqdid.signing_adapters import BoundedDurableIssuer
from pqdid.statements import decode_state, encode_state


@dataclass(frozen=True)
class _AllocationView:
    allocated_count: int


class ManagerIssuancePort:
    """Trusted owner reference port: no manager secret/checkpoint crosses the interface.

    The issuer's existing recovery validator needs an allocation floor. Fresh witness
    reads use an admitted manager snapshot, never the historical reservation payload.
    An independent manager writer change requires explicit recovery of this owner.
    """

    def __init__(self, manager):
        require(type(manager) is BoundedDurableManager, "manager-owner")
        self._manager = manager
        # Compatibility identity for existing attach/reconcile; no raw store methods.
        self._store = SimpleNamespace(key=manager._owner._store.key)

    @property
    def parameters(self):
        return self._manager.parameters

    def snapshot(self):
        return _AllocationView(self._manager.snapshot()[1].state.allocated_count)

    def reservation(self, issuer_service, operation):
        return self._manager.reservation(issuer_service, operation)

    def registered_witness(self, identifier, reference):
        _, cp, _ = self._manager.snapshot()
        candidate = _manager(self.parameters, cp.state, self._manager._owner._store._deps)
        return candidate.registered_witness(identifier, reference)


class DurableIssuance:
    """Explicit phase orchestration of unchanged durable/reference contracts.

    Each method is owner-local and requires an admitted issuer and manager. Intent,
    reservation, attachment, pending, claim and certification are separate commits.
    Exceptions preserve the reached journal phase; reconcile is explicit, not retry.
    """

    def __init__(self, store, permit, ticket, *, manager, signing_key):
        port = store._deps.manager
        require(type(port) is ManagerIssuancePort and port._manager is manager, "manager-port")
        validate_parameters_structure(manager.parameters, expected=store.key.parameters)
        self._issuer = BoundedDurableIssuer(store, permit, ticket, signing_key=signing_key)
        self._manager, self._port, self._store, self._permit = manager, port, store, permit
        self._serial = Lock()

    @property
    def ticket(self):
        return self._issuer.ticket

    @contextmanager
    def _operation(self):
        require(self._serial.acquire(blocking=False), "issuance-busy")
        try:
            yield
        finally:
            self._serial.release()

    def stage_operation(self, operation, phase):
        """Local journal identities only; no change to any protocol signing format."""
        require(type(operation) is bytes and len(operation) == 32, "operation")
        require(
            phase in {b"reserve", b"attach", b"pending", b"claim", b"certify", b"reconcile"},
            "phase",
        )
        return digest(
            (
                b"issuer-manager",
                self._store.key.service_id,
                self._port._store.key.service_id,
                operation,
                phase,
            )
        )

    def snapshot(self):
        with self._operation():
            return self._issuer.snapshot()

    def begin(self, operation, request: issue.IssueRequest, state, recipient):
        with self._operation():
            self.stage_operation(operation, b"reserve")
            self._store._authorise(self._permit.principal, "approve-issue")
            _, cp, _ = self._issuer.snapshot()
            pp, deps = self._store.key.parameters, self._store._deps
            candidate = _issuer(pp, cp.state, deps)
            candidate._request(request)
            controller = issue._controller(
                deps.resolver.current(pp, request.did), request.did, request.version
            )
            approved = deps.authorisation.approve(pp, request, controller)
            require(
                type(approved) is bytes and approved == request.holder_approval,
                "unapproved-attributes",
            )
            values = decode_attributes(pp.schema, approved)
            require(
                values[pp.schema.did_index - 1] == request.did
                and values[pp.schema.version_index - 1] == request.version,
                "approved-did-version",
            )
            issue._state_auth(pp, state)
            intent = ApprovedChallenge(
                approved,
                encode_state(pp, state),
                request.did,
                request.version,
                controller.controller_public_key,
            )
            self._issuer.intent(
                operation,
                request.session,
                recipient,
                intent,
                self._port._store.key.service_id,
                state.reference,
            )
            self._manager.reserve(
                self.stage_operation(operation, b"reserve"),
                self._store.key.service_id,
                operation,
                state.reference,
            )
            self._issuer.attach(self.stage_operation(operation, b"attach"), operation, self._port)
            nonce = candidate._fresh_nonce(issue._Session())
            self._issuer.pending(self.stage_operation(operation, b"pending"), operation, nonce)
            return self._challenge(operation)

    def _challenge(self, operation):
        _, cp, entries = self._issuer.snapshot()
        row = entries.get(operation)
        require(row is not None and row[0] == b"PENDING", "pending-required")
        session = next((s for s in cp.state.sessions if s.name == row[1][0]), None)
        require(
            session is not None
            and session.phase is issue.SessionPhase.PENDING
            and session.identifier == row[2]
            and session.nonce == row[4]
            and session.challenge == row[1][2],
            "journal-challenge-mismatch",
        )
        pp, approved = self._store.key.parameters, row[1][2]
        return issue.EnrolmentChallenge(
            pp, approved.attributes, row[2], row[4], decode_state(pp, approved.state)
        )

    def challenge(self, operation):
        """Explicit resumption of complete PENDING only, never SIGNING/retirement."""
        with self._operation():
            return self._challenge(operation)

    def finish(self, operation, submission):
        with self._operation():
            return self._issuer.certify(
                self.stage_operation(operation, b"claim"),
                self.stage_operation(operation, b"certify"),
                operation,
                submission,
            )

    def reconcile(self, operation):
        with self._operation():
            # A later explicitly admitted head can require another reconciliation
            # (e.g. PENDING resume followed by an interrupted signing attempt).
            local_operation = digest(
                (self.stage_operation(operation, b"reconcile"), self.ticket.record())
            )
            return self._issuer.reconcile(local_operation, operation, self._port)

    def retrieve(self, operation, recipient, transport):
        with self._operation():
            return self._issuer.retrieve_committed(
                self.stage_operation(operation, b"certify"), recipient, transport
            )


def accept_delivery(holder: issue.HolderAcceptance, payload: bytes):
    """Decode the bounded stored result, then use existing atomic holder acceptance.

    Holder secret/intent stay on the holder side. This is in-memory acceptance, not
    a durable wallet, and it asserts neither current non-revocation nor authentication.
    """
    if type(holder) is not issue.HolderAcceptance:
        raise EncodingError("holder acceptance required")
    try:
        issued = _issued(holder._parameters, decode(payload))
        return holder.accept(issued)
    except MemoryError:
        return issue.IssueResult(issue.IssueStatus.RESOURCE_EXHAUSTED)
    except EncodingError, Unavailable, issue.IssueError, ValueError, TypeError:
        return issue.IssueResult(issue.IssueStatus.INVALID_INPUT)
