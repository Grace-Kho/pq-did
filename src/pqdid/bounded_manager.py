"""Opt-in synthetic/reference durable manager; no live authority or key custody.

One unchanged SQLite authority database owns checkpoint, signed history, nonce set,
operation response and head. Sign outside the transaction against an exact admitted
ticket; compare again under BEGIN IMMEDIATE before writing. Public history is not a
recipient-bound credential. No process-local candidate is a publication source.
"""

import socket
from contextlib import contextmanager
from dataclasses import replace
from threading import Lock

from pqdid.parameters import validate_parameters_structure
from pqdid.persistence import sqlite_store
from pqdid.persistence.codec import Unavailable, decode, encode, require
from pqdid.persistence.lifecycle import DurableManager
from pqdid.recovery import _manager
from pqdid.recovery_records import Role
from pqdid.revocation_state import ManagerStatus, build_revocation_request_message
from pqdid.signing_adapters import ManagerSigningAdapter, TrustedSigningKey
from pqdid.statements import encode_state
from pqdid.witness_updates import DEFAULT_UPDATE_LIMITS, decode_update


class _Access:
    """Trusted existing write policy and a fixed head, never request-selected identity."""

    def __init__(self, store, permit, ticket):
        self.store, self.permit, self.ticket = store, permit, ticket

    def allow(self, key, operation, typed_inputs):
        store = self.store
        if (
            key.authority_role is not Role.MANAGER
            or key.service_id != store.key.service_id
            or key.parameters != store.key.parameters
            or operation not in {"state", "update", "current"}
        ):
            return False
        store.admit(self.permit, self.ticket)
        return True


class BoundedDurableManager:
    """Owner-local typed facade; caller supplies no signer, context or finished result.

    Construction requires an independently retained expected ticket and writer permit.
    It never refreshes that expectation from a self-consistent store. After an uncertain
    commit the caller must reconcile explicitly; retrieval never generates signatures.
    The SQLite store and authorisation policy are trusted dependencies, not a sandbox.
    """

    def __init__(self, store, permit, ticket, *, signing_key: TrustedSigningKey):
        require(type(signing_key) is TrustedSigningKey, "signing-key")
        require(signing_key.service_id == store.key.service_id, "wrong-signing-service")
        validate_parameters_structure(signing_key.parameters, expected=store.key.parameters)
        self._owner = DurableManager(store, permit, ticket)
        # Reuse the existing bounded public-identity/import check and fixed manager role.
        ManagerSigningAdapter(signing_key)
        self._key, self._serial = signing_key, Lock()

    @property
    def ticket(self):
        return self._owner.ticket

    @property
    def parameters(self):
        return self._owner._store.key.parameters

    @contextmanager
    def _operation(self):
        require(self._serial.acquire(blocking=False), "manager-busy")
        try:
            yield
        finally:
            self._serial.release()

    @contextmanager
    def _admitted(self, expected):
        owner, store = self._owner, self._owner._store
        store._authorise(owner._permit.principal, "write")
        with store._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            ticket, cp, entries, writer, ops = store._load(connection)
            store._fence(owner._permit, ticket, writer)
            require(ticket == expected, "stale-head")
            store._validate(cp)
            yield connection, ticket, cp, entries, writer, ops

    def snapshot(self):
        with self._operation(), self._admitted(self.ticket) as (_, ticket, cp, entries, _, _):
            return ticket, cp, entries

    def reserve(self, operation, issuer_service, issue_operation, reference):
        """Unchanged authorised allocation contract; no cross-store transaction."""
        with self._operation():
            return self._owner.reserve(operation, issuer_service, issue_operation, reference)

    def reservation(self, issuer_service, issue_operation):
        _, _, entries = self.snapshot()
        return entries.get(b"allocation:" + issuer_service + issue_operation)

    def _capture(self, operation):
        require(type(operation) is bytes and len(operation) == 32, "operation")
        with self._admitted(self.ticket) as (_, ticket, cp, _, _, ops):
            require(operation not in ops, "already-committed-use-retrieval")
            return ticket, cp

    def _candidate(self, cp, ticket):
        owner, store = self._owner, self._owner._store
        signer = ManagerSigningAdapter(
            self._key, authorisation=_Access(store, owner._permit, ticket)
        )
        return _manager(self.parameters, cp.state, replace(store._deps, signer=signer._bridge()))

    def _commit(self, operation, kind, arguments, expected, previous, checkpoint, response):
        # All byte construction/signing happened privately. This lock excludes other
        # admitted writes through the actual COMMIT; a concurrent head cannot slip in.
        owner, store = self._owner, self._owner._store
        request = encode((kind, owner._permit.principal, expected.record(), arguments))
        with self._admitted(expected) as (connection, ticket, cp, entries, writer, ops):
            require(cp == previous, "changed-checkpoint")
            require(operation not in ops, "already-committed-use-retrieval")
            result = store._write(
                connection,
                ticket,
                checkpoint,
                entries,
                operation,
                request,
                kind,
                response,
                ticket.generation,
                writer,
            )
        owner.ticket = result.ticket
        # Only the committed store can supply public bytes. An uncertain _write never
        # gets here, and never silently changes the caller's expected recovery head.
        return replace(result, response=b"")

    def revoke(self, operation, request):
        with self._operation():
            ticket, cp = self._capture(operation)
            arguments = (
                build_revocation_request_message(self.parameters, request),
                request.signature,
            )
            candidate = self._candidate(cp, ticket)
            result = candidate.revoke(request)
            require(result.status is ManagerStatus.COMMITTED, "manager-" + result.status.value)
            snap = candidate.snapshot()
            record = replace(
                cp.state,
                state=encode_state(self.parameters, snap.state),
                revoked=tuple(sorted(snap.revoked)),
                consumed_nonces=tuple(sorted(snap.consumed_nonces)),
                history=snap.history,
            )
            response = encode((record.state, result.record))
            return self._commit(
                operation, b"REVOKED", arguments, ticket, cp, replace(cp, state=record), response
            )

    def read_current(self, operation, nonce):
        """Commit a nonce-bound ordered read outcome; later reads never silently resign."""
        with self._operation():
            ticket, cp = self._capture(operation)
            result = self._candidate(cp, ticket).read_current(nonce)
            require(result.status is ManagerStatus.CURRENT, "manager-" + result.status.value)
            reply = result.reply
            response = encode(
                (reply.nonce, encode_state(self.parameters, reply.state), reply.signature)
            )
            return self._commit(operation, b"CURRENT", (nonce,), ticket, cp, cp, response)

    def updates(self, namespace, after_epoch, target_epoch, *, limits=DEFAULT_UPDATE_LIMITS):
        """Public namespace/version page, without holder identifier or recipient binding.

        This owner-local return linearises at the admitted locked snapshot. A later
        revocation does not undo that ordered historical read. Transport deployment
        remains separate; only retrieve_committed provides a locked socket enqueue.
        """
        with self._operation(), self._admitted(self.ticket) as (_, _, cp, _, _, _):
            candidate = _manager(self.parameters, cp.state, self._owner._store._deps)
            return candidate.updates(namespace, after_epoch, target_epoch, limits=limits)

    def retrieve_committed(self, operation, transport):
        """Public manager result, not issuer recipient delivery; no signing/retry.

        One nonblocking local SEQPACKET enqueue while holding the fencing/head lock.
        Old revocations remain public history. A stored CURRENT reply is withheld if
        its state has since changed; callers need a new explicit nonce-bound read.
        """
        require(type(operation) is bytes and len(operation) == 32, "operation")
        require(type(transport) is socket.socket and not transport.getblocking(), "transport")
        require(
            transport.family == socket.AF_UNIX and transport.type == socket.SOCK_SEQPACKET,
            "transport",
        )
        with self._operation(), self._admitted(self.ticket) as (_, _, cp, _, _, ops):
            require(operation in ops, "missing-outcome")
            _, decision, response = ops[operation]
            values = decode(response)
            if decision == b"REVOKED":
                state, record = values
                require(record in cp.state.history, "outcome-history-mismatch")
                update = decode_update(self.parameters, record)
                require(encode_state(self.parameters, update.new_state) == state, "outcome-state")
            elif decision == b"CURRENT":
                _, state, _ = values
                require(state == cp.state.state, "superseded-current")
            else:
                raise Unavailable("not-public-manager-outcome")
            sqlite_store._fault("before-enqueue")  # Existing inert, test-only boundary.
            sent = transport.send(response, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            require(sent == len(response), "incomplete-publication")
            sqlite_store._fault("enqueue-before-return")
        return b"REDELIVERY"
