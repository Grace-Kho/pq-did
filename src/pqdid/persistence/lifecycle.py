"""Narrow durable facades; other reference mutations are deliberately unavailable.

The issuer API is an owner-private reconciliation journal, not a second enrolment
protocol. Approved intent and signing authorisation must come from the configured
issuer policy. Production signing and real proof verification remain unsupported.
"""

from dataclasses import replace

from pqdid.expiry import is_unexpired
from pqdid.issuance import SessionPhase
from pqdid.recovery import _manager
from pqdid.recovery_records import CertificationRecord, ChallengeRecord, IssuerSession, Role
from pqdid.revocation_state import ManagerStatus
from pqdid.statements import decode_context, decode_state, encode_context, encode_state
from pqdid.verifier_state import Decision, ReferenceVerifier, StoredChallenge

from .codec import Unavailable, encode, require
from .sqlite_store import _fault, digest


class _Facade:
    role = None

    def __init__(self, store, permit, ticket):
        require(store.key.role is self.role, "cross-role")
        self._store, self._permit = store, permit
        self.ticket = store.admit(permit, ticket)

    def _run(self, operation, kind, arguments, prepare, prior=None):
        result = self._store._transition(
            self._permit,
            self.ticket if prior is None else prior,
            operation,
            kind,
            arguments,
            prepare,
        )
        self.ticket = result.ticket
        return result

    def snapshot(self):
        self._store.admit(self._permit, self.ticket)
        return self._store.inspect(self._permit.principal)


class DurableManager(_Facade):
    role = Role.MANAGER

    def reserve(self, operation, issuer_service, issue_operation, reference, *, prior=None):
        require(type(issuer_service) is bytes and len(issuer_service) == 32)
        require(type(issue_operation) is bytes and len(issue_operation) == 32)
        key = b"allocation:" + issuer_service + issue_operation
        args = (
            issuer_service,
            issue_operation,
            reference.namespace,
            reference.epoch,
            reference.root,
        )

        def prepare(cp, entries):
            # Same remote issue identity cannot be rebound even under another local op ID.
            require(key not in entries, "reservation-exists")
            candidate = _manager(self._store.key.parameters, cp.state, self._store._deps)
            result = candidate.reserve_identifier(reference)
            require(result.status is ManagerStatus.ALLOCATED, "allocation-rejected")
            payload = (
                result.identifier,
                encode_state(self._store.key.parameters, result.state),
                result.path,
            )
            entries[key] = (args, payload)
            state = replace(cp.state, allocated_count=cp.state.allocated_count + 1)
            return replace(cp, state=state), entries, b"ALLOCATED", encode(payload)

        return self._run(operation, b"reserve", args, prepare, prior)

    def reservation(self, issuer_service, issue_operation):
        _, _, entries = self.snapshot()
        return entries.get(b"allocation:" + issuer_service + issue_operation)


class _ChallengeStore:
    def __init__(self, owner):
        self.owner = owner
        self.audience = owner._store.key.audience

    def pending(self, nonce):
        owner = self.owner
        pp = owner._store.key.parameters
        _, cp, _ = owner.snapshot()
        for row in cp.state.challenges:
            context = decode_context(pp, row.context)
            if context.nonce == nonce and not row.consumed:
                return StoredChallenge(
                    pp, context, decode_state(pp, row.state), row.require_did_state
                )
        return None

    def consume(self, expected, session, clock):
        owner, pp = self.owner, self.owner._store.key.parameters
        encoded = encode_context(pp, expected.context)
        operation = digest((b"consume", expected.context.nonce))

        def prepare(cp, entries):
            found = next((r for r in cp.state.challenges if r.context == encoded), None)
            require(found is not None and not found.consumed, "consumed")
            require(
                found.state == encode_state(pp, expected.state)
                and found.require_did_state == expected.require_did_state,
                "challenge-mismatch",
            )
            require(
                session == expected.context.session and expected.context.audience == self.audience,
                "session-mismatch",
            )
            require(is_unexpired(expected.context.expires_at, now=clock.now()), "expired")
            state = replace(
                cp.state,
                challenges=tuple(
                    replace(r, consumed=True) if r == found else r for r in cp.state.challenges
                ),
            )
            return replace(cp, state=state), entries, b"CONSUMED", b""

        try:
            result = owner._run(operation, b"consume", (encoded, session), prepare)
        except Unavailable as error:
            if str(error) == "expired":
                return Decision.EXPIRED
            if str(error) == "consumed":
                return Decision.CONSUMED
            raise
        return Decision.CONSUMED if result.replay else Decision.ACCEPTED


class DurableVerifier(_Facade):
    role = Role.VERIFIER

    def register(self, operation, challenge):
        pp = self._store.key.parameters
        require(type(challenge) is StoredChallenge and challenge.parameters == pp)
        require(challenge.context.audience == self._store.key.audience, "cross-audience")
        record = ChallengeRecord(
            encode_context(pp, challenge.context),
            encode_state(pp, challenge.state),
            challenge.require_did_state,
            False,
        )

        def prepare(cp, entries):
            require(len(cp.state.challenges) < self._store._deps.verifier_capacity, "challenge-cap")
            require(
                is_unexpired(challenge.context.expires_at, now=self._store._deps.clock.now()),
                "expired",
            )
            require(
                all(
                    decode_context(pp, r.context).nonce != challenge.context.nonce
                    for r in cp.state.challenges
                ),
                "nonce-reserved",
            )
            rows = tuple(
                sorted(
                    (*cp.state.challenges, record),
                    key=lambda r: decode_context(pp, r.context).nonce,
                )
            )
            return (
                replace(cp, state=replace(cp.state, challenges=rows)),
                entries,
                b"REGISTERED",
                b"",
            )

        return self._run(operation, b"register", (record,), prepare)

    def verify(self, *, session, context, presentation):
        # Only the existing public verifier can reach this facade's durable consume path.
        self._store.admit(self._permit, self.ticket)
        deps = self._store._deps
        verifier = ReferenceVerifier(
            parameters=self._store.key.parameters,
            audience=self._store.key.audience,
            request_public_key=deps.request_key,
            clock=deps.clock,
            store=_ChallengeStore(self),
            provider=deps.provider,
            proof_verifier=deps.proof_verifier,
            nonces=deps.nonces,
            proof_byte_limit=deps.proof_byte_limit,
        )
        return verifier.verify(session=session, context=context, presentation=presentation)


class DurableIssuer(_Facade):
    role = Role.ISSUER

    def intent(self, operation, session, recipient, approved, manager_service, reference):
        self._store._authorise(self._permit.principal, "approve-issue")
        require(type(session) is bytes and 1 <= len(session) <= 256)
        require(type(recipient) is bytes and 1 <= len(recipient) <= 256)
        require(type(manager_service) is bytes and len(manager_service) == 32)
        args = (
            session,
            recipient,
            approved,
            manager_service,
            reference.namespace,
            reference.epoch,
            reference.root,
        )

        def prepare(cp, entries):
            require(
                len(entries) < 64 and all(row[1][0] != session for row in entries.values()),
                "session-reserved",
            )
            # Immutable intent/outbox precedes manager contact; attributes never leave issuer DB.
            entries[operation] = (b"INTENT", args, None, None, None)
            return cp, entries, b"INTENT", b""

        return self._run(operation, b"intent", args, prepare)

    def attach(self, operation, issue_operation, manager):
        _, _, entries = self.snapshot()
        row = entries.get(issue_operation)
        require(row is not None and row[0] == b"INTENT", "intent-required")
        require(manager._store.key.service_id == row[1][3], "wrong-manager")
        reservation = manager.reservation(self._store.key.service_id, issue_operation)
        require(reservation is not None, "reservation-unavailable")
        args, payload = reservation
        require(
            args == (self._store.key.service_id, issue_operation, row[1][4], row[1][5], row[1][6]),
            "reservation-conflict",
        )

        def prepare(cp, current):
            require(current.get(issue_operation) == row, "intent-changed")
            require(all(value[2] != payload[0] for value in current.values()), "identifier-rebound")
            current[issue_operation] = (b"RESERVED", row[1], payload[0], payload, None)
            return cp, current, b"RESERVED", b""

        return self._run(operation, b"attach", (issue_operation, payload), prepare)

    def pending(self, operation, issue_operation, nonce):
        require(type(nonce) is bytes and len(nonce) == 32)

        def prepare(cp, entries):
            row = entries.get(issue_operation)
            require(row is not None and row[0] == b"RESERVED", "reservation-required")
            require(nonce not in cp.state.used_nonces, "nonce-reserved")
            session = IssuerSession(row[1][0], SessionPhase.PENDING, row[2], nonce, row[1][2])
            state = replace(
                cp.state,
                allocated_floor=max(cp.state.allocated_floor, row[2] + 1),
                sessions=tuple(sorted((*cp.state.sessions, session), key=lambda s: s.name)),
                used_nonces=tuple(sorted((*cp.state.used_nonces, nonce))),
            )
            entries[issue_operation] = (b"PENDING", row[1], row[2], row[3], nonce)
            return replace(cp, state=state), entries, b"PENDING", b""

        return self._run(operation, b"pending", (issue_operation, nonce), prepare)

    def claim_signing(self, operation, issue_operation):
        self._store._authorise(self._permit.principal, "sign-issue")

        def prepare(cp, entries):
            row = entries.get(issue_operation)
            require(row is not None and row[0] == b"PENDING", "not-pending")
            entries[issue_operation] = (
                b"SIGNING",
                *row[1:],
                (self.ticket.generation, self.ticket.sequence + 1),
            )
            # Existing checkpoint remains PENDING; authoritative journal overrides its usability.
            return cp, entries, b"SIGNING", b""

        result = self._run(operation, b"claim-signing", (issue_operation,), prepare)
        require(not result.replay, "signing-not-retried")
        return result.ticket

    def log_certificate(self, operation, issue_operation, issued, recipient, signing_ticket):
        self._store._authorise(self._permit.principal, "sign-issue")
        require(signing_ticket == self.ticket, "delayed-signature")

        def prepare(cp, entries):
            row = entries.get(issue_operation)
            require(row is not None and row[0] == b"SIGNING", "signing-required")
            require(
                row[5] == (signing_ticket.generation, signing_ticket.sequence), "delayed-signature"
            )
            require(row[1][1] == recipient and issued.witness.identifier == row[2], "issue-binding")
            state = replace(
                cp.state,
                sessions=tuple(
                    replace(s, phase=SessionPhase.CERTIFIED) if s.name == row[1][0] else s
                    for s in cp.state.sessions
                ),
                certifications=(*cp.state.certifications, CertificationRecord(row[1][0], issued)),
            )
            entries[issue_operation] = (b"CERTIFIED", *row[1:])
            return replace(cp, state=state), entries, b"CERTIFIED", encode(issued)

        result = self._run(operation, b"certificate", (issue_operation, issued, recipient), prepare)
        # No credential return before separate current-generation publication / recipient check.
        return replace(result, response=b"")

    def reconcile(self, operation, issue_operation, manager):
        _, _, initial = self.snapshot()
        row = initial.get(issue_operation)
        require(row is not None, "missing-intent")
        require(manager._store.key.service_id == row[1][3], "wrong-manager")
        reservation = manager.reservation(self._store.key.service_id, issue_operation)
        if reservation is not None:
            require(
                reservation[0]
                == (self._store.key.service_id, issue_operation, row[1][4], row[1][5], row[1][6]),
                "reservation-conflict",
            )
        require(
            row[2] is None or (reservation is not None and reservation[1][0] == row[2]),
            "missing-or-conflicting-manager-record",
        )

        def prepare(cp, entries):
            require(entries.get(issue_operation) == row, "intent-changed")
            phase = row[0]
            if phase in (b"PENDING", b"CERTIFIED", b"RETIRED"):
                return cp, entries, phase, b""  # No signing / credential / acceptance replay.
            require(phase in (b"INTENT", b"RESERVED", b"SIGNING"), "unknown-issue-phase")
            rid = reservation[1][0] if reservation else row[2]
            entries[issue_operation] = (
                b"RETIRED",
                row[1],
                rid,
                reservation[1] if reservation else row[3],
                row[4],
            )
            sessions = list(cp.state.sessions)
            existing = next((s for s in sessions if s.name == row[1][0]), None)
            if existing is None:
                sessions.append(IssuerSession(row[1][0], SessionPhase.ABORTED, rid, None, None))
            else:
                sessions[sessions.index(existing)] = replace(existing, phase=SessionPhase.ABORTED)
            state = replace(
                cp.state,
                allocated_floor=max(cp.state.allocated_floor, 0 if rid is None else rid + 1),
                sessions=tuple(sorted(sessions, key=lambda s: s.name)),
            )
            return replace(cp, state=state), entries, b"RETIRED", b""

        return self._run(operation, b"reconcile", (issue_operation,), prepare)

    def retrieve_committed(self, operation, recipient, transport):
        _fault("release-before-publication")
        return self._store.publish(self._permit, self.ticket, operation, recipient, transport)
