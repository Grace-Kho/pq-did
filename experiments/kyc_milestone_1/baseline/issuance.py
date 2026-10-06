"""Baseline issuance journal: allocation, signing claim, commit, bound retrieval."""

import hashlib
import secrets
from dataclasses import dataclass

from pqdid.statements import decode_state, encode_state
from pqdid.witness_updates import WitnessCheckpoint

from .records import (
    credential_body,
    decode_credential,
    enrol_body,
    frame,
    octets,
    require,
)
from .signing import Signer, verify


@dataclass(frozen=True)
class Enrolment:
    operation: bytes
    session: bytes
    nonce: bytes
    holder_key: bytes
    attributes: bytes
    identifier: int


@dataclass(frozen=True)
class Delivery:
    credential: object
    checkpoint: WitnessCheckpoint


class BaselineIssuer:
    def __init__(
        self,
        pp,
        journal,
        manager,
        issuer_key,
        *,
        service_id,
        approved_attributes,
        permitted_recipient,
    ):
        self.pp, self.journal, self.manager = pp, journal, manager
        self.service_id = octets(service_id, 32)
        self.approved_attributes = approved_attributes
        self.recipient = permitted_recipient
        self.signer = Signer(pp, "issuer", issuer_key, pp.issuer_public_key, self._admitted)

    def _admitted(self):
        self.journal.snapshot()
        return True

    def begin(self, approved_attributes, intended_holder_key, recipient):
        require(recipient == self.recipient, "recipient-not-authorised")
        require(approved_attributes == self.approved_attributes, "unapproved-attributes")
        octets(intended_holder_key, 1952)
        session, nonce = secrets.token_bytes(32), secrets.token_bytes(32)
        operation = hashlib.sha256(b"baseline-issue" + session).digest()
        row = (
            b"INTENT",
            session,
            nonce,
            intended_holder_key,
            approved_attributes,
            recipient,
            None,
            None,
            None,
        )

        def intent(rows):
            require(operation not in rows, "issuer-operation-reused")
            rows[operation] = row

        self.journal.transition("intent", intent)
        state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        self.manager.reserve(
            hashlib.sha256(b"reserve" + operation).digest(),
            self.service_id,
            operation,
            state.reference,
        )
        allocation = self.manager.reservation(self.service_id, operation)
        require(allocation is not None, "missing-allocation")
        rid, encoded_state, path = allocation[1]

        def attach(rows):
            require(rows.get(operation) == row, "changed-intent")
            rows[operation] = (b"RESERVED", *row[1:6], rid, path, encoded_state)

        self.journal.transition("reservation", attach)
        return Enrolment(operation, session, nonce, intended_holder_key, approved_attributes, rid)

    def complete(self, session, enrolment_signature):
        rows = self.journal.snapshot()
        selected = [(op, row) for op, row in rows.items() if row[1] == session]
        require(len(selected) == 1, "unknown-session")
        operation, row = selected[0]
        require(row[0] == b"RESERVED", "not-reserved-use-redelivery")
        body = enrol_body(self.pp, row[1], row[2], row[3], row[4], row[6])
        require(
            verify("enrol", row[3], body, octets(enrolment_signature, 3309)), "enrolment-possession"
        )

        def claim(current):
            require(current.get(operation) == row, "changed-reservation")
            current[operation] = (b"SIGNING", *row[1:])

        self.journal.transition("claim", claim)
        claimed = self.journal.snapshot()[operation]
        unsigned = credential_body(self.pp, row[3], row[4], row[6])
        signature = self.signer.sign_credential(row[3], row[4], row[6])
        credential = frame("credential", (unsigned, signature))
        decode_credential(self.pp, credential)
        # The original reservation's state must still be current at certification.
        current_state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        require(
            current_state.reference == decode_state(self.pp, row[8]).reference,
            "issuance-state-superseded",
        )

        def certify(current):
            require(current.get(operation) == claimed, "changed-signing-claim")
            current[operation] = (b"CERTIFIED", *row[1:], credential)

        self.journal.transition("certification", certify)
        return operation  # No uncommitted or recipient-free credential result.

    def retrieve(self, operation, trusted_recipient):
        row = self.journal.snapshot().get(operation)
        require(row is not None and row[0] == b"CERTIFIED", "not-certified")
        require(trusted_recipient == self.recipient == row[5], "recipient-mismatch")
        credential = decode_credential(self.pp, row[9])
        state = decode_state(self.pp, row[8])
        require(encode_state(self.pp, state) == row[8], "stored-state")
        return Delivery(credential, WitnessCheckpoint(row[6], row[7], state))
