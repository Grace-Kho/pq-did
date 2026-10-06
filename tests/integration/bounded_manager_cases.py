"""Synthetic TEST-ONLY keys, policy and isolated stores; never deployment inputs."""

import socket
from contextlib import contextmanager
from dataclasses import replace

from pqdid import bounded_mldsa_sign as core
from pqdid.bounded_manager import BoundedDurableManager
from pqdid.merkle import default_subtree_roots
from pqdid.parameters import encode_parameters
from pqdid.persistence.codec import encode
from pqdid.persistence.records import ServiceKey
from pqdid.persistence.sqlite_store import SQLiteStore
from pqdid.recovery import Dependencies
from pqdid.recovery_records import Checkpoint, ManagerRecord, Role
from pqdid.revocation_state import RevocationRequest, SigningStatus
from pqdid.signing_adapters import IssuerSigningAdapter, ManagerSigningAdapter, TrustedSigningKey
from pqdid.statements import RevocationState, decode_state, encode_state
from tests.unit.relation_cases import parameters

OP = b"r" * 32
CURRENT = b"c" * 32


class Grant:
    """Test-only trusted bootstrap/request issuer; never attached to durable manager."""

    def __init__(self, key):
        self.key = key

    def allow(self, key, operation, typed_inputs):
        return key == self.key


class Policy:
    """Existing owner policy interface, explicit fixed synthetic principals."""

    write_enabled = True

    def allow(self, key, principal, action):
        if action in {"initialise", "replace"}:
            return principal == b"admin"
        if action == "write":
            return self.write_enabled and principal in {b"writer", b"replacement"}
        if action == "read":
            return principal in {b"writer", b"replacement"}
        # Manager public delivery must not repurpose the private recipient permission.
        return False


class Material:
    def __init__(self):
        # Public synthetic seeds. Never write expanded private keys to evidence/store.
        issuer, manager = (core.reference_keygen_mldsa65(bytes([n]) * 32) for n in (21, 22))
        self.pp = replace(
            parameters(),
            issuer_public_key=issuer.public_key,
            revocation_public_key=manager.public_key,
        )
        self.manager_key = TrustedSigningKey(
            self.pp,
            b"M" * 32,
            Role.MANAGER,
            b"synthetic-manager",
            manager.public_key,
            manager.secret_key,
        )
        self.issuer_key = TrustedSigningKey(
            self.pp,
            b"I" * 32,
            Role.ISSUER,
            b"synthetic-issuer",
            issuer.public_key,
            issuer.secret_key,
        )

    def initial(self):
        state = RevocationState(
            self.pp.namespace, 0, default_subtree_roots(self.pp.domain)[20], bytes(3309)
        )
        signed = ManagerSigningAdapter(
            self.manager_key, authorisation=Grant(self.manager_key)
        ).state(self.pp, state)
        assert signed.status is SigningStatus.SIGNED
        encoded = encode_state(self.pp, replace(state, signature=signed.signature))
        return Checkpoint(
            1,
            Role.MANAGER,
            b"M" * 32,
            encode_parameters(self.pp),
            ManagerRecord(2, encoded, (), (), encoded, (), (), ()),
        )

    def request(self, state, *, identifier=0, nonce=b"N" * 32):
        request = RevocationRequest(identifier, state.reference, nonce, bytes(3309))
        signed = IssuerSigningAdapter(
            self.issuer_key, authorisation=Grant(self.issuer_key)
        ).revocation_request(self.pp, request)
        assert signed.status is SigningStatus.SIGNED
        return replace(request, signature=signed.signature)


def store(root, material, policy):
    key = ServiceKey(Role.MANAGER, b"M" * 32, b"A" * 32, material.pp)
    return SQLiteStore(
        root / "db" / "manager.sqlite3", key, dependencies=Dependencies(), authorisation=policy
    )


class Rig:
    def __init__(self, root, material):
        self.root, self.material, self.pp, self.policy = root, material, material.pp, Policy()
        (root / "db").mkdir(mode=0o700)
        cp = material.initial()
        self.store = store(root, material, self.policy)
        ticket = self.store.initialise(b"admin", cp)
        self.permit, self.initial_ticket = self.store.acquire(
            b"admin", b"g" * 32, ticket, b"writer"
        )
        self.owner = self.fresh(self.initial_ticket)
        self.state = decode_state(self.pp, cp.state.state)
        self.request = material.request(self.state)
        (root / "bootstrap.pql").write_bytes(encode(cp))
        (root / "ticket.pql").write_bytes(encode(self.initial_ticket.record()))
        q = self.request
        (root / "request.pql").write_bytes(encode((q.identifier, q.nonce, q.signature)))
        self.notes = {}

    def fresh(self, ticket, permit=None):
        return BoundedDurableManager(
            self.store, permit or self.permit, ticket, signing_key=self.material.manager_key
        )

    def summary(self):
        ticket, cp, entries = self.store.inspect(b"writer")
        state = decode_state(self.pp, cp.state.state)
        return {
            "sequence": ticket.sequence,
            "head": ticket.digest.hex(),
            "generation": ticket.generation,
            "allocated": cp.state.allocated_count,
            "epoch": state.epoch,
            "history": len(cp.state.history),
            "revoked": list(cp.state.revoked),
            "consumed_nonces": len(cp.state.consumed_nonces),
            "entries": len(entries),
        }

    def replace_writer(self):
        ticket, _, _ = self.store.inspect(b"writer")
        return self.store.acquire(b"admin", b"x" * 32, ticket, b"replacement")


@contextmanager
def channel():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        left.setblocking(False)
        right.setblocking(False)
        yield left, right
    finally:
        left.close()
        right.close()
