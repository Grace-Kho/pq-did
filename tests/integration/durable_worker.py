"""Isolated TEST-ONLY owner/operator and public proof-token adapters; no production auth."""

import json
import os
import resource
import select
import socket
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from pqdid.parameters import decode_parameters
from pqdid.persistence import sqlite_store
from pqdid.persistence.codec import Unavailable, decode
from pqdid.persistence.lifecycle import DurableIssuer, DurableManager, DurableVerifier
from pqdid.persistence.records import ServiceKey, WriterPermit
from pqdid.persistence.sqlite_store import SQLiteStore
from pqdid.recovery import DEFAULT_DEPENDENCIES, Dependencies
from pqdid.recovery_records import Role
from pqdid.statements import decode_context, decode_state, encode_auth_statement
from pqdid.verifier_state import CurrentStateReply, Presentation, ProofVerdict, StoredChallenge

OP = b"o" * 32
ISSUE = b"i" * 32


class Operator:
    """TEST ONLY: fixture identities; never installed as default policy."""

    def allow(self, key, principal, action):
        if action in {"initialise", "replace"}:
            return principal == b"test-admin"
        if action == "retrieve":
            return principal in {b"recipient", b"wrong-recipient"}
        return principal in {b"worker", b"replacement"}


class Clock:
    value = 99

    def now(self):
        return self.value


class Nonces:
    def nonce(self):
        return (1).to_bytes(32)


class Proof:
    """Exact previously evaluated public statement/token, NOT cryptographic verification."""

    def __init__(self, pp, fixture):
        self.pp, self.fixture = pp, fixture

    def verify(self, statement, proof):
        sqlite_store._fault("proof-ready")
        return (
            ProofVerdict.VALID
            if (encode_auth_statement(self.pp, statement), proof)
            == (self.fixture[0], self.fixture[3])
            else ProofVerdict.INVALID
        )


class Provider:
    def __init__(self, pp, fixture):
        self.pp, self.fixture = pp, fixture

    def instance(self, expected):
        return self.pp if expected == self.pp else None

    def current(self, expected, nonce):
        return CurrentStateReply(nonce, decode_state(self.pp, self.fixture[4]), self.fixture[5])


class ManagerRead:
    def __init__(self, root):
        self.root = root
        self.parameters = decode_parameters(
            decode((root / "manager.fixture").read_bytes()).parameters
        )

    def snapshot(self):
        _, cp, _ = store(self.root, "manager").inspect(b"worker")
        return SimpleNamespace(allocated_count=cp.state.allocated_count)


def store(root, role):
    cp = decode((root / (role + ".fixture")).read_bytes())
    pp = decode_parameters(cp.parameters)
    deps = DEFAULT_DEPENDENCIES
    audience = b""
    if role == "issuer":
        deps = Dependencies(manager=ManagerRead(root), resolver=object(), authorisation=object())
    if role.startswith("verifier"):
        audience = cp.state.audience
        fixture = decode((root / (role + ".public")).read_bytes())
        deps = Dependencies(
            clock=Clock(),
            provider=Provider(pp, fixture),
            proof_verifier=Proof(pp, fixture),
            nonces=Nonces(),
            audience=audience,
            request_key=cp.state.request_key,
        )
    key = ServiceKey(cp.role, cp.service_id, role.encode()[:1] * 32, pp, audience)
    return SQLiteStore(
        root / role / "authority.sqlite3", key, dependencies=deps, authorisation=Operator()
    )


def facade(root, role, *, permit=None, ticket=None):
    owner = store(root, role)
    current, _, _ = owner.inspect(b"worker")
    permit = permit or WriterPermit(b"worker", current.generation)
    kind = {
        Role.MANAGER: DurableManager,
        Role.ISSUER: DurableIssuer,
        Role.VERIFIER: DurableVerifier,
    }
    return kind[owner.key.role](owner, permit, ticket or current)


def initialise(root, role):
    owner = store(root, role)
    (root / role).mkdir(mode=0o700)
    cp = decode((root / (role + ".fixture")).read_bytes())
    ticket = owner.initialise(b"test-admin", cp)
    permit, ticket = owner.acquire(b"test-admin", b"g" * 32, ticket, b"worker")
    return permit, ticket


def summary(root, role):
    ticket, cp, entries = store(root, role).inspect(b"worker")
    return {
        "sequence": ticket.sequence,
        "head": ticket.digest.hex(),
        "checkpoint": ticket.checkpoint.hex(),
        "generation": ticket.generation,
        "allocated": getattr(cp.state, "allocated_count", None),
        "phases": [r[0].decode() for r in entries.values()] if role == "issuer" else [],
        "certifications": len(getattr(cp.state, "certifications", ())),
        "consumed": sum(r.consumed for r in getattr(cp.state, "challenges", ())),
        "entries": len(entries),
    }


def reference(root):
    cp = decode((root / "manager.fixture").read_bytes())
    return decode_state(decode_parameters(cp.parameters), cp.state.state).reference


def issue_stage(root, stage):
    issuer = facade(root, "issuer")
    manager = facade(root, "manager")
    approved, issued = decode((root / "issued.fixture").read_bytes())
    if stage == "intent":
        return issuer.intent(
            ISSUE,
            b"pilot-session",
            b"recipient",
            approved,
            manager._store.key.service_id,
            reference(root),
        )
    if stage == "reserve":
        return manager.reserve(OP, issuer._store.key.service_id, ISSUE, reference(root))
    if stage == "attach":
        return issuer.attach(b"a" * 32, ISSUE, manager)
    if stage == "pending":
        return issuer.pending(b"p" * 32, ISSUE, b"n" * 32)
    if stage == "sign":
        return issuer.claim_signing(b"s" * 32, ISSUE)
    if stage == "log":
        sqlite_store._fault("signature-ready")
        return issuer.log_certificate(b"c" * 32, ISSUE, issued, b"recipient", issuer.ticket)
    if stage == "reconcile":
        return issuer.reconcile(b"r" * 32, ISSUE, manager)
    if stage == "release":
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            left.setblocking(False)
            decision = issuer.retrieve_committed(b"c" * 32, b"recipient", left)
            assert decode(right.recv(65536)) == issued
            return SimpleNamespace(decision=decision)
        finally:
            left.close()
            right.close()
    raise AssertionError("unknown stage")


def verify(root, role):
    owner = facade(root, role)
    cp = decode((root / (role + ".fixture")).read_bytes())
    fixture = decode((root / (role + ".public")).read_bytes())
    context = decode_context(owner._store.key.parameters, cp.state.challenges[0].context)
    return owner.verify(
        session=context.session,
        context=context,
        presentation=Presentation(fixture[1], fixture[2], fixture[3]),
    )


def main():
    root, action, role, point = Path(sys.argv[1]), *sys.argv[2:5]

    def barrier(label):
        if label == point:
            print(
                json.dumps(
                    {
                        "barrier": label,
                        "pid": os.getpid(),
                        "self_maxrss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                        * 1024,
                    }
                ),
                flush=True,
            )
            assert select.select([sys.stdin], [], [], 10)[0], "bounded barrier deadline"
            assert sys.stdin.readline().strip() == "go"

    sqlite_store._fault = barrier
    # lifecycle imports the inert function separately; replace only this test process.
    import pqdid.persistence.lifecycle as lifecycle

    lifecycle._fault = barrier
    result = {}
    try:
        if action == "inspect":
            result = summary(root, role)
        elif action == "reserve":
            owner = facade(root, "manager")
            barrier("prepared")
            value = owner.reserve(OP, b"S" * 32, ISSUE, reference(root))
            result = {"decision": value.decision.decode(), "rid": decode(value.response)[0]}
        elif action == "replace":
            owner = store(root, role)
            ticket, _, _ = owner.inspect(b"worker")
            barrier("prepared")
            permit, head = owner.acquire(b"test-admin", b"x" * 32, ticket, b"replacement")
            result = {"generation": permit.generation, "head": head.digest.hex()}
        elif action == "verify":
            result = {"decision": verify(root, role).value}
        elif action == "register":
            owner = facade(root, role)
            cp = decode((root / (role + ".fixture")).read_bytes())
            pp = owner._store.key.parameters
            row = cp.state.challenges[0]
            context = replace(decode_context(pp, row.context), nonce=b"Z" * 32)
            value = owner.register(
                b"v" * 32, StoredChallenge(pp, context, decode_state(pp, row.state), False)
            )
            result = {"decision": value.decision.decode()}
        elif action.startswith("issue-"):
            value = issue_stage(root, action[6:])
            result = {"decision": getattr(value, "decision", b"SIGNING").decode()}
        else:
            raise AssertionError("unknown action")
    except Unavailable as error:
        result = {"unavailable": str(error)}
    print(
        json.dumps(
            {
                "result": result,
                "pid": os.getpid(),
                "self_maxrss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
