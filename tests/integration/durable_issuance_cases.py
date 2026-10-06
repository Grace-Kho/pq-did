"""TEST ONLY integration fixtures; explicit synthetic proof acceptance, never production."""

from dataclasses import replace

from pqdid import bounded_mldsa_sign as core
from pqdid.bounded_manager import BoundedDurableManager
from pqdid.did_state import (
    DIDStatus,
    IssuanceDIDAdapter,
    ReferenceDIDRegistry,
    ReferenceDIDResolver,
    encode_did_record,
)
from pqdid.durable_issuance import DurableIssuance, ManagerIssuancePort
from pqdid.issuance import HolderAcceptance, IssueRequest
from pqdid.parameters import encode_parameters
from pqdid.persistence.codec import decode, encode
from pqdid.persistence.records import HeadTicket, ServiceKey, WriterPermit
from pqdid.persistence.sqlite_store import SQLiteStore
from pqdid.recovery import Dependencies
from pqdid.recovery_records import Checkpoint, IssuerRecord, ManagerRecord, Role
from pqdid.revocation_state import RevocationRequest, SigningStatus
from pqdid.statements import decode_state, encode_state
from tests.unit.test_signing_adapters import Harness, Nonces, StorePolicy

ISSUE = b"i" * 32


def keys():
    return tuple(core.reference_keygen_mldsa65(bytes([n]) * 32) for n in range(1, 7))


class Rig:
    def __init__(self, root, material, *, proof=True, existing=False):
        self.root, self.h, self.notes = root, Harness(material), {}
        h = self.h
        if existing:
            fields, record, encoded_state = decode((root / "context.pql").read_bytes())
            registry = ReferenceDIDRegistry(h.config, signer=h.registry.signer)
            assert registry.append(record, None) is DIDStatus.COMMITTED
            h.registry = registry
            h.resolver = ReferenceDIDResolver(h.config, registry, nonces=Nonces())
            h.request = IssueRequest(*fields)
            h.attributes = h.request.attributes
            self.state = decode_state(h.pp, encoded_state)
        else:
            self.state = h.manager.snapshot().state
            q = h.request
            fields = (q.session, q.did, q.version, q.attributes, q.evidence, q.holder_approval)
            (root / "context.pql").write_bytes(
                encode(
                    (
                        fields,
                        encode_did_record(h.current_record(h.did)),
                        encode_state(h.pp, self.state),
                    )
                )
            )
        self.pp = h.pp
        self.manager_store = self.make_store(
            "manager", Role.MANAGER, h.selected[1].service_id, Dependencies()
        )
        if existing:
            mt, it = decode((root / "tickets.pql").read_bytes())
            self.mp, mt = WriterPermit(b"writer", mt[3]), HeadTicket(*mt)
            self.ip, it = WriterPermit(b"writer", it[3]), HeadTicket(*it)
        else:
            encoded = encode_state(h.pp, self.state)
            cp = Checkpoint(
                1,
                Role.MANAGER,
                h.selected[1].service_id,
                encode_parameters(h.pp),
                ManagerRecord(1, encoded, (), (), encoded, (), (), ()),
            )
            mt = self.manager_store.initialise(b"admin", cp)
            self.mp, mt = self.manager_store.acquire(b"admin", b"g" * 32, mt, b"writer")
        self.manager = BoundedDurableManager(
            self.manager_store, self.mp, mt, signing_key=h.selected[1]
        )
        self.port = ManagerIssuancePort(self.manager)
        self.deps = Dependencies(
            manager=self.port,
            resolver=IssuanceDIDAdapter(h.resolver),
            authorisation=h.approval,
            proof_verifier=h.proof if proof else None,
            nonces=Nonces(),
        )
        self.issuer_store = self.make_store(
            "issuer", Role.ISSUER, h.selected[0].service_id, self.deps
        )
        if not existing:
            cp = Checkpoint(
                1,
                Role.ISSUER,
                h.selected[0].service_id,
                encode_parameters(h.pp),
                IssuerRecord(0, (), (), ()),
            )
            it = self.issuer_store.initialise(b"admin", cp)
            self.ip, it = self.issuer_store.acquire(b"admin", b"g" * 32, it, b"writer")
        self.flow = DurableIssuance(
            self.issuer_store, self.ip, it, manager=self.manager, signing_key=h.selected[0]
        )

    def make_store(self, name, role, service_id, deps):
        directory = self.root / name
        directory.mkdir(mode=0o700, exist_ok=True)
        return SQLiteStore(
            directory / "authority.sqlite3",
            ServiceKey(role, service_id, name[:1].encode() * 32, self.pp),
            dependencies=deps,
            authorisation=StorePolicy(),
        )

    def pending(self):
        challenge = self.flow.begin(ISSUE, self.h.request, self.state, b"recipient")
        submission = self.h.prepare(challenge)
        self.holder = HolderAcceptance(
            self.pp, self.h.secret, self.h.attributes, submission.statement
        )
        return submission

    def summary(self):
        mt, mc, me = self.manager_store.inspect(b"writer")
        it, ic, ie = self.issuer_store.inspect(b"writer")
        return {
            "manager_head": mt.digest.hex(),
            "issuer_head": it.digest.hex(),
            "allocated": mc.state.allocated_count,
            "epoch": decode_state(self.pp, mc.state.state).epoch,
            "reservations": len(me),
            "phase": None if ISSUE not in ie else ie[ISSUE][0].decode(),
            "issuer_floor": ic.state.allocated_floor,
            "certifications": len(ic.state.certifications),
            "nonces": len(ic.state.used_nonces),
            "issuer_generation": it.generation,
        }

    def heads(self):
        return self.manager_store.inspect(b"writer")[0], self.issuer_store.inspect(b"writer")[0]

    def reopen(self, mt, it):
        self.manager = BoundedDurableManager(
            self.manager_store, self.mp, mt, signing_key=self.h.selected[1]
        )
        self.port = ManagerIssuancePort(self.manager)
        self.deps = replace(self.deps, manager=self.port)
        self.issuer_store = self.make_store(
            "issuer", Role.ISSUER, self.h.selected[0].service_id, self.deps
        )
        self.flow = DurableIssuance(
            self.issuer_store, self.ip, it, manager=self.manager, signing_key=self.h.selected[0]
        )

    def prepare_worker(self):
        (self.root / "tickets.pql").write_bytes(encode(tuple(t.record() for t in self.heads())))

    def revoke(self, identifier):
        state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        request = RevocationRequest(identifier, state.reference, b"R" * 32, bytes(3309))
        signed = self.h.issuer_adapter.revocation_request(self.pp, request)
        assert signed.status is SigningStatus.SIGNED
        return self.manager.revoke(b"r" * 32, replace(request, signature=signed.signature))
