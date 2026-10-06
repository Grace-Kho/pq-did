"""Runnable public/synthetic baseline scenarios, independent of any proof backend."""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from pqdid.bounded_manager import BoundedDurableManager
from pqdid.durable_verification import ManagerVerificationProvider
from pqdid.merkle import default_subtree_roots
from pqdid.parameters import decode_parameters, encode_parameters
from pqdid.persistence.codec import encode as local_encode
from pqdid.persistence.records import ServiceKey
from pqdid.persistence.sqlite_store import SQLiteStore
from pqdid.policy import Range, encode_policy, make_policy
from pqdid.recovery import Dependencies
from pqdid.recovery_records import Checkpoint, ManagerRecord, Role, VerifierRecord
from pqdid.revocation_state import (
    RevocationRequest,
    SigningStatus,
    build_revocation_request_message,
)
from pqdid.schema import decode_attributes, encode_attributes
from pqdid.signing_adapters import IssuerSigningAdapter, ManagerSigningAdapter, TrustedSigningKey
from pqdid.statements import RevocationState, decode_auth_statement, decode_state, encode_state
from pqdid.verifier_state import SystemNonces
from pqdid.witness_updates import UpdateStatus
from pqdid.witnesses import decode_auth_witness

from .holder import Holder
from .issuance import BaselineIssuer
from .records import (
    PROFILE,
    encode_credential,
    encode_presentation,
    encode_request,
    enrol_body,
    require,
)
from .signing import Key
from .storage import IssuerJournal, directory
from .verifier import BaselineVerifier

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests/fixtures/relations_vectors.json"


class SyntheticClock:
    """Recorded synthetic epoch plus real monotonic elapsed; test offset is explicit."""

    def __init__(self, epoch_base):
        require(type(epoch_base) is int and epoch_base >= 0, "clock-base")
        self.epoch_base, self.start_ns, self.offset = epoch_base, time.monotonic_ns(), 0

    def now(self):
        return (
            self.epoch_base + (time.monotonic_ns() - self.start_ns) // 1_000_000_000 + self.offset
        )


@dataclass(frozen=True, repr=False)
class Material:
    pp: object
    keys: tuple = field(repr=False)
    attributes: bytes
    policy: object
    validity_index: int
    fixture_sha256: str
    source_fixture_sha256: str
    epoch_base: int


class _StorePolicy:
    """Trusted local owner configuration, not authentication of a remote caller."""

    def allow(self, key, principal, action):
        if action in {"initialise", "replace"}:
            return principal == b"admin"
        return principal == b"writer"


class _OwnerGate:
    def __init__(self, key):
        self.key = key

    def allow(self, key, operation, typed_inputs):
        return key == self.key


class _MeasuredProvider(ManagerVerificationProvider):
    """Observe actual local reply bytes without changing their verification path."""

    def __init__(self, owner, consumer):
        super().__init__(owner.manager, consumer=consumer)
        self.owner = owner

    def current(self, expected, nonce):
        reply = super().current(expected, nonce)
        self.owner._current_counter += 1
        suffix = str(self.owner._current_counter)
        self.owner._size("current_nonce_" + suffix, nonce)
        self.owner._size(
            "current_reply_" + suffix,
            local_encode((reply.nonce, encode_state(expected, reply.state), reply.signature)),
        )
        return reply


class Scenario:
    @staticmethod
    def capabilities():
        return {
            "profile": PROFILE.decode(),
            "issue": True,
            "present": True,
            "verify": True,
            "revoke_update": True,
            "prove_auth": False,
            "verify_auth_proof": False,
            "privacy": "fully disclosed; persistent holder key and rid are linkable",
        }

    @staticmethod
    def material(epoch_base=1_800_000_000):
        raw = FIXTURE.read_bytes()
        fixture = json.loads(raw)
        instance = next(item for item in fixture["instances"] if item["name"] == "alpha")
        pp = decode_parameters(bytes.fromhex(instance["parameters"]))
        example = next(
            item for item in fixture["authentication"] if item["name"] == "alpha-42-old-002c"
        )
        statement = decode_auth_statement(pp, bytes.fromhex(example["statement"]))
        witness = decode_auth_witness(pp.schema, bytes.fromhex(example["witness"]))
        keys = tuple(Key.generate() for _ in range(6))
        pp = replace(pp, issuer_public_key=keys[0].public, revocation_public_key=keys[1].public)
        values = list(decode_attributes(pp.schema, witness.attributes))
        validity = next(
            i for i, value in enumerate(pp.schema.fields, 1) if value.name == "validUntil"
        )
        values[validity - 1] = epoch_base + 86400
        attributes = encode_attributes(pp.schema, tuple(values))
        regenerated = local_encode(
            (
                b"baseline-fixture-v1",
                encode_parameters(pp),
                attributes,
                encode_policy(pp.schema, statement.context.policy),
                epoch_base,
                120,
                b"validUntil>=session-expiry/v1",
            )
        )
        return Material(
            pp,
            keys,
            attributes,
            statement.context.policy,
            validity,
            hashlib.sha256(regenerated).hexdigest(),
            hashlib.sha256(raw).hexdigest(),
            epoch_base,
        )

    @classmethod
    def create(cls, root, *, epoch_base=1_800_000_000, material=None, clock=None):
        value = cls()
        value.root = directory(Path(root).absolute(), create=True)
        value.data = cls.material(epoch_base) if material is None else material
        require(value.data.epoch_base == epoch_base, "material-clock-base")
        value.pp, value.clock = (
            value.data.pp,
            SyntheticClock(epoch_base) if clock is None else clock,
        )
        value.keys = value.data.keys
        value.stages_ns, value.message_bytes = {}, {}
        value._other_holders, value._counter, value._current_counter = [], 0, 0
        value.trusted = {}
        for index, role, name in (
            (0, Role.ISSUER, b"I"),
            (1, Role.MANAGER, b"M"),
            (2, Role.VERIFIER, b"A"),
            (3, Role.VERIFIER, b"B"),
        ):
            key = value.keys[index]
            value.trusted[name] = TrustedSigningKey(
                value.pp, name * 32, role, name, key.public, key.secret
            )
        roots = default_subtree_roots(value.pp.domain)
        state = RevocationState(value.pp.namespace, 0, roots[-1], bytes(3309))
        mk = value.trusted[b"M"]
        signed = ManagerSigningAdapter(mk, authorisation=_OwnerGate(mk)).state(value.pp, state)
        require(signed.status is SigningStatus.SIGNED, "initial-state-signing")
        state = replace(state, signature=signed.signature)
        encoded = encode_state(value.pp, state)
        value.manager_store = value._store("manager", mk, Dependencies())
        cp = value._checkpoint(mk, ManagerRecord(0, encoded, (), (), encoded, (), (), ()))
        ticket = value.manager_store.initialise(b"admin", cp)
        value.manager_permit, ticket = value.manager_store.acquire(
            b"admin", secrets.token_bytes(32), ticket, b"writer"
        )
        value.manager = BoundedDurableManager(
            value.manager_store, value.manager_permit, ticket, signing_key=mk
        )
        value.verifiers, value.verifier_stores, value.verifier_permits = {}, {}, {}
        for name, index in (("A", 2), ("B", 3)):
            key = value.trusted[name.encode()]
            audience = b"baseline-audience-" + name.encode()
            deps = Dependencies(
                provider=_MeasuredProvider(value, key.service_id),
                clock=value.clock,
                nonces=SystemNonces(),
                audience=audience,
                request_key=key.public_key,
            )
            store = value._store("verifier-" + name, key, deps, audience)
            cp = value._checkpoint(key, VerifierRecord(audience, key.public_key, ()))
            ticket = store.initialise(b"admin", cp)
            permit, ticket = store.acquire(b"admin", secrets.token_bytes(32), ticket, b"writer")
            value.verifier_stores[name], value.verifier_permits[name] = store, permit
            value.verifiers[name] = BaselineVerifier(store, permit, ticket, value.keys[index])
        issuer_dir = directory(value.root / "issuer", create=True)
        identity = hashlib.sha256(b"baseline-issuer" + encode_parameters(value.pp)).digest()
        journal = IssuerJournal.create(issuer_dir / "issuer.sqlite3", identity)
        value.issuer = value._issuer(journal)
        request_keys = {v.audience: v.store._deps.request_key for v in value.verifiers.values()}
        value.holder = Holder.create(
            value.pp,
            value.root / "holder",
            value.clock,
            request_keys,
            value.data.policy,
            key=value.keys[4],
        )
        return value

    def _issuer(self, journal):
        return BaselineIssuer(
            self.pp,
            journal,
            self.manager,
            self.keys[0],
            service_id=self.trusted[b"I"].service_id,
            approved_attributes=self.data.attributes,
            permitted_recipient=b"holder",
        )

    def _checkpoint(self, key, state):
        return Checkpoint(1, key.authority_role, key.service_id, encode_parameters(self.pp), state)

    def _store(self, name, key, deps, audience=b""):
        path = directory(self.root / name, create=True)
        return SQLiteStore(
            path / "authority.sqlite3",
            ServiceKey(key.authority_role, key.service_id, key.service_id, self.pp, audience),
            dependencies=deps,
            authorisation=_StorePolicy(),
        )

    def _time(self, name, operation):
        start = time.monotonic_ns()
        try:
            return operation()
        finally:
            self.stages_ns[name] = time.monotonic_ns() - start

    def _size(self, name, data):
        self.message_bytes[name] = {"canonical": len(data), "transport": len(data)}

    def issue(self, holder=None):
        holder = self.holder if holder is None else holder
        challenge = self._time(
            "issuance_begin",
            lambda: self.issuer.begin(self.data.attributes, holder.public_key, b"holder"),
        )
        signature = self._time("enrolment_sign", lambda: holder.enrol(challenge))
        operation = self._time(
            "certification", lambda: self.issuer.complete(challenge.session, signature)
        )
        delivery = self._time(
            "recipient_retrieval", lambda: self.issuer.retrieve(operation, b"holder")
        )
        self._time(
            "holder_acceptance", lambda: holder.accept_credential(delivery, self.data.attributes)
        )
        self.last_enrolment, self.last_operation = challenge, operation
        self._size("credential", encode_credential(self.pp, delivery.credential))
        self._size(
            "enrolment_body",
            enrol_body(
                self.pp,
                challenge.session,
                challenge.nonce,
                challenge.holder_key,
                challenge.attributes,
                challenge.identifier,
            ),
        )
        self._size("initial_witness_path", delivery.checkpoint.path)
        self._size("initial_state", encode_state(self.pp, delivery.checkpoint.state))
        self.message_bytes["enrolment_signature"] = {
            "canonical": len(signature),
            "transport": len(signature),
        }
        return delivery

    def add_holder(self):
        name = "holder-other-" + str(len(self._other_holders))
        request_keys = {v.audience: v.store._deps.request_key for v in self.verifiers.values()}
        holder = Holder.create(
            self.pp, self.root / name, self.clock, request_keys, self.data.policy, key=self.keys[5]
        )
        self._other_holders.append(holder)
        self.issue(holder)
        return holder

    def policy(self, expires_at):
        # Original fixture policies predate the baseline's explicit validity rule.
        # Add the approved time-relative clause here; never mutate that fixture.
        clauses = tuple(c for c in self.data.policy.clauses if c.index != self.data.validity_index)
        clauses += (Range(self.data.validity_index, expires_at, (1 << 64) - 1),)
        disclosed = tuple(sorted(set(self.data.policy.disclosed) | {self.data.validity_index}))
        return make_policy(self.pp.schema, disclosed, clauses)

    def request(self, audience="A"):
        self._counter += 1
        expires = self.clock.now() + 120
        policy = self.policy(expires)
        self.holder.approved_policy = policy
        for holder in self._other_holders:
            holder.approved_policy = policy
        request = self.verifiers[audience].request(
            policy, b"session-" + self._counter.to_bytes(8, "big"), expires
        )
        self._size("request", encode_request(self.pp, request))
        return request

    def present(self, request):
        presentation = self.holder.present(request)
        self._size("presentation", encode_presentation(self.pp, presentation))
        return presentation

    def verify(self, request, presentation):
        owner = next(
            (v for v in self.verifiers.values() if v.audience == request.context.audience), None
        )
        require(owner is not None, "unknown-verifier-audience")
        return owner.verify(request, presentation)

    def revoke(self, identifier):
        state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        request = RevocationRequest(
            identifier, state.reference, secrets.token_bytes(32), bytes(3309)
        )
        key = self.trusted[b"I"]
        signature = IssuerSigningAdapter(key, authorisation=_OwnerGate(key)).revocation_request(
            self.pp, request
        )
        require(signature.status is SigningStatus.SIGNED, "revocation-authorisation-signature")
        self._size("revocation_request_body", build_revocation_request_message(self.pp, request))
        self._size("revocation_request_signature", signature.signature)
        self.manager.revoke(
            secrets.token_bytes(32), replace(request, signature=signature.signature)
        )
        state = decode_state(self.pp, self.manager.snapshot()[1].state.state)
        self._size("published_revocation_state", encode_state(self.pp, state))
        return state

    def synchronise(self, holder=None):
        holder = self.holder if holder is None else holder
        epoch = decode_state(self.pp, self.manager.snapshot()[1].state.state).epoch
        return holder.synchronise(self.manager, epoch)

    def revoke_update(self, *, own=False):
        target = self.holder if own else self._other_holders[-1]
        self._time("revocation", lambda: self.revoke(target.credential.identifier))
        result = self._time("holder_update", self.synchronise)
        return result

    def reopen(self):
        # Tickets below are retained by the live trusted coordinator BEFORE reopen,
        # never rediscovered and admitted from an untrusted database after a crash.
        manager_ticket = self.manager.ticket
        verifier_tickets = {k: v.ticket for k, v in self.verifiers.items()}
        journal = self.issuer.journal
        self.manager = BoundedDurableManager(
            self.manager_store, self.manager_permit, manager_ticket, signing_key=self.trusted[b"M"]
        )
        for name, index in (("A", 2), ("B", 3)):
            store = self.verifier_stores[name]
            store._deps = replace(
                store._deps, provider=_MeasuredProvider(self, store.key.service_id)
            )
            self.verifiers[name] = BaselineVerifier(
                store, self.verifier_permits[name], verifier_tickets[name], self.keys[index]
            )
        self.issuer = self._issuer(
            IssuerJournal(journal.path, journal.identity, journal.ticket, journal.generation)
        )
        self.holder = Holder(
            self.pp,
            self.holder.path,
            self.clock,
            self.holder.request_keys,
            self.holder.approved_policy,
        )
        self._other_holders = [
            Holder(self.pp, h.path, self.clock, h.request_keys, h.approved_policy)
            for h in self._other_holders
        ]
        return self

    def snapshot(self):
        manager = self.manager.snapshot()[1].state
        return {
            "manager_epoch": decode_state(self.pp, manager.state).epoch,
            "allocated_count": manager.allocated_count,
            "issuer_phases": sorted(
                row[0].decode() for row in self.issuer.journal.snapshot().values()
            ),
            "verifiers": {name: verifier.snapshot() for name, verifier in self.verifiers.items()},
            "holder_epoch": None
            if self.holder.checkpoint is None
            else self.holder.checkpoint.state.epoch,
        }

    def storage_inventory(self):
        """Disposable store sizes, without reading or exporting secret key bytes."""
        allowed = {
            "manager": {"authority.sqlite3", "authority.sqlite3-journal"},
            "verifier-A": {"authority.sqlite3", "authority.sqlite3-journal"},
            "verifier-B": {"authority.sqlite3", "authority.sqlite3-journal"},
            "issuer": {"issuer.sqlite3", "issuer.sqlite3-journal"},
            "holder": {"holder.key", "wallet.bin"},
        }
        for holder in self._other_holders:
            allowed[holder.path.name] = {"holder.key", "wallet.bin"}
        require({p.name for p in self.root.iterdir()} == set(allowed), "unexpected-trial-directory")
        files = []
        for name, names in allowed.items():
            path = directory(self.root / name)
            for item in path.iterdir():
                require(
                    item.name in names and item.is_file() and not item.is_symlink(),
                    "unexpected-trial-file",
                )
                info = item.stat()
                require(info.st_nlink == 1, "trial-hardlink")
                files.append(
                    {
                        "path": str(item.relative_to(self.root)),
                        "bytes": info.st_size,
                        "secret_material": item.name == "holder.key",
                    }
                )
        return files

    def cleanup(self):
        """Remove only registered fresh trial files after retained outcome evidence.

        Connections are operation-scoped and already closed. The benchmark caller
        records inventory/results before this call; failed fixtures stay retained.
        Historical stores, results, dependencies and templates are never touched.
        """
        inventory = self.storage_inventory()
        for item in inventory:
            (self.root / item["path"]).unlink()
        for child in self.root.iterdir():
            child.rmdir()
        self.root.rmdir()
        return inventory

    def setup_for(self, scenario_id):
        start = time.monotonic_ns()
        require(scenario_id in {"ISSUE", "PRESENT-A", "PRESENT-B", "REVOKE-UPDATE"}, "scenario")
        if scenario_id != "ISSUE":
            self.issue()
        if scenario_id == "REVOKE-UPDATE":
            self.add_holder()
        self.stages_ns, self.message_bytes = {}, {}
        return time.monotonic_ns() - start

    def run(self, scenario_id):
        self.stages_ns, self.message_bytes = {}, {}
        details = {}
        operation_start = time.monotonic_ns()
        if scenario_id == "ISSUE":
            self.issue()
            outcome = "accepted"
        elif scenario_id in {"PRESENT-A", "PRESENT-B"}:
            request = self._time("request", lambda: self.request(scenario_id[-1]))
            presentation = self._time("presentation", lambda: self.present(request))
            result = self._time("verification", lambda: self.verify(request, presentation))
            details["verification"] = result.value
            outcome = {
                "accepted": "accepted",
                "expired": "expired",
                "stale-or-unauthenticated-state": "stale-state",
            }.get(result.value, "unexpected-rejection")
        elif scenario_id == "REVOKE-UPDATE":
            result = self.revoke_update()
            affected = self._time(
                "affected_credential_rejection", lambda: self.synchronise(self._other_holders[-1])
            )
            details = {
                "surviving_witness_update": result.status.value,
                "affected_credential_rejection": affected.status.value,
                "rejection_boundary": "authenticated local witness-update rejection",
            }
            outcome = (
                "accepted"
                if (
                    result.status is UpdateStatus.UPDATED
                    and affected.status is UpdateStatus.REVOKED
                )
                else "unexpected-rejection"
            )
            page = self.holder.last_history.page
            self._size("revocation_update", page.records[0])
        else:
            raise ValueError("unknown scenario")
        operation_end = time.monotonic_ns()
        return {
            "outcome": outcome,
            "outcome_details": details,
            "operation_start_monotonic_ns": operation_start,
            "operation_end_monotonic_ns": operation_end,
            "stages_ns": dict(self.stages_ns),
            "message_bytes": dict(self.message_bytes),
            "state": self.snapshot(),
            "fixture_sha256": self.data.fixture_sha256,
            "source_fixture_sha256": self.data.source_fixture_sha256,
            "fixture_encoding": (
                "local canonical tuple: profile,pp,attributes,base-policy,epoch,120,validity-rule"
            ),
            "instance_sha256": hashlib.sha256(encode_parameters(self.pp)).hexdigest(),
            "signing": {
                "attempts": None,
                "exhaustion": False,
                "reason": "bounded core does not expose candidate count",
            },
            "disclosure": "full attributes, holder public key, issuer signature, rid and path",
            "transport": "local exact canonical bytes; no network framing",
        }
