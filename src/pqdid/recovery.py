"""Fail-closed admission of recovered LOCAL reference services.

The injected authority is an independent trust boundary, not a file/signature
checker. Its exclusive lease covers freshness and permission to activate; default
unavailable. No durable storage, distributed fencing or production authority is
implemented. See docs/stage2_recovery_admission.md for the precise trust contract.
"""

from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from threading import Lock
from typing import Protocol

from pqdid import did_state as did
from pqdid import issuance as issue
from pqdid import revocation_state as rev
from pqdid import verifier_state as verifier
from pqdid import witness_updates as updates
from pqdid.codec import EncodingError, require_uint
from pqdid.credentials import (
    CREDENTIAL_SIGNING_CONTEXT,
    build_mcred,
    decode_credential,
)
from pqdid.merkle import path_root
from pqdid.parameters import PublicParameters, decode_parameters, validate_parameters_structure
from pqdid.recovery_records import (
    DEFAULT_RECOVERY_LIMITS,
    ROLE_TYPES,
    ApprovedChallenge,
    CertificationRecord,
    ChallengeRecord,
    Checkpoint,
    ControllerRecord,
    DIDHistory,
    HolderRecord,
    IssuedRecord,
    IssuerRecord,
    IssuerSession,
    ManagerRecord,
    RecoveryLimits,
    RegistryRecord,
    ResolverRecord,
    Role,
    VerifierRecord,
    WitnessRecord,
    checkpoint_digest,
)
from pqdid.schema import decode_attributes
from pqdid.statements import (
    decode_context,
    decode_enrol_statement,
    decode_state,
)


class Admission(Enum):
    QUARANTINED = "quarantined"
    VALIDATING = "validating"
    ADMITTED = "admitted"
    REJECTED = "rejected"


class RecoveryUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("recovered operation unavailable")


@dataclass(frozen=True)
class RecoveryBinding:
    role: Role
    service_id: bytes
    checkpoint_digest: bytes


@dataclass(frozen=True)
class RecoveryEvidence:
    authority_id: bytes
    binding: RecoveryBinding


class RecoveryAuthority(Protocol):
    def exclusive(
        self, binding: RecoveryBinding
    ) -> AbstractContextManager[RecoveryEvidence | None]:
        """Independently compare complete latest role state and grant sole local writer.

        Serialise authoritative changes against activation inside this context.
        Evidence covers ALL reservation/consumption/session/history transitions,
        including failed replies, plus bound trusted configuration. Retire prior
        writer before granting. Never derive currentness from the candidate itself.
        The production rollback-resistant ledger/lease implementation is OPEN.
        """
        ...


class UnavailableAuthority:
    @contextmanager
    def exclusive(self, binding):
        yield None


@dataclass(frozen=True, repr=False)
class KeyHandle:
    name: bytes
    public_key: bytes
    signer: rev.ManagerSigner


@dataclass(frozen=True, repr=False)
class Dependencies:
    """Trusted live dependencies, never deserialised from recovery data.

    Services supplied here are admitted recovered facades or explicitly trusted
    live initial services. Signers/clock/nonce sources retain their prior contracts.
    """

    signer: object = None
    proof_verifier: object = None
    nonces: object = None
    clock: object = None
    provider: object = None
    manager: object = None
    resolver: object = None
    authorisation: object = None
    transport: object = None
    did_config: did.DIDConfiguration | None = None
    keys: tuple[KeyHandle, ...] = ()
    audience: bytes = b""
    request_key: bytes = b""
    manager_limits: rev.ManagerLimits = rev.DEFAULT_MANAGER_LIMITS
    issue_limits: issue.IssueLimits = issue.DEFAULT_ISSUE_LIMITS
    did_limits: did.DIDLimits = did.DEFAULT_DID_LIMITS
    verifier_capacity: int = 100
    proof_byte_limit: int = 10 * 1024**2
    nonce_draws: int = 8


DEFAULT_DEPENDENCIES = Dependencies()


def _require(condition):
    if not condition:
        raise EncodingError("inconsistent recovery record")


def _ordered(values, kind, cap, *, width=None):
    _require(type(values) is tuple and len(values) <= cap)
    previous = None
    for value in values:
        _require(type(value) is kind)
        if width is not None:
            _require(len(value) == width)
        _require(previous is None or previous < value)
        previous = value


def _witness(pp, record):
    _require(type(record) is WitnessRecord)
    state = decode_state(pp, record.state)
    issue._state_auth(pp, state)
    _require(path_root(pp.domain, record.identifier, 0, record.path) == state.root)
    return updates.WitnessCheckpoint(record.identifier, record.path, state)


def _issued(pp, record):
    _require(type(record) is IssuedRecord)
    credential = decode_credential(pp, record.credential)
    checkpoint = _witness(pp, record.witness)
    _require(credential.revocation_identifier == checkpoint.identifier)
    issue._verify(
        pp.issuer_public_key,
        build_mcred(pp, credential.metadata, credential.certificate.binding, checkpoint.identifier),
        credential.certificate.signature,
        CREDENTIAL_SIGNING_CONTEXT,
        issue.IssueStatus.UNAUTHORISED,
    )
    return issue.IssuedCredential(credential, checkpoint)


def _work(record):
    """Conservative validation work units; checked before any crypto/reconstruction.

    Includes signature/key validation and sparse-tree work; each unit has the
    existing suite's fixed bounded loops. Also preflight each role's cardinalities.
    """
    if type(record) is ManagerRecord:
        _ordered(record.base_revoked, int, rev.MAX_REVOKED)
        _ordered(record.revoked, int, rev.MAX_REVOKED)
        _ordered(record.base_nonces, bytes, rev.MAX_NONCES, width=32)
        _ordered(record.consumed_nonces, bytes, rev.MAX_NONCES, width=32)
        _require(type(record.history) is tuple and len(record.history) <= rev.MAX_HISTORY)
        return 8 + 4 * len(record.history) + 3 * (len(record.revoked) + len(record.base_revoked))
    if type(record) is IssuerRecord:
        _require(len(record.sessions) <= 64 and len(record.certifications) <= 64)
        _ordered(record.used_nonces, bytes, 64, width=32)
        _require(all(type(s) is IssuerSession for s in record.sessions))
        _ordered(tuple(s.name for s in record.sessions), bytes, 64)
        _require(all(type(c) is CertificationRecord for c in record.certifications))
        return 8 + 8 * len(record.sessions) + 4 * len(record.certifications)
    if type(record) is VerifierRecord:
        _require(len(record.challenges) <= 100)
        _require(all(type(c) is ChallengeRecord for c in record.challenges))
        return 8 + 4 * len(record.challenges)
    if type(record) is RegistryRecord:
        _require(len(record.histories) <= 32)
        _require(all(type(h) is DIDHistory for h in record.histories))
        _ordered(tuple(h.did for h in record.histories), bytes, 32, width=171)
        count = sum(len(h.records) for h in record.histories)
        _require(count <= 32 and all(h.records for h in record.histories))
        return 8 + 4 * count
    if type(record) is ResolverRecord:
        _ordered(record.used_nonces, bytes, 64, width=32)
        return 8
    if type(record) is ControllerRecord:
        _require(len(record.history) + (record.pending is not None) <= 32)
        return 16 + 4 * len(record.history)
    _require(type(record) is HolderRecord)
    return 16


def _manager(pp, record, deps):
    require_uint(record.allocated_count, 21)
    _require(record.allocated_count <= 1 << 20)
    base = decode_state(pp, record.base_state)
    state = decode_state(pp, record.state)
    # Reconstruct both sparse roots, not a 2^20-leaf inventory. Original bootstrap
    # prefix/base trust still requires independent evidence for the whole record.
    service = rev.ReferenceRevocationManager(
        pp,
        state=base,
        allocated_count=record.allocated_count,
        revoked=frozenset(record.base_revoked),
        consumed_nonces=frozenset(record.base_nonces),
        signer=deps.signer,
        limits=deps.manager_limits,
    )
    current = service.snapshot()
    _require(len(record.history) <= deps.manager_limits.history)
    _require(len(record.revoked) <= deps.manager_limits.revoked)
    _require(len(record.consumed_nonces) <= deps.manager_limits.nonces)
    _require(len(record.history) == state.epoch - base.epoch)
    # Requests' nonces are not in public update encodings. Their relation to each
    # committed transition needs the independent complete-role provenance anchor.
    _require(set(record.base_nonces) <= set(record.consumed_nonces))
    _require(len(record.consumed_nonces) == len(record.base_nonces) + len(record.history))
    tree, revoked, previous = current.tree, set(record.base_revoked), base
    for encoded in record.history:
        update = updates.decode_update(pp, encoded)
        rid = update.revoked_identifier
        _require(update.old_state.reference == previous.reference)
        _require(update.new_state.epoch == previous.epoch + 1)
        _require(rid < record.allocated_count and rid not in revoked)
        _require(tree.path(rid) == update.old_path)
        issue._state_auth(pp, update.old_state)
        issue._state_auth(pp, update.new_state)
        updates._authenticate(
            pp,
            updates.build_update_message(pp, update),
            update.signature,
            updates.UPDATE_SIGNING_CONTEXT,
        )
        tree = tree.revoke(pp, rid)
        _require(tree.root == update.new_state.root)
        revoked.add(rid)
        previous = update.new_state
    issue._state_auth(pp, state)
    _require(previous.reference == state.reference and tree.root == state.root)
    _require(revoked == set(record.revoked))
    service._snapshot = rev.ManagerSnapshot(
        state,
        base,
        record.allocated_count,
        frozenset(revoked),
        frozenset(record.consumed_nonces),
        record.history,
        tree,
    )
    return service


def _issuer(pp, record, deps):
    _require(
        deps.manager is not None and deps.resolver is not None and deps.authorisation is not None
    )
    require_uint(record.allocated_floor, 21)
    _require(record.allocated_floor <= 1 << 20)
    validate_parameters_structure(deps.manager.parameters, expected=pp)
    _require(deps.manager.snapshot().allocated_count >= record.allocated_floor)
    _require(len(record.sessions) <= deps.issue_limits.sessions)
    service = issue.ReferenceIssuer(
        pp,
        resolver=deps.resolver,
        authorisation=deps.authorisation,
        manager=deps.manager,
        signer=deps.signer,
        proof_verifier=deps.proof_verifier,
        nonces=deps.nonces,
        limits=deps.issue_limits,
    )
    ids, nonces = set(), set()
    for row in record.sessions:
        issue._session_name(row.name)
        # In-flight operations require a durable intent/outcome policy. Do not
        # silently retry or turn CLAIMED/PREPARING into empty/pending sessions.
        _require(
            row.phase
            in {
                issue.SessionPhase.PENDING,
                issue.SessionPhase.ABORTED,
                issue.SessionPhase.CERTIFIED,
            }
        )
        if row.identifier is not None:
            require_uint(row.identifier, 20)
            _require(row.identifier < record.allocated_floor and row.identifier not in ids)
            ids.add(row.identifier)
        if row.nonce is not None:
            _require(type(row.nonce) is bytes and len(row.nonce) == 32)
            _require(row.identifier is not None and row.nonce not in nonces)
            nonces.add(row.nonce)
        challenge, controller = None, None
        if row.challenge is not None:
            approved = row.challenge
            _require(type(approved) is ApprovedChallenge and row.nonce is not None)
            values = decode_attributes(pp.schema, approved.attributes)
            _require(values[pp.schema.did_index - 1] == approved.did)
            _require(values[pp.schema.version_index - 1] == approved.version)
            state = decode_state(pp, approved.state)
            issue._state_auth(pp, state)
            did._key(approved.controller_key)
            controller = issue.ControllerResolution(
                approved.did,
                verifier.ResolvedDID(
                    b'{"id":"' + approved.did + b'"}',
                    approved.version,
                    "application/did+json",
                    True,
                ),
                approved.controller_key,
            )
            issue._controller(controller, approved.did, approved.version)
            challenge = issue.EnrolmentChallenge(
                pp, approved.attributes, row.identifier, row.nonce, state
            )
        if row.phase in {issue.SessionPhase.PENDING, issue.SessionPhase.CERTIFIED}:
            _require(challenge is not None)
        service._sessions[row.name] = issue._Session(
            row.phase,
            row.identifier,
            row.nonce,
            challenge,
            controller,
        )
    _require(nonces == set(record.used_nonces))
    certified, issued = set(), []
    for row in record.certifications:
        _require(row.session in service._sessions and row.session not in certified)
        entry = service._sessions[row.session]
        _require(entry.phase is issue.SessionPhase.CERTIFIED)
        credential = _issued(pp, row.issued)
        _require(credential.checkpoint.identifier == entry.identifier)
        _require(credential.checkpoint.state == entry.challenge.state)
        _require(credential.credential.attributes == entry.challenge.approved_attributes)
        certified.add(row.session)
        issued.append(credential)
    _require(
        certified
        == {n for n, s in service._sessions.items() if s.phase is issue.SessionPhase.CERTIFIED}
    )
    service._used_nonces = set(record.used_nonces)
    service._certifications = tuple(issued)
    return service


def _verifier(pp, record, deps):
    _require(record.audience == deps.audience and record.request_key == deps.request_key)
    _require(deps.clock is not None and deps.provider is not None)
    _require(type(deps.verifier_capacity) is int and 1 <= deps.verifier_capacity <= 100)
    _require(len(record.challenges) <= deps.verifier_capacity)
    require_uint(deps.clock.now(), 64)  # Current trusted clock; never a saved time.
    store = verifier.InMemoryChallengeStore(record.audience, capacity=deps.verifier_capacity)
    previous = None
    for row in record.challenges:
        _require(type(row.require_did_state) is bool and type(row.consumed) is bool)
        context, state = decode_context(pp, row.context), decode_state(pp, row.state)
        _require(previous is None or previous < context.nonce)
        previous = context.nonce
        _require(context.audience == record.audience and context.state_reference == state.reference)
        if row.require_did_state:
            _require(
                {pp.schema.did_index, pp.schema.version_index} <= set(context.policy.disclosed)
            )
        issue._state_auth(pp, state)
        # Preserve expired records and all consumed flags, including unsigned
        # reservations left by failed request signing. No resurrection or eviction.
        store._records[context.nonce] = verifier.StoredChallenge(
            pp,
            context,
            state,
            row.require_did_state,
        )
        if row.consumed:
            store._consumed.add(context.nonce)
    return verifier.ReferenceVerifier(
        parameters=pp,
        audience=record.audience,
        request_public_key=record.request_key,
        clock=deps.clock,
        store=store,
        provider=deps.provider,
        signer=deps.signer,
        proof_verifier=deps.proof_verifier,
        nonces=deps.nonces,
        proof_byte_limit=deps.proof_byte_limit,
        max_nonce_draws=deps.nonce_draws,
    )


def _config(pp, record, deps):
    config = deps.did_config
    _require(type(config) is did.DIDConfiguration and config.parameters == pp)
    _require(
        record.registry_id == config.registry_id
        and record.registry_key == config.registry_public_key
    )
    return config


def _chain(config, records):
    previous, chain = None, []
    for encoded in records:
        record = did.decode_did_record(encoded)
        did._transition(config, record, previous)
        chain.append(record)
        previous = record
    return tuple(chain)


def _registry(pp, record, deps):
    config = _config(pp, record, deps)
    _require(sum(len(h.records) for h in record.histories) <= deps.did_limits.records)
    service = did.ReferenceDIDRegistry(config, signer=deps.signer, limits=deps.did_limits)
    for history in record.histories:
        chain = _chain(config, history.records)
        _require(chain[-1].body.did == history.did)
        service._histories[history.did] = chain
    return service


def _resolver(pp, record, deps):
    config = _config(pp, record, deps)
    _require(deps.transport is not None and len(record.used_nonces) <= deps.did_limits.reads)
    service = did.ReferenceDIDResolver(
        config, deps.transport, nonces=deps.nonces, limits=deps.did_limits
    )
    service._used = set(record.used_nonces)
    return service


def _key_handle(deps, name, key):
    _require(type(deps.keys) is tuple and len(deps.keys) <= 2)
    _require(all(type(k) is KeyHandle for k in deps.keys))
    _require(len({k.name for k in deps.keys}) == len(deps.keys))
    matches = [k for k in deps.keys if k.name == name and k.public_key == key]
    _require(type(name) is bytes and len(name) == 32 and len(matches) == 1)
    _require(matches[0].signer is not None)
    return matches[0].signer


def _controller(pp, record, deps):
    config = _config(pp, record, deps)
    _require(deps.resolver is not None and deps.resolver.config == config)
    _require(len(record.history) + (record.pending is not None) <= deps.did_limits.records)
    identity = did.make_did(config, record.genesis_key, record.salt)
    chain = _chain(config, record.history)
    if chain:
        _require(
            chain[0].body.did == identity and chain[0].body.controller_key == record.genesis_key
        )
        _require(chain[0].body.salt == record.salt)
    previous = chain[-1] if chain else None
    key = previous.body.controller_key if previous else record.genesis_key
    signer = _key_handle(deps, record.signer_handle, key)
    service = did.ReferenceDIDController(
        deps.resolver, record.genesis_key, record.salt, signer=signer
    )
    pending = None
    if record.pending is not None:
        pending = did.decode_did_record(record.pending)
        did._transition(config, pending, previous)
        _require(pending.body.did == identity)
        service._pending_signer = _key_handle(
            deps, record.pending_signer_handle, pending.body.controller_key
        )
    else:
        _require(record.pending_signer_handle is None)
    service._state = did.ControllerSnapshot(
        identity, key, previous.version if previous else None, pending
    )
    return service


class _Holder:
    def __init__(self, acceptance, checkpoint):
        self.acceptance, self._checkpoint = acceptance, checkpoint

    def snapshot(self):
        return self.acceptance.snapshot()

    def checkpoint(self):
        return self._checkpoint

    def accept(self, issued):
        outcome = self.acceptance.accept(issued)
        if outcome.status is issue.IssueStatus.ACCEPTED:
            self._checkpoint = outcome.issued.checkpoint
        return outcome


def _holder(pp, record, deps):
    intent = decode_enrol_statement(pp, record.intent)
    acceptance = issue.HolderAcceptance(pp, record.secret, intent.approved_attributes, intent)
    checkpoint = None
    if record.accepted is not None:
        issued = _issued(pp, record.accepted)
        _require(acceptance.accept(issued).status is issue.IssueStatus.ACCEPTED)
        checkpoint = _witness(pp, record.current_witness)
        _require(checkpoint.identifier == issued.checkpoint.identifier)
        _require(checkpoint.state.epoch >= issued.checkpoint.state.epoch)
        if checkpoint.state.epoch == issued.checkpoint.state.epoch:
            _require(checkpoint.state.reference == issued.checkpoint.state.reference)
    else:
        _require(record.current_witness is None)
    return _Holder(acceptance, checkpoint)


_BUILDERS: dict[Role, Callable] = dict(
    zip(
        Role,
        (
            _manager,
            _issuer,
            _verifier,
            _registry,
            _resolver,
            _controller,
            _holder,
        ),
        strict=True,
    )
)
_METHODS = {
    Role.MANAGER: {
        "snapshot",
        "reserve_identifier",
        "registered_witness",
        "revoke",
        "read_current",
        "updates",
        "instance",
        "current",
        "resolve_did",
    },
    Role.ISSUER: {"snapshot", "begin", "finish", "abort"},
    Role.VERIFIER: {"create_challenge", "verify"},
    Role.REGISTRY: {"snapshot", "read", "append"},
    Role.RESOLVER: {"resolve"},
    Role.CONTROLLER: {"snapshot", "publish", "recover"},
    Role.HOLDER: {"snapshot", "checkpoint", "accept"},
}


class RecoveredService:
    """One-shot admission and role facade. No public raw-service escape hatch.

    Quarantined/rejected/validating calls raise RecoveryUnavailable. A nonblocking
    gate also refuses concurrent calls during admission; runtime methods otherwise
    preserve original results. Python private access is not an adversarial sandbox.
    """

    def __init__(
        self,
        parameters: PublicParameters,
        role: Role,
        service_id: bytes,
        *,
        authority_id: bytes,
        authority: RecoveryAuthority | None = None,
        dependencies: Dependencies = DEFAULT_DEPENDENCIES,
        limits: RecoveryLimits = DEFAULT_RECOVERY_LIMITS,
    ):
        validate_parameters_structure(parameters)
        _require(type(role) is Role and type(service_id) is bytes and len(service_id) == 32)
        _require(type(authority_id) is bytes and len(authority_id) == 32)
        _require(type(dependencies) is Dependencies and type(limits) is RecoveryLimits)
        limits.__post_init__()
        self._parameters, self._role, self._id = parameters, role, service_id
        self._authority_id = authority_id
        self._authority = authority if authority is not None else UnavailableAuthority()
        self._deps, self._limits = replace(dependencies), limits
        self._admission, self._service, self._lock = Admission.QUARANTINED, None, Lock()

    @property
    def admission(self):
        return self._admission

    @property
    def parameters(self):
        # Pinned configuration alone is not an authoritative state observation.
        return self._parameters

    @property
    def config(self):
        if not self._lock.acquire(blocking=False):
            raise RecoveryUnavailable()
        try:
            if self._admission is not Admission.ADMITTED or self._role not in {
                Role.REGISTRY,
                Role.RESOLVER,
            }:
                raise RecoveryUnavailable()
            return self._service.config
        finally:
            self._lock.release()

    def admit(self, checkpoint: Checkpoint) -> Admission:
        if not self._lock.acquire(blocking=False):
            raise RecoveryUnavailable()
        try:
            if self._admission is not Admission.QUARANTINED:
                raise RecoveryUnavailable()
            self._admission = Admission.VALIDATING
            try:
                digest = checkpoint_digest(checkpoint, self._limits)
                _require(type(checkpoint.version) is int and checkpoint.version == 1)
                _require(checkpoint.role is self._role and checkpoint.service_id == self._id)
                decode_parameters(checkpoint.parameters, expected=self._parameters)
                _require(type(checkpoint.state) is ROLE_TYPES[self._role])
                _require(_work(checkpoint.state) <= self._limits.work)
                candidate = _BUILDERS[self._role](self._parameters, checkpoint.state, self._deps)
                binding = RecoveryBinding(self._role, self._id, digest)
                with self._authority.exclusive(binding) as evidence:
                    _require(type(evidence) is RecoveryEvidence)
                    _require(
                        evidence.authority_id == self._authority_id and evidence.binding == binding
                    )
                    # Effective activation point, serialised against authoritative
                    # advancement by the trusted lease, and calls by our local gate.
                    self._service = candidate
                    self._admission = Admission.ADMITTED
                # A context-manager adapter must not turn a suppressed validation
                # exception into an apparently completed admission attempt.
                _require(self._admission is Admission.ADMITTED)
                return self._admission
            except BaseException as error:
                # Even a resource/lease-exit interruption cannot publish a partial
                # candidate. No caller can enter until the outer gate is released.
                self._service, self._admission = None, Admission.REJECTED
                if isinstance(error, Exception):
                    return Admission.REJECTED
                raise
        finally:
            self._lock.release()

    def __getattr__(self, name):
        if name not in _METHODS[self._role]:
            raise AttributeError(name)

        def guarded(*args, **kwargs):
            if not self._lock.acquire(blocking=False):
                raise RecoveryUnavailable()
            try:
                if self._admission is not Admission.ADMITTED:
                    raise RecoveryUnavailable()
                return getattr(self._service, name)(*args, **kwargs)
            finally:
                self._lock.release()

        return guarded
