"""TEST-ONLY quiescent checkpoint capture and independently held authority oracle.

Not a storage engine/export API, cryptographic receipt or production rollback anchor.
Authority decisions are deterministic; inherited native test keys are ephemeral.
"""

from contextlib import contextmanager
from threading import Lock

from pqdid.credentials import encode_credential
from pqdid.did_state import encode_did_record
from pqdid.parameters import encode_parameters
from pqdid.recovery import (
    DEFAULT_DEPENDENCIES,
    Dependencies,
    KeyHandle,
    RecoveredService,
    RecoveryBinding,
    RecoveryEvidence,
)
from pqdid.recovery_records import (
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
    RegistryRecord,
    ResolverRecord,
    Role,
    VerifierRecord,
    WitnessRecord,
    checkpoint_digest,
)
from pqdid.statements import encode_context, encode_enrol_statement, encode_state

from .revocation_state_cases import RecordingSigner

SERVICE_ID = b"S" * 32
AUTHORITY_ID = b"A" * 32
KEY = b"K" * 32
NEXT_KEY = b"N" * 32


def binding(checkpoint):
    return RecoveryBinding(checkpoint.role, checkpoint.service_id, checkpoint_digest(checkpoint))


class FixtureRecoveryAuthority:
    """Explicit independently retained fixture oracle, NEVER reads candidate state.

    Test code records the authoritative checkpoint after named transitions. One
    exclusive activation grant; further recovery needs an explicit new fixture.
    The oracle is not itself checkpointed alongside the service under test.
    """

    def __init__(self, authoritative):
        self.latest = binding(authoritative)
        self.authority_id = AUTHORITY_ID
        self.before = lambda: None
        self.inside = lambda: None
        self.exit_error = None
        self.granted = False
        self.lock = Lock()

    @contextmanager
    def exclusive(self, requested):
        self.before()
        with self.lock:
            self.inside()
            allowed = requested == self.latest and not self.granted
            yield RecoveryEvidence(self.authority_id, requested) if allowed else None
            if self.exit_error:
                raise self.exit_error("TEST-ONLY-lease-exit-failure")
            if allowed:
                self.granted = True


def checkpoint(pp, role, state):
    return Checkpoint(1, role, SERVICE_ID, encode_parameters(pp), state)


def witness(pp, value):
    return WitnessRecord(value.identifier, value.path, encode_state(pp, value.state))


def issued(pp, value):
    return IssuedRecord(encode_credential(pp, value.credential), witness(pp, value.checkpoint))


def manager_checkpoint(h, base=None):
    manager, pp = h.issue.manager, h.pp
    value = manager.snapshot()
    base = value if base is None else base
    return checkpoint(
        pp,
        Role.MANAGER,
        ManagerRecord(
            value.allocated_count,
            encode_state(pp, value.base_state),
            tuple(sorted(base.revoked)),
            tuple(sorted(base.consumed_nonces)),
            encode_state(pp, value.state),
            tuple(sorted(value.revoked)),
            tuple(sorted(value.consumed_nonces)),
            value.history,
        ),
    )


def issuer_checkpoint(h):
    source, pp = h.issue.issuer, h.pp
    sessions, certificates = [], []
    for name, row in sorted(source._sessions.items()):
        approved = None
        if row.challenge:
            c = row.challenge
            approved = ApprovedChallenge(
                c.approved_attributes,
                encode_state(pp, c.state),
                row.controller.did,
                row.controller.resolution.version,
                row.controller.controller_public_key,
            )
        sessions.append(IssuerSession(name, row.phase, row.identifier, row.nonce, approved))
    for cert in source._certifications:
        name = next(
            n
            for n, s in source._sessions.items()
            if s.identifier == cert.credential.revocation_identifier
        )
        certificates.append(CertificationRecord(name, issued(pp, cert)))
    return checkpoint(
        pp,
        Role.ISSUER,
        IssuerRecord(
            h.issue.manager.snapshot().allocated_count,
            tuple(sessions),
            tuple(sorted(source._used_nonces)),
            tuple(certificates),
        ),
    )


def verifier_checkpoint(v):
    records = tuple(
        ChallengeRecord(
            encode_context(v.pp, row.context),
            encode_state(v.pp, row.state),
            row.require_did_state,
            nonce in v.store._consumed,
        )
        for nonce, row in sorted(v.store._records.items())
    )
    return checkpoint(
        v.pp,
        Role.VERIFIER,
        VerifierRecord(
            v.audience,
            v.verifier.request_public_key,
            records,
        ),
    )


def verifier_deps(v):
    return Dependencies(
        signer=v.verifier.signer,
        proof_verifier=v.adapter,
        nonces=v.nonces,
        clock=v.clock,
        provider=v.verifier.provider,
        audience=v.audience,
        request_key=v.verifier.request_public_key,
    )


def role_case(h, role):
    """Current, quiescent fully certified lifecycle state for each supported role."""
    pp, d = h.pp, h.did
    config = d.config
    if role is Role.MANAGER:
        return manager_checkpoint(h), Dependencies(signer=h.issue.manager._signer)
    if role is Role.ISSUER:
        src = h.issue.issuer
        return issuer_checkpoint(h), Dependencies(
            manager=h.issue.manager,
            resolver=src.resolver,
            authorisation=src.authorisation,
            signer=src.signer,
            proof_verifier=src.proof_verifier,
            nonces=src.nonces,
        )
    if role is Role.REGISTRY:
        state = RegistryRecord(
            config.registry_id,
            config.registry_public_key,
            tuple(
                DIDHistory(identity, tuple(encode_did_record(r) for r in chain))
                for identity, chain in d.registry.snapshot()
            ),
        )
        return checkpoint(pp, role, state), Dependencies(did_config=config, signer=d.signer)
    if role is Role.RESOLVER:
        state = ResolverRecord(
            config.registry_id, config.registry_public_key, tuple(sorted(d.resolver._used))
        )
        return checkpoint(pp, role, state), Dependencies(
            did_config=config, transport=d.transport, nonces=d.resolver.nonces
        )
    if role is Role.CONTROLLER:
        state = ControllerRecord(
            config.registry_id,
            config.registry_public_key,
            h.authority.controller.public_key,
            d.controller.salt,
            tuple(encode_did_record(r) for r in d.registry.snapshot()[0][1]),
            None,
            KEY,
            None,
        )
        return checkpoint(pp, role, state), Dependencies(
            did_config=config,
            resolver=d.resolver,
            keys=(
                KeyHandle(
                    KEY, h.authority.controller.public_key, RecordingSigner(h.authority.controller)
                ),
            ),
        )
    assert role is Role.HOLDER
    state = HolderRecord(
        h.issue.secret,
        encode_enrol_statement(pp, h.submission.statement),
        issued(pp, h.issued),
        witness(pp, h.issued.checkpoint),
    )
    return checkpoint(pp, role, state), Dependencies()


def gate(pp, record, deps=DEFAULT_DEPENDENCIES, authority=None, **kwargs):
    return RecoveredService(
        pp,
        record.role,
        record.service_id,
        authority_id=AUTHORITY_ID,
        authority=authority,
        dependencies=deps,
        **kwargs,
    )
