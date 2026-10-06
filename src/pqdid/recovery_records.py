"""Version 1 LOCAL recovery containers, never protocol encodings or freshness proofs.

Only immutable leaves are admitted. Embedded protocol objects use their existing
canonical byte encodings. Private records deliberately have no field repr.
"""

import hashlib
from dataclasses import dataclass, fields
from enum import Enum
from types import UnionType
from typing import get_args, get_origin, get_type_hints

from pqdid.codec import EncodingError
from pqdid.issuance import SessionPhase


class Role(Enum):
    MANAGER = "manager"
    ISSUER = "issuer"
    VERIFIER = "verifier"
    REGISTRY = "registry"
    RESOLVER = "resolver"
    CONTROLLER = "controller"
    HOLDER = "holder"


@dataclass(frozen=True, repr=False)
class WitnessRecord:
    identifier: int
    path: bytes
    state: bytes


@dataclass(frozen=True, repr=False)
class IssuedRecord:
    credential: bytes
    witness: WitnessRecord


@dataclass(frozen=True, repr=False)
class ManagerRecord:
    # Permanent contiguous prefix [0, allocated_count), INCLUDING abandoned issues.
    # Completeness requires independent authority over this entire record.
    allocated_count: int
    base_state: bytes
    base_revoked: tuple[int, ...]
    base_nonces: tuple[bytes, ...]
    state: bytes
    revoked: tuple[int, ...]
    consumed_nonces: tuple[bytes, ...]
    history: tuple[bytes, ...]


@dataclass(frozen=True, repr=False)
class ApprovedChallenge:
    attributes: bytes
    state: bytes
    did: bytes
    version: bytes
    controller_key: bytes


@dataclass(frozen=True, repr=False)
class IssuerSession:
    name: bytes
    phase: SessionPhase
    identifier: int | None
    nonce: bytes | None
    challenge: ApprovedChallenge | None


@dataclass(frozen=True, repr=False)
class CertificationRecord:
    session: bytes
    issued: IssuedRecord


@dataclass(frozen=True, repr=False)
class IssuerRecord:
    allocated_floor: int
    sessions: tuple[IssuerSession, ...]  # Sorted by name, never omit failed sessions.
    used_nonces: tuple[bytes, ...]
    certifications: tuple[CertificationRecord, ...]  # Original commit order.


@dataclass(frozen=True, repr=False)
class ChallengeRecord:
    context: bytes
    state: bytes
    require_did_state: bool
    consumed: bool


@dataclass(frozen=True, repr=False)
class VerifierRecord:
    audience: bytes
    request_key: bytes
    challenges: tuple[ChallengeRecord, ...]  # Sorted by decoded nonce.


@dataclass(frozen=True, repr=False)
class DIDHistory:
    did: bytes
    records: tuple[bytes, ...]


@dataclass(frozen=True, repr=False)
class RegistryRecord:
    registry_id: bytes
    registry_key: bytes
    histories: tuple[DIDHistory, ...]  # Sorted by DID, each full genesis chain.


@dataclass(frozen=True, repr=False)
class ResolverRecord:
    registry_id: bytes
    registry_key: bytes
    used_nonces: tuple[bytes, ...]


@dataclass(frozen=True, repr=False)
class ControllerRecord:
    registry_id: bytes
    registry_key: bytes
    genesis_key: bytes
    salt: bytes
    history: tuple[bytes, ...]  # Through locally confirmed version, not registry latest.
    pending: bytes | None
    signer_handle: bytes
    pending_signer_handle: bytes | None


@dataclass(frozen=True, repr=False)
class HolderRecord:
    secret: bytes
    intent: bytes
    accepted: IssuedRecord | None
    current_witness: WitnessRecord | None


@dataclass(frozen=True, repr=False)
class Checkpoint:
    version: int
    role: Role
    service_id: bytes  # Independently pinned deployment instance within pp/namespace.
    parameters: bytes
    state: (
        ManagerRecord
        | IssuerRecord
        | VerifierRecord
        | RegistryRecord
        | ResolverRecord
        | ControllerRecord
        | HolderRecord
    )


@dataclass(frozen=True)
class RecoveryLimits:
    bytes: int = 2 * 1024**2
    blob: int = 65536
    nodes: int = 8192
    records: int = 512
    work: int = 1024

    def __post_init__(self):
        for value, maximum in zip(
            (self.bytes, self.blob, self.nodes, self.records, self.work),
            (2 * 1024**2, 65536, 8192, 512, 1024),
            strict=True,
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise EncodingError("unsupported recovery limit")


RECORD_TYPES = (
    WitnessRecord,
    IssuedRecord,
    ManagerRecord,
    ApprovedChallenge,
    IssuerSession,
    CertificationRecord,
    IssuerRecord,
    ChallengeRecord,
    VerifierRecord,
    DIDHistory,
    RegistryRecord,
    ResolverRecord,
    ControllerRecord,
    HolderRecord,
    Checkpoint,
)
ROLE_TYPES = dict(
    zip(
        Role,
        (
            ManagerRecord,
            IssuerRecord,
            VerifierRecord,
            RegistryRecord,
            ResolverRecord,
            ControllerRecord,
            HolderRecord,
        ),
        strict=True,
    )
)


DEFAULT_RECOVERY_LIMITS = RecoveryLimits()
_SCHEMA = {kind: get_type_hints(kind) for kind in RECORD_TYPES}


def _matches(value, expected):
    origin = get_origin(expected)
    if origin is UnionType:
        return any(_matches(value, member) for member in get_args(expected))
    return type(value) is (tuple if origin is tuple else expected)


def checkpoint_digest(value: Checkpoint, limits: RecoveryLimits = DEFAULT_RECOVERY_LIMITS) -> bytes:
    """Bounded preflight + unambiguous local identity; NEVER independent evidence.

    Two passes: reject oversized graphs before hashing ANY payload. Tuples cannot
    contain mutable leaves or arbitrary objects; depth/work also bound cyclic or
    maliciously forged dataclasses. No serialised copy of the container is retained.
    """
    if type(value) is not Checkpoint or type(limits) is not RecoveryLimits:
        raise EncodingError("expected checkpoint and limits")
    limits.__post_init__()

    def visit(item, expected, emit, budget, depth=0):
        budget[0] += 1
        if budget[0] > limits.nodes or depth > 16:
            raise EncodingError("recovery node/depth limit")
        if not _matches(item, expected):
            raise EncodingError("incorrect recovery field type")
        kind = type(item)
        if kind in RECORD_TYPES:
            budget[1] += 1
            if budget[1] > limits.records:
                raise EncodingError("recovery record limit")
            emit(b"R" + kind.__name__.encode() + b"\0")
            for field in fields(item):
                visit(getattr(item, field.name), _SCHEMA[kind][field.name], emit, budget, depth + 1)
        elif kind is tuple:
            if len(item) > limits.nodes - budget[0]:
                raise EncodingError("recovery tuple limit")
            emit(b"T" + len(item).to_bytes(4))
            for child in item:
                visit(child, get_args(expected)[0], emit, budget, depth + 1)
        elif kind is bytes:
            budget[2] += len(item)
            if len(item) > limits.blob or budget[2] > limits.bytes:
                raise EncodingError("recovery byte limit")
            emit(b"B" + len(item).to_bytes(4))
            emit(item)
        elif kind in (Role, SessionPhase):
            emit(b"E" + kind.__name__.encode() + b":" + item.value.encode() + b"\0")
        elif kind is int and 0 <= item < 1 << 64:
            emit(b"I" + item.to_bytes(8))
        elif kind is bool:
            emit(b"1" if item else b"0")
        elif item is None:
            emit(b"N")
        else:
            raise EncodingError("unsupported recovery leaf")

    visit(value, Checkpoint, lambda _: None, [0, 0, 0])
    digest = hashlib.sha256(b"PQ-DID/local-recovery-container/v1\0")
    visit(value, Checkpoint, digest.update, [0, 0, 0])
    return digest.digest()
