"""Local identities and explicit policy: no default operator authorisation."""

from dataclasses import dataclass
from typing import Protocol

from pqdid.parameters import PublicParameters, encode_parameters
from pqdid.recovery_records import Role

from .codec import require

MAX_COUNTER = (1 << 63) - 1


@dataclass(frozen=True, repr=False)
class ServiceKey:
    role: Role
    service_id: bytes
    authority_id: bytes
    parameters: PublicParameters
    audience: bytes = b""

    def identity(self):
        require(self.role in (Role.MANAGER, Role.ISSUER, Role.VERIFIER), "unsupported-role")
        for value in (self.service_id, self.authority_id):
            require(type(value) is bytes and len(value) == 32)
        require(type(self.audience) is bytes and len(self.audience) <= 256)
        require(bool(self.audience) == (self.role is Role.VERIFIER))
        return (
            1,
            self.role,
            self.service_id,
            self.authority_id,
            encode_parameters(self.parameters),
            self.parameters.namespace,
            self.audience,
        )


@dataclass(frozen=True)
class HeadTicket:
    sequence: int
    digest: bytes
    checkpoint: bytes
    generation: int

    def __post_init__(self):
        require(type(self.sequence) is int and 1 <= self.sequence <= MAX_COUNTER, "counter")
        require(type(self.generation) is int and 0 <= self.generation <= MAX_COUNTER, "counter")
        require(
            all(type(v) is bytes and len(v) == 32 for v in (self.digest, self.checkpoint)),
            "head-identity",
        )

    def record(self):
        return (self.sequence, self.digest, self.checkpoint, self.generation)


@dataclass(frozen=True, repr=False)
class WriterPermit:
    principal: bytes
    generation: int

    def __post_init__(self):
        require(type(self.principal) is bytes and 1 <= len(self.principal) <= 256, "principal")
        require(type(self.generation) is int and 1 <= self.generation <= MAX_COUNTER, "counter")


@dataclass(frozen=True, repr=False)
class Outcome:
    operation: bytes
    decision: bytes
    response: bytes
    ticket: HeadTicket
    replay: bool = False


class Authorisation(Protocol):
    def allow(self, key: ServiceKey, principal: bytes, action: str) -> bool: ...


class DenyAll:
    def allow(self, key, principal, action):
        return False
