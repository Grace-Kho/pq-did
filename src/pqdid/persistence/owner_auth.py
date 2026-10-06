"""Pilot-local capabilities and operation ACLs; never PQ-DAA authentication.

Secrets and policies are provisioned through a trusted owner configuration, not
requests. Same-UID peers are not isolated from the owner's filesystem or process.
"""

import hmac
from dataclasses import dataclass

from .codec import encode, require
from .sqlite_store import digest

ADMIN = frozenset({b"admit", b"replace", b"status"})
MANAGER = frozenset({b"reserve", b"reservation", b"allocation-count", b"status"})
VERIFIER = frozenset({b"register", b"verify", b"status"})
ISSUER = frozenset(
    {b"intent", b"attach", b"pending", b"claim", b"certify", b"reconcile", b"status"}
)
OBSERVER = frozenset({b"status"})
RECIPIENT = frozenset({b"retrieve"})
PERMISSIONS = frozenset().union(ADMIN, MANAGER, VERIFIER, ISSUER, OBSERVER, RECIPIENT)


@dataclass(frozen=True, repr=False)
class Principal:
    name: bytes
    secret: bytes
    permissions: frozenset[bytes]
    uid: int
    gid: int
    issuer_service: bytes | None = None
    recipient: bytes | None = None

    def __post_init__(self):
        require(type(self.name) is bytes and 1 <= len(self.name) <= 64, "principal")
        require(type(self.secret) is bytes and len(self.secret) == 32, "capability")
        require(
            type(self.permissions) is frozenset and self.permissions <= PERMISSIONS, "permissions"
        )
        require(
            all(type(v) is int and 0 <= v < 1 << 32 for v in (self.uid, self.gid)), "peer-policy"
        )
        if self.issuer_service is not None:
            require(type(self.issuer_service) is bytes and len(self.issuer_service) == 32)
        if self.recipient is not None:
            require(type(self.recipient) is bytes and 1 <= len(self.recipient) <= 256)
        require(
            not self.permissions & {b"reserve", b"reservation"} or self.issuer_service is not None
        )
        require((b"retrieve" in self.permissions) == (self.recipient is not None))


class AuthorityPolicy:
    """Immutable owner-scope configuration; empty grants deny every IPC caller."""

    def __init__(self, key, writers, principals=()):
        self._identity = encode(key.identity())
        self.scope = digest((b"PQ-DID/local-owner-scope/v1", key.identity()))
        require(type(writers) is tuple and 1 <= len(writers) <= 4)
        require(all(type(w) is bytes and 1 <= len(w) <= 64 for w in writers))
        require(len(set(writers)) == len(writers))
        require(type(principals) is tuple and len(principals) <= 8)
        require(all(type(p) is Principal for p in principals))
        require(len({p.name for p in principals}) == len(principals), "duplicate-principal")
        require(len({p.secret for p in principals}) == len(principals), "duplicate-capability")
        require(not set(writers) & {p.name for p in principals}, "internal-identity-overlap")
        self._writers, self._principals = writers, principals

    def authenticate(self, secret, scope, peer):
        require(type(secret) is bytes and len(secret) == 32, "denied")
        require(type(scope) is bytes and hmac.compare_digest(scope, self.scope), "denied")
        found = None
        for principal in self._principals:
            matches = hmac.compare_digest(secret, principal.secret)
            if matches and (principal.uid, principal.gid) == peer[1:]:
                found = principal
        require(found is not None, "denied")
        return found

    @staticmethod
    def authorise(principal, operation):
        require(operation in principal.permissions, "denied")

    def recipient_exists(self, recipient):
        return any(p.recipient == recipient for p in self._principals)

    def allow(self, key, principal, action):
        # Internal durable-store policy. IPC authentication/ACL occurs separately first.
        if encode(key.identity()) != self._identity:
            return False
        if principal in self._writers:
            return action in {"read", "write", "approve-issue", "sign-issue"}
        if action in {"initialise", "replace"}:
            return any(
                p.name == principal and b"replace" in p.permissions for p in self._principals
            )
        return action == "retrieve" and self.recipient_exists(principal)
