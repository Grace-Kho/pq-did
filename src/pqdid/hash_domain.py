"""Public suite/instance inputs used by VII-A.1/.5 hash operations.

This validates canonical hash-domain bytes, not issuer trust, keys or complete pp.
The schema is derived from refI so callers cannot supply a contradictory copy.
"""

from dataclasses import dataclass, field

from pqdid.codec import EncodingError, decode_record, encode_record, require_bytes
from pqdid.schema import Schema, decode_schema

SUITE = b"PQ-DID-MITH-1"
NAMESPACE_BYTES = 32
HASH_BYTES = 48


@dataclass(frozen=True)
class HashDomain:
    suite: bytes
    issuer_reference: bytes
    namespace: bytes
    schema: Schema = field(init=False)

    def __post_init__(self) -> None:
        if require_bytes(self.suite) != SUITE:
            raise EncodingError("unsupported suite")
        if len(require_bytes(self.namespace)) != NAMESPACE_BYTES:
            raise EncodingError("namespace must contain exactly 32 bytes")
        issuer, key_id, encoded_schema = decode_record(self.issuer_reference, "iref")
        if not 1 <= len(issuer) <= 256 or not 1 <= len(key_id) <= 256:
            raise EncodingError("issuer/key identifiers must contain 1 to 256 bytes")
        object.__setattr__(self, "schema", decode_schema(encoded_schema))


def require_domain(domain: HashDomain) -> HashDomain:
    if type(domain) is not HashDomain:
        raise EncodingError("expected a validated hash domain")
    return domain


def encode_metadata(domain: HashDomain) -> bytes:
    """E(µ) = enc_meta(refI,ns), without adding suite or extra wrappers."""
    require_domain(domain)
    return encode_record("meta", (domain.issuer_reference, domain.namespace))


def require_hash(value: bytes) -> bytes:
    if len(require_bytes(value)) != HASH_BYTES:
        raise EncodingError("hash must contain exactly 48 bytes")
    return value
