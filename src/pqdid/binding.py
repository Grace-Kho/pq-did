"""Local holder-binding consistency from VII-A.5, p. 15.

Y = SHA3-384(enc_holder(suite,E(µ),xH)); B = (Y,Esch(m)).
These operations do not certify a credential or prove possession to a verifier.
Secrets/attributes and returned preimages are private local inputs; never log them.
"""

import hashlib
from dataclasses import dataclass
from hmac import compare_digest

from pqdid.codec import EncodingError, decode_record, encode_record, require_bytes
from pqdid.hash_domain import HashDomain, encode_metadata, require_domain, require_hash
from pqdid.schema import ATTRIBUTE_VECTOR_BYTES, decode_attributes

HOLDER_SECRET_BYTES = 32


@dataclass(frozen=True, repr=False)
class BindingRepresentation:
    """The complete B, not just Y; suppress private attribute bytes in repr."""

    holder_value: bytes
    attributes: bytes

    def __post_init__(self) -> None:
        require_hash(self.holder_value)
        if len(require_bytes(self.attributes)) != ATTRIBUTE_VECTOR_BYTES:
            raise EncodingError("binding attributes must contain exactly 1024 bytes")


def encode_holder_input(domain: HashDomain, holder_secret: bytes) -> bytes:
    """Return the private hash preimage with exactly the manuscript's three fields."""
    require_domain(domain)
    if len(require_bytes(holder_secret)) != HOLDER_SECRET_BYTES:
        raise EncodingError("holder secret must contain exactly 32 bytes")
    return encode_record("holder", (domain.suite, encode_metadata(domain), holder_secret))


def holder_binding_value(domain: HashDomain, holder_secret: bytes) -> bytes:
    """Compute the 48-byte Y; attributes are paired with Y in B, not hashed into Y."""
    return hashlib.sha3_384(encode_holder_input(domain, holder_secret)).digest()


def _validate_binding(domain: HashDomain, binding: BindingRepresentation) -> None:
    require_domain(domain)
    if type(binding) is not BindingRepresentation:
        raise EncodingError("expected a binding representation")
    decode_attributes(domain.schema, binding.attributes)


def create_binding(
    domain: HashDomain, holder_secret: bytes, encoded_attributes: bytes
) -> BindingRepresentation:
    """Pair Y with the validated canonical attribute block; no issuer signature."""
    require_domain(domain)
    decode_attributes(domain.schema, encoded_attributes)
    return BindingRepresentation(holder_binding_value(domain, holder_secret), encoded_attributes)


def encode_binding(domain: HashDomain, binding: BindingRepresentation) -> bytes:
    _validate_binding(domain, binding)
    return encode_record("binding", (binding.holder_value, binding.attributes))


def decode_binding(domain: HashDomain, encoded: bytes) -> BindingRepresentation:
    require_domain(domain)
    holder_value, attributes = decode_record(encoded, "binding")
    binding = BindingRepresentation(holder_value, attributes)
    _validate_binding(domain, binding)
    return binding


def check_binding_consistency(
    domain: HashDomain,
    binding: BindingRepresentation,
    holder_secret: bytes,
    encoded_attributes: bytes,
) -> bool:
    """Check the local opening equations, not BindRep/certification or a ZK proof.

    Malformed inputs raise EncodingError. Valid but mismatched inputs return False.
    This local reference routine receives private inputs; do not expose it as a
    presentation-verifier API. No holder secret is stored in the representation.
    """
    _validate_binding(domain, binding)
    decode_attributes(domain.schema, encoded_attributes)
    matches_holder = compare_digest(
        binding.holder_value, holder_binding_value(domain, holder_secret)
    )
    matches_attributes = compare_digest(binding.attributes, encoded_attributes)
    return matches_holder & matches_attributes
