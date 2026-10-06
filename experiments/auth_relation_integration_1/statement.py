"""Trusted public preprocessing for the isolated, statement-specific Rauth.

No private witness enters this module. A PreparedPublic is an internal cache,
never prover-supplied advice. Compilation rederives it before using its constants.
Transport capacity failure is incomplete admission, not credential invalidity.
"""

import hashlib
from dataclasses import dataclass

from pqdid import bounded_mldsa as reference
from pqdid.codec import EncodingError
from pqdid.merkle import leaf_hash
from pqdid.parameters import PublicParameters
from pqdid.public_checks import pub_ok, public_policy_ok
from pqdid.statements import (
    AuthenticationStatement,
    decode_auth_statement,
    encode_auth_statement,
)

PUBLIC_TRANSPORT_BYTES = 65_536
PROFILE = "PQDID-AURORA-AUTH-DRAFT1/experimental-boolean-relation-v1"


class PublicCapacity(RuntimeError):
    """The public research transport could not be admitted; not a false proof."""


class PublicRejection(EncodingError):
    """Structural, authenticated-state, policy or bounded-expansion rejection."""


@dataclass(frozen=True, repr=False)
class PreparedPublic:
    parameters: PublicParameters
    statement: AuthenticationStatement
    encoded_statement: bytes
    matrix: tuple
    t1_hat: tuple
    public_key_hash: bytes
    zero_leaf: bytes
    preprocessing_sha256: str


def _identity(encoded, matrix, t1_hat, tr, zero_leaf):
    digest = hashlib.sha256(b"PQDID-AUTH-PUBLIC-PREPROCESSING-v1\0")
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    for row in matrix:
        for polynomial in row:
            for value in polynomial:
                digest.update(value.to_bytes(4, "big"))
    for polynomial in t1_hat:
        for value in polynomial:
            digest.update(value.to_bytes(4, "big"))
    digest.update(tr)
    digest.update(zero_leaf)
    return digest.hexdigest()


def prepare_public(expected_pp, statement) -> PreparedPublic:
    """Independently validate all public checks and expand the trusted issuer key.

    The original 30 independent 1,026-byte matrix budgets are used unchanged.
    StateAuth uses the bounded ML-DSA verifier. No caller acceptance bit, matrix,
    issuer identity, context override or uncapped native fallback is accepted.
    """
    encoded = encode_auth_statement(expected_pp, statement)
    if len(encoded) > PUBLIC_TRANSPORT_BYTES:
        raise PublicCapacity("statement exceeds isolated 65,536-byte transport")
    if not pub_ok(expected_pp, statement) or not public_policy_ok(expected_pp, statement):
        raise PublicRejection("public state authentication or policy rejected")
    rho, t1 = reference._decode_public_key(expected_pp.issuer_public_key)
    try:
        expanded = reference._expand_a(rho)
    except reference._SamplerExhausted as error:
        raise PublicRejection("public bounded ExpandA exhausted") from error
    matrix = tuple(tuple(tuple(poly) for poly in row) for row in expanded)
    t1_hat = tuple(
        tuple(reference._ntt([value * (1 << 13) % reference._Q for value in row])) for row in t1
    )
    tr = hashlib.shake_256(expected_pp.issuer_public_key).digest(64)
    zero_leaf = leaf_hash(expected_pp.domain, 0)
    identity = _identity(encoded, matrix, t1_hat, tr, zero_leaf)
    return PreparedPublic(expected_pp, statement, encoded, matrix, t1_hat, tr, zero_leaf, identity)


def parse_public(expected_pp, encoded: bytes) -> PreparedPublic:
    if type(encoded) is not bytes:
        raise PublicRejection("public statement must be exact bytes")
    if len(encoded) > PUBLIC_TRANSPORT_BYTES:
        raise PublicCapacity("statement exceeds isolated 65,536-byte transport")
    statement = decode_auth_statement(expected_pp, encoded)
    prepared = prepare_public(expected_pp, statement)
    if prepared.encoded_statement != encoded:
        raise PublicRejection("noncanonical public statement")
    return prepared


def validate_prepared(prepared: PreparedPublic) -> None:
    """Reject forged or modified preprocessing instead of trusting frozen fields."""
    if type(prepared) is not PreparedPublic:
        raise PublicRejection("expected internally prepared public statement")
    recomputed = prepare_public(prepared.parameters, prepared.statement)
    if recomputed != prepared:
        raise PublicRejection("public preprocessing disagrees with trusted statement")
