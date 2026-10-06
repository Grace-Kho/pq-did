"""Depth-20 SHA3-384 Merkle reference mathematics (VII-A.1/.5, pp. 14–15).

No root authentication/freshness, allocation, credential or holder-knowledge checks
are performed. Private identifiers/paths remain local reference inputs.
"""

import hashlib
from hmac import compare_digest

from pqdid.codec import (
    PATH_SIBLINGS,
    EncodingError,
    encode_record,
    encode_uint,
    require_uint,
    unpack_sibling_path,
)
from pqdid.hash_domain import HashDomain, encode_metadata, require_domain, require_hash

TREE_DEPTH = PATH_SIBLINGS
IDENTIFIER_LIMIT = 1 << TREE_DEPTH


def leaf_hash(domain: HashDomain, leaf_status: int) -> bytes:
    """L_b; b=0 unrevoked, b=1 revoked. No identifier is part of the leaf."""
    require_domain(domain)
    require_uint(leaf_status, 1)
    encoded = encode_record(
        "leaf", (domain.suite, encode_metadata(domain), encode_uint(leaf_status, 1))
    )
    return hashlib.sha3_384(encoded).digest()


def node_hash(domain: HashDomain, level: int, left: bytes, right: bytes) -> bytes:
    """F_level(left,right), with node levels 1 through 20 inclusive."""
    require_domain(domain)
    if type(level) is not int or not 1 <= level <= TREE_DEPTH:
        raise EncodingError("node level must be between 1 and 20")
    require_hash(left)
    require_hash(right)
    encoded = encode_record(
        "node", (domain.suite, encode_metadata(domain), encode_uint(level, 1), left, right)
    )
    return hashlib.sha3_384(encoded).digest()


def default_subtree_roots(domain: HashDomain) -> tuple[bytes, ...]:
    """Return Z_0,...,Z_20 for all-unrevoked subtrees, using only 21 hashes."""
    roots = [leaf_hash(domain, 0)]
    for level in range(1, TREE_DEPTH + 1):
        roots.append(node_hash(domain, level, roots[-1], roots[-1]))
    return tuple(roots)


def path_root(domain: HashDomain, identifier: int, leaf_status: int, path: bytes) -> bytes:
    """Compute PathRoot using the raw 960-byte s_0,...,s_19 payload.

    Sibling index j is bottom-up (0..19). Identifier bit j chooses whether the
    current value is the left (0) or right (1) child of node F_(j+1).
    """
    require_domain(domain)
    require_uint(identifier, TREE_DEPTH)
    require_uint(leaf_status, 1)
    siblings = unpack_sibling_path(path)
    value = leaf_hash(domain, leaf_status)
    for j, sibling in enumerate(siblings):
        left, right = (sibling, value) if (identifier >> j) & 1 else (value, sibling)
        value = node_hash(domain, j + 1, left, right)
    return value


def verify_non_revocation_path(
    domain: HashDomain, identifier: int, path: bytes, supplied_root: bytes
) -> bool:
    """Check PathRoot(identifier,0,path) == supplied_root, and only that condition.

    Raises EncodingError on malformed inputs; returns False on a valid mismatch.
    The supplied root need not be authenticated/current and identifier allocation
    is not checked. A path can remain valid for an old root after revocation.
    """
    require_hash(supplied_root)
    return compare_digest(path_root(domain, identifier, 0, path), supplied_root)
