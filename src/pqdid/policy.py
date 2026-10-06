"""Public equality/range policies over disclosed fields only (V-A, VII-A.1)."""

from dataclasses import dataclass
from itertools import pairwise

from pqdid.codec import EncodingError, decode_record, decode_uint, encode_record, encode_uint
from pqdid.schema import (
    UINT64,
    AttributeValue,
    Schema,
    decode_attribute,
    decode_disclosed_attributes,
    decode_disclosure_mask,
    encode_attribute,
    encode_disclosure_mask,
)


@dataclass(frozen=True)
class Equality:
    index: int
    value: AttributeValue


@dataclass(frozen=True)
class Range:
    index: int
    lower: int
    upper: int


type Clause = Equality | Range


@dataclass(frozen=True)
class Policy:
    disclosed: tuple[int, ...]
    clauses: tuple[Clause, ...]


def encode_clause(schema: Schema, clause: Clause) -> bytes:
    if type(schema) is not Schema or type(clause) not in (Equality, Range):
        raise EncodingError("unsupported policy clause")
    field = schema.field(clause.index)
    index = encode_uint(clause.index, 1)
    if type(clause) is Equality:
        return encode_record("eq", (index, encode_attribute(field, clause.value)))
    if field.type_code != UINT64:
        raise EncodingError("range requires an unsigned-integer field")
    lower, upper = encode_uint(clause.lower, 8), encode_uint(clause.upper, 8)
    if clause.lower > clause.upper:
        raise EncodingError("inverted range")
    return encode_record("range", (index, lower, upper))


def decode_clause(schema: Schema, encoded: bytes) -> Clause:
    if type(schema) is not Schema:
        raise EncodingError("expected a validated schema")
    # Only two supported literal tags; neither fallback accepts unknown tags.
    try:
        index, value = decode_record(encoded, "eq")
    except EncodingError:
        index, lower, upper = decode_record(encoded, "range")
        clause = Range(decode_uint(index, 1), decode_uint(lower, 8), decode_uint(upper, 8))
    else:
        j = decode_uint(index, 1)
        clause = Equality(j, decode_attribute(schema.field(j), value))
    encode_clause(schema, clause)
    return clause


def _policy_fields(schema: Schema, policy: Policy) -> tuple[bytes, ...]:
    if type(schema) is not Schema or type(policy) is not Policy:
        raise EncodingError("invalid schema or policy")
    if type(policy.disclosed) is not tuple or type(policy.clauses) is not tuple:
        raise EncodingError("policy requires immutable tuples")
    if len(policy.clauses) > 32:
        raise EncodingError("policy exceeds 32 clauses")
    mask = encode_disclosure_mask(policy.disclosed, len(schema.fields))
    clauses = tuple(encode_clause(schema, clause) for clause in policy.clauses)
    if any(clause.index not in policy.disclosed for clause in policy.clauses):
        raise EncodingError("policy tests an undisclosed field")
    if any(left >= right for left, right in pairwise(clauses)):
        raise EncodingError("policy clauses must be distinct and canonically sorted")
    return (mask, *clauses)


def make_policy(schema: Schema, disclosed: tuple[int, ...], clauses: tuple[Clause, ...]) -> Policy:
    """Sort application-supplied clauses; reject duplicates and invalid policies."""
    if type(clauses) is not tuple or len(clauses) > 32:
        raise EncodingError("expected at most 32 clauses in a tuple")
    ordered = tuple(sorted(clauses, key=lambda clause: encode_clause(schema, clause)))
    policy = Policy(disclosed, ordered)
    _policy_fields(schema, policy)
    return policy


def encode_policy(schema: Schema, policy: Policy) -> bytes:
    return encode_record("policy", _policy_fields(schema, policy))


def decode_policy(schema: Schema, encoded: bytes) -> Policy:
    if type(schema) is not Schema:
        raise EncodingError("expected a validated schema")
    mask, *clauses = decode_record(encoded, "policy")
    policy = Policy(
        decode_disclosure_mask(mask, len(schema.fields)),
        tuple(decode_clause(schema, clause) for clause in clauses),
    )
    _policy_fields(schema, policy)
    return policy


def evaluate_policy(schema: Schema, policy: Policy, disclosed_bytes: bytes) -> bool:
    """Return satisfaction; malformed policies/disclosures raise EncodingError.

    This does not prove that the disclosed values were certified or authorised.
    Context-dependent bounds (e.g. validUntil >= texp) must be explicit clauses
    in the registered policy. No clock or hidden attributes are read here.
    """
    _policy_fields(schema, policy)
    values = decode_disclosed_attributes(schema, policy.disclosed, disclosed_bytes)
    for clause in policy.clauses:
        value = values[clause.index]
        if type(clause) is Equality:
            if value != clause.value:
                return False
        elif not clause.lower <= value <= clause.upper:
            return False
    return True
