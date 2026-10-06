"""R-007: only supported, canonical policies over public disclosure bytes."""

import pytest

from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.policy import (
    Equality,
    Policy,
    Range,
    decode_clause,
    decode_policy,
    encode_clause,
    encode_policy,
    evaluate_policy,
    make_policy,
)
from pqdid.schema import encode_attributes, project_attributes


def test_policy_builder_matches_fixed_bytes(schema, vectors):
    clauses = (Range(6, 2000000000, 2**64 - 1), Equality(3, True), Range(4, 2, 2**64 - 1))
    policy = make_policy(schema, (3, 4, 6), clauses)
    assert encode_policy(schema, policy) == bytes.fromhex(vectors["E30"]["expected_hex"])
    assert decode_policy(schema, encode_policy(schema, policy)) == policy
    assert encode_policy(schema, make_policy(schema, (3,), (Equality(3, True),))) == bytes.fromhex(
        vectors["E10"]["expected_hex"]
    )


def test_policy_a_and_b_success_and_failure(schema, attributes):
    a = make_policy(
        schema,
        (3, 4, 6),
        (Equality(3, True), Range(4, 2, 2**64 - 1), Range(6, 2000000000, 2**64 - 1)),
    )
    b = make_policy(
        schema, (3, 5, 6), (Equality(3, True), Equality(5, b"SG"), Range(6, 2000000000, 2**64 - 1))
    )
    full = encode_attributes(schema, attributes)
    assert evaluate_policy(schema, a, project_attributes(schema, full, a.disclosed))
    assert evaluate_policy(schema, b, project_attributes(schema, full, b.disclosed))
    for index, bad_value, policy in [(2, False, a), (3, 1, a), (4, b"US", b), (5, 1999999999, a)]:
        values = list(attributes)
        values[index] = bad_value
        disclosed = project_attributes(schema, encode_attributes(schema, values), policy.disclosed)
        assert not evaluate_policy(schema, policy, disclosed)
    # Hidden values never enter public policy evaluation.
    changed_hidden = (b"different DID bytes", b"different version bytes", *attributes[2:])
    assert project_attributes(
        schema, encode_attributes(schema, changed_hidden), a.disclosed
    ) == project_attributes(schema, full, a.disclosed)


@pytest.mark.parametrize(
    "value,expected", [(0, False), (1, True), (2, True), (3, False), (2**64 - 1, False)]
)
def test_range_inclusive_endpoints(schema, attributes, value, expected):
    policy = make_policy(schema, (4,), (Range(4, 1, 2),))
    full = encode_attributes(schema, (*attributes[:3], value, *attributes[4:]))
    assert evaluate_policy(schema, policy, project_attributes(schema, full, (4,))) is expected


def test_empty_policy_and_clause_limit(schema, attributes):
    empty = make_policy(schema, (), ())
    assert evaluate_policy(schema, empty, b"")
    policy = make_policy(schema, (4,), tuple(Range(4, n, 100) for n in range(32)))
    assert len(decode_policy(schema, encode_policy(schema, policy)).clauses) == 32
    with pytest.raises(EncodingError):
        make_policy(schema, (4,), tuple(Range(4, n, 100) for n in range(33)))
    with pytest.raises(EncodingError):
        evaluate_policy(schema, empty, b"\0")


@pytest.mark.parametrize(
    "clause",
    [
        Equality(0, True),
        Equality(7, True),
        Equality(True, b"x"),
        Equality(3, 1),
        Equality(4, True),
        Range(3, 0, 1),
        Range(4, 2, 1),
        Range(4, -1, 2),
        Range(4, 0, 2**64),
        Range(4, True, 2),
        "age>=18",
    ],
)
def test_unsupported_clause_domains(schema, clause):
    with pytest.raises(EncodingError):
        encode_clause(schema, clause)


def test_hidden_field_duplicate_and_order_rejection(schema, vectors):
    with pytest.raises(EncodingError):
        make_policy(schema, (3,), (Range(4, 1, 2),))
    with pytest.raises(EncodingError):
        make_policy(schema, (3,), (Equality(3, True), Equality(3, True)))
    fields = decode_record(bytes.fromhex(vectors["E30"]["expected_hex"]), "policy")
    for bad in [
        encode_record("policy", (fields[0], *reversed(fields[1:]))),
        encode_record("policy", (fields[0], fields[1], fields[1])),
        encode_record("policy", (b"\0\0", fields[1])),
    ]:
        with pytest.raises(EncodingError):
            decode_policy(schema, bad)
    with pytest.raises(EncodingError):
        encode_policy(schema, Policy((3, 4), (Range(4, 1, 2), Equality(3, True))))


def test_malformed_disclosures_rejected_before_evaluation(schema):
    policy = make_policy(schema, (3, 4), (Equality(3, False),))
    # First clause is false, but a later invalid public field must still reject.
    for malformed in [b"\0\1\1", b"\0\1\1" + b"\0\7" + bytes(8)]:
        with pytest.raises(EncodingError):
            evaluate_policy(schema, policy, malformed)
    with pytest.raises(EncodingError):
        decode_clause(schema, encode_record("field", (b"x", b"\0", b"\0\0")))
