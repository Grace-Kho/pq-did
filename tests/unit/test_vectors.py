"""Consume fixed JSON bytes without regenerating the expected results."""

import pytest

from pqdid.codec import (
    EncodingError,
    decode_length_prefixed,
    decode_record,
    decode_uint,
    encode_length_prefixed,
    encode_record,
    encode_uint,
    pack_sibling_path,
    unpack_sibling_path,
)
from pqdid.expiry import decode_timestamp, encode_timestamp, is_unexpired
from pqdid.policy import Equality, Range, decode_clause, decode_policy, encode_clause, encode_policy
from pqdid.schema import (
    AttributeField,
    decode_attribute,
    decode_disclosed_attributes,
    decode_disclosure_mask,
    decode_schema,
    encode_attribute,
    encode_attributes,
    encode_disclosure_mask,
    encode_schema,
    project_attributes,
)

from .conftest import VECTORS

# E15/E28 are Stage 3 proof-view vectors, not codecs being implemented here.
CURRENT_VECTORS = [v for key, v in VECTORS.items() if key not in ("E15", "E28")]


def _exercise(vector, schema, attributes):
    op, data = vector["operation"], vector["inputs"]
    encoded = bytes.fromhex(vector.get("expected_hex", data.get("encoded_hex", "")))
    if op == "I2OSP":
        result = encode_uint(data["value"], data["width"])
        assert decode_uint(result, data["width"]) == data["value"]
        return result
    if op == "LP":
        payload = bytes.fromhex(data["payload_hex"])
        assert decode_length_prefixed(encoded) == payload
        return encode_length_prefixed(payload)
    if op in ("Ej", "decode_Ej"):
        field = AttributeField("fixture", data["type"], data["capacity"])
        if op == "decode_Ej":
            return decode_attribute(field, encoded)
        value = data.get("value", bytes.fromhex(data.get("payload_hex", "")))
        if data["type"] == 1:
            value = data["payload_hex"] == "01"
        assert decode_attribute(field, encoded) == value
        return encode_attribute(field, value)
    if op == "eq":
        clause = Equality(data["index"], data["value"])
        assert decode_clause(schema, encoded) == clause
        return encode_clause(schema, clause)
    if op == "range":
        clause = Range(data["index"], data["lower"], data["upper"])
        assert decode_clause(schema, encoded) == clause
        return encode_clause(schema, clause)
    if op in ("decode_eq", "decode_range"):
        return decode_clause(schema, encoded)
    if op in ("policy", "decode_policy"):
        return encode_policy(schema, decode_policy(schema, encoded))
    if op == "mask":
        assert decode_disclosure_mask(encoded, data["field_count"]) == tuple(
            data["disclosed_indices"]
        )
        return encode_disclosure_mask(data["disclosed_indices"], data["field_count"])
    if op == "decode_mask":
        return decode_disclosure_mask(encoded, data["field_count"])
    if op == "did-chain":
        assert decode_record(encoded, "did-chain") == ()
        return encode_record("did-chain", ())
    if op == "schema":
        assert decode_schema(encoded) == schema
        return encode_schema(schema)
    if op == "context_bytes_only":
        # Build each field from fixture inputs; compare the entire fixed expected
        # encoding, rather than merely round-tripping that encoding.
        ref = encode_record(
            "iref",
            (
                data["issuer_identifier_ascii"].encode(),
                data["issuer_key_identifier_ascii"].encode(),
                encode_schema(schema),
            ),
        )
        state_ref = encode_record(
            "rref",
            (
                bytes.fromhex(data["namespace_hex"]),
                encode_uint(data["epoch"], 8),
                bytes.fromhex(data["root_hex"]),
            ),
        )
        policy = bytes.fromhex(VECTORS[data["policy"]]["expected_hex"])
        fields = (
            data["suite"].encode(),
            data["audience_ascii"].encode(),
            data["session_ascii"].encode(),
            bytes.fromhex(data["nonce_hex"]),
            policy,
            ref,
            state_ref,
            encode_timestamp(data["expiry_unsigned_value"]),
        )
        assert decode_record(encoded, "context") == fields
        return encode_record("context", fields)
    if op == "projection":
        assert decode_disclosed_attributes(schema, data["disclosed_indices"], encoded) == dict(
            zip(data["disclosed_indices"], data["disclosed_values"], strict=True)
        )
        return project_attributes(
            schema, encode_attributes(schema, attributes), data["disclosed_indices"]
        )
    if op == "sibling_path":
        siblings = tuple(bytes.fromhex(s) for s in data["siblings_hex"])
        result = pack_sibling_path(siblings)
        assert unpack_sibling_path(result) == siblings
        return result
    if op == "unpack_sibling_path":
        return unpack_sibling_path(encoded)
    if op == "timestamp":
        result = encode_timestamp(data["seconds"])
        assert decode_timestamp(result) == data["seconds"]
        return result
    if op == "decode_timestamp":
        return decode_timestamp(encoded)
    if op == "expiry_predicate":
        return is_unexpired(data["texp"], now=data["now"])
    if op == "update_framing":
        fields = tuple(bytes.fromhex(s) for s in data["field_payloads_hex"])
        assert decode_record(encoded, data["tag"]) == fields
        return encode_record(data["tag"], fields)
    raise AssertionError(f"unhandled fixed vector {vector['id']}")


@pytest.mark.parametrize("vector", CURRENT_VECTORS, ids=lambda v: v["id"])
def test_fixed_specification_vector(vector, schema, attributes):
    if vector["expected"] == "reject":
        with pytest.raises(EncodingError):
            _exercise(vector, schema, attributes)
    elif "expected_result" in vector:
        assert _exercise(vector, schema, attributes) is vector["expected_result"]
    else:
        result = _exercise(vector, schema, attributes)
        assert result == bytes.fromhex(vector["expected_hex"])
        assert len(result) == vector["expected_bytes"]
