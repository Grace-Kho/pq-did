"""R-006/R-007: types, required fields, canonical padding and projection."""

from dataclasses import replace

import pytest

from pqdid.codec import EncodingError, decode_record, encode_record
from pqdid.schema import (
    AttributeField,
    Schema,
    decode_attribute,
    decode_attributes,
    decode_disclosed_attributes,
    decode_disclosure_mask,
    decode_schema,
    encode_attribute,
    encode_attributes,
    encode_disclosure_mask,
    encode_schema,
    project_attributes,
)


@pytest.mark.parametrize(
    "name,type_code,capacity",
    [
        ("", 0, 1),
        ("x" * 65, 0, 1),
        ("é", 0, 1),
        (1, 0, 1),
        ("x", 3, 1),
        ("x", True, 1),
        ("x", 0, -1),
        ("x", 0, True),
        ("x", 0, 65536),
        ("x", 1, 0),
        ("x", 2, 7),
    ],
)
def test_invalid_descriptors(name, type_code, capacity):
    with pytest.raises(EncodingError):
        AttributeField(name, type_code, capacity)


def test_minimum_and_maximum_schema_capacity():
    minimal = Schema((AttributeField("d", 0, 171), AttributeField("v", 0, 56)), 1, 2)
    assert decode_schema(encode_schema(minimal)) == minimal
    assert len(encode_attributes(minimal, (b"", b""))) == 1024
    fields = (AttributeField("d", 0, 936), AttributeField("v", 0, 56)) + tuple(
        AttributeField(f"f{i}", 0, 0) for i in range(14)
    )
    maximum = Schema(fields, 1, 2)
    assert maximum.used_bytes == 1024
    values = (b"x" * 936, b"y" * 56) + (b"",) * 14
    assert decode_attributes(maximum, encode_attributes(maximum, values)) == values
    with pytest.raises(EncodingError):
        Schema((replace(fields[0], capacity=937), *fields[1:]), 1, 2)
    with pytest.raises(EncodingError):
        Schema((*fields, AttributeField("extra", 0, 0)), 1, 2)
    with pytest.raises(EncodingError):
        Schema(fields[:1], 1, 2)


@pytest.mark.parametrize("did,version", [(0, 2), (1, 7), (1, 1), (True, 2), (1, False)])
def test_required_indices(schema, did, version):
    with pytest.raises(EncodingError):
        Schema(schema.fields, did, version)


def test_required_fields_and_duplicate_names(schema):
    for index, change in [
        (0, {"capacity": 170}),
        (1, {"capacity": 55}),
        (0, {"type_code": 1}),
        (1, {"type_code": 2}),
        (2, {"name": "did"}),
    ]:
        fields = list(schema.fields)
        fields[index] = replace(fields[index], **change)
        with pytest.raises(EncodingError):
            Schema(tuple(fields), 1, 2)
    with pytest.raises(EncodingError):
        Schema(list(schema.fields), 1, 2)


def test_schema_wire_counts_and_types(schema):
    fields = decode_record(encode_schema(schema), "schema")
    for changed in [(b"\5", *fields[1:]), (b"\0\6", *fields[1:]), (fields[0], b"\0", *fields[2:])]:
        with pytest.raises(EncodingError):
            decode_schema(encode_record("schema", changed))
    descriptor = decode_record(fields[3], "field")
    for changed in [
        (b"\xff", *descriptor[1:]),
        (descriptor[0], b"\3", descriptor[2]),
        (descriptor[0], b"\0\0", descriptor[2]),
        (*descriptor[:2], b"\xab"),
    ]:
        with pytest.raises(EncodingError):
            decode_schema(
                encode_record("schema", (*fields[:3], encode_record("field", changed), *fields[4:]))
            )


@pytest.mark.parametrize("value", [True, False, -1, 2**64, 1.0, "1", b"1"])
def test_uint_attribute_rejects_non_integer_or_out_of_range(value):
    with pytest.raises(EncodingError):
        encode_attribute(AttributeField("u", 2, 8), value)


@pytest.mark.parametrize("value", [0, 1, 2, b"\1", "true", None])
def test_boolean_requires_bool(value):
    with pytest.raises(EncodingError):
        encode_attribute(AttributeField("b", 1, 1), value)


def test_attribute_boundaries_and_extra_fixed_capacity():
    for value in (0, 2**64 - 1):
        field = AttributeField("u", 2, 10)
        encoded = encode_attribute(field, value)
        assert encoded[:2] == b"\0\10" and encoded[-2:] == bytes(2)
        assert decode_attribute(field, encoded) == value
    boolean = AttributeField("b", 1, 3)
    assert encode_attribute(boolean, True) == b"\0\1\1\0\0"
    assert decode_attribute(boolean, b"\0\1\1\0\0") is True
    raw = AttributeField("b", 0, 4)
    assert decode_attribute(raw, encode_attribute(raw, b"a\0b\0")) == b"a\0b\0"
    with pytest.raises(EncodingError):
        encode_attribute(raw, b"12345")
    with pytest.raises(EncodingError):
        decode_attribute(raw, b"\0\5abcd")


def test_attribute_vector_round_trip_and_bad_padding(schema, attributes):
    encoded = encode_attributes(schema, attributes)
    assert len(encoded) == 1024 and encoded[258:] == bytes(766)
    assert decode_attributes(schema, encoded) == attributes
    for bad in [encoded[:-1], encoded + b"\0", encoded[:-1] + b"\1"]:
        with pytest.raises(EncodingError):
            decode_attributes(schema, bad)
    with pytest.raises(EncodingError):
        encode_attributes(schema, attributes[:-1])
    short = encode_attributes(schema, (b"x", *attributes[1:]))
    bad = short[:3] + b"\1" + short[4:]
    with pytest.raises(EncodingError):
        decode_attributes(schema, bad)
    with pytest.raises(EncodingError):
        project_attributes(schema, bad, (3,))  # Hidden fields still need canonical encoding.


@pytest.mark.parametrize("field_count", range(2, 17))
def test_mask_boundaries_and_single_bits(field_count):
    for indices in [
        (),
        tuple(range(1, field_count + 1)),
        *((i,) for i in range(1, field_count + 1)),
    ]:
        assert (
            decode_disclosure_mask(encode_disclosure_mask(indices, field_count), field_count)
            == indices
        )
    if field_count < 16:
        with pytest.raises(EncodingError):
            decode_disclosure_mask((1 << field_count).to_bytes(2, "big"), field_count)


@pytest.mark.parametrize("indices", [(0,), (7,), (True,), (1, 1), (4, 3), (1.0,), {1, 2}])
def test_noncanonical_disclosure_indices(indices):
    with pytest.raises(EncodingError):
        encode_disclosure_mask(indices, 6)


@pytest.mark.parametrize("field_count", [0, 1, 17, True, 6.0])
def test_invalid_mask_domain(field_count):
    with pytest.raises(EncodingError):
        encode_disclosure_mask((), field_count)
    with pytest.raises(EncodingError):
        decode_disclosure_mask(bytes(2), field_count)


def test_disclosure_projection(schema, attributes, vectors):
    full = encode_attributes(schema, attributes)
    projected = project_attributes(schema, full, (3, 4, 6))
    assert projected == bytes.fromhex(vectors["E32"]["expected_hex"])
    assert decode_disclosed_attributes(schema, (3, 4, 6), projected) == {
        3: True,
        4: 3,
        6: 2000000000,
    }
    assert project_attributes(schema, full, ()) == b""
    assert decode_disclosed_attributes(schema, (), b"") == {}
    for bad in [projected[:-1], projected + b"\0", b"\0\1\2" + projected[3:]]:
        with pytest.raises(EncodingError):
            decode_disclosed_attributes(schema, (3, 4, 6), bad)
    with pytest.raises(EncodingError):
        decode_disclosed_attributes(schema, (), b"\0")
