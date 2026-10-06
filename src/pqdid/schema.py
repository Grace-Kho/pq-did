"""Immutable schemas, canonical attributes and disclosure bytes (VII-A.1).

Type-0 attributes are opaque bytes, including designated DID/version fields.
Method-specific DID resolution/control and credential authenticity are later layers.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from pqdid.codec import (
    EncodingError,
    decode_record,
    decode_uint,
    encode_record,
    encode_uint,
    require_bytes,
    require_uint,
)

BYTES = 0
BOOLEAN = 1
UINT64 = 2
ATTRIBUTE_VECTOR_BYTES = 1024
type AttributeValue = bytes | bool | int


@dataclass(frozen=True)
class AttributeField:
    name: str
    type_code: int
    capacity: int

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name.isascii() or not 1 <= len(self.name) <= 64:
            raise EncodingError("field name must be 1 to 64 ASCII bytes")
        require_uint(self.type_code, 8)
        if self.type_code not in (BYTES, BOOLEAN, UINT64):
            raise EncodingError("unsupported attribute type")
        require_uint(self.capacity, 16)
        minimum = {BYTES: 0, BOOLEAN: 1, UINT64: 8}[self.type_code]
        if self.capacity < minimum:
            raise EncodingError("insufficient fixed-type capacity")


@dataclass(frozen=True)
class Schema:
    fields: tuple[AttributeField, ...]
    did_index: int
    version_index: int

    def __post_init__(self) -> None:
        if type(self.fields) is not tuple or not 2 <= len(self.fields) <= 16:
            raise EncodingError("schema requires an immutable tuple of 2 to 16 fields")
        if any(type(field) is not AttributeField for field in self.fields):
            raise EncodingError("invalid field descriptor")
        if len({field.name for field in self.fields}) != len(self.fields):
            raise EncodingError("duplicate schema field name")
        if self.used_bytes > ATTRIBUTE_VECTOR_BYTES:
            raise EncodingError("schema capacities exceed 1024 bytes")
        did = self.field(self.did_index)
        version = self.field(self.version_index)
        if self.did_index == self.version_index:
            raise EncodingError("DID and version indices must differ")
        if did.type_code != BYTES or did.capacity < 171:
            raise EncodingError("DID field must be bytes with capacity at least 171")
        if version.type_code != BYTES or version.capacity < 56:
            raise EncodingError("version field must be bytes with capacity at least 56")

    @property
    def used_bytes(self) -> int:
        return sum(2 + field.capacity for field in self.fields)

    def field(self, index: int) -> AttributeField:
        if type(index) is not int or not 1 <= index <= len(self.fields):
            raise EncodingError("field index outside schema")
        return self.fields[index - 1]


def _schema(schema: Schema) -> Schema:
    if type(schema) is not Schema:
        raise EncodingError("expected a validated schema")
    return schema


def encode_schema(schema: Schema) -> bytes:
    _schema(schema)
    descriptors = tuple(
        encode_record(
            "field",
            (
                field.name.encode("ascii"),
                encode_uint(field.type_code, 1),
                encode_uint(field.capacity, 2),
            ),
        )
        for field in schema.fields
    )
    return encode_record(
        "schema",
        (
            encode_uint(len(schema.fields), 1),
            encode_uint(schema.did_index, 1),
            encode_uint(schema.version_index, 1),
            *descriptors,
        ),
    )


def decode_schema(encoded: bytes) -> Schema:
    count, did, version, *descriptors = decode_record(encoded, "schema")
    if decode_uint(count, 1) != len(descriptors):
        raise EncodingError("schema descriptor count mismatch")
    fields = []
    for descriptor in descriptors:
        name, type_code, capacity = decode_record(descriptor, "field")
        try:
            text = name.decode("ascii")
        except UnicodeDecodeError as error:
            raise EncodingError("non-ASCII field name") from error
        fields.append(AttributeField(text, decode_uint(type_code, 1), decode_uint(capacity, 2)))
    return Schema(tuple(fields), decode_uint(did, 1), decode_uint(version, 1))


def encode_attribute(field: AttributeField, value: AttributeValue) -> bytes:
    if type(field) is not AttributeField:
        raise EncodingError("invalid field descriptor")
    if field.type_code == BYTES:
        payload = require_bytes(value)
    elif field.type_code == BOOLEAN:
        if type(value) is not bool:
            raise EncodingError("Boolean attribute requires bool")
        payload = b"\x01" if value else b"\x00"
    else:
        payload = encode_uint(value, 8)
    if len(payload) > field.capacity:
        raise EncodingError("attribute exceeds field capacity")
    return encode_uint(len(payload), 2) + payload + bytes(field.capacity - len(payload))


def decode_attribute(field: AttributeField, encoded: bytes) -> AttributeValue:
    if type(field) is not AttributeField:
        raise EncodingError("invalid field descriptor")
    if len(require_bytes(encoded)) != 2 + field.capacity:
        raise EncodingError("incorrect padded field length")
    length = decode_uint(encoded[:2], 2)
    if length > field.capacity:
        raise EncodingError("attribute length exceeds capacity")
    payload = encoded[2 : 2 + length]
    if any(encoded[2 + length :]):
        raise EncodingError("non-zero attribute padding")
    if field.type_code == BYTES:
        return payload
    if field.type_code == BOOLEAN:
        if payload not in (b"\x00", b"\x01"):
            raise EncodingError("Boolean must be exactly 00 or 01")
        return payload == b"\x01"
    return decode_uint(payload, 8)


def encode_attributes(schema: Schema, values: Sequence[AttributeValue]) -> bytes:
    _schema(schema)
    if not isinstance(values, (tuple, list)) or len(values) != len(schema.fields):
        raise EncodingError("attribute count does not match schema")
    fields = b"".join(
        encode_attribute(field, value) for field, value in zip(schema.fields, values, strict=True)
    )
    return fields + bytes(ATTRIBUTE_VECTOR_BYTES - len(fields))


def decode_attributes(schema: Schema, encoded: bytes) -> tuple[AttributeValue, ...]:
    _schema(schema)
    if len(require_bytes(encoded)) != ATTRIBUTE_VECTOR_BYTES:
        raise EncodingError("attribute vector must be exactly 1024 bytes")
    values = []
    offset = 0
    for field in schema.fields:
        end = offset + 2 + field.capacity
        values.append(decode_attribute(field, encoded[offset:end]))
        offset = end
    if any(encoded[offset:]):
        raise EncodingError("non-zero attribute vector tail padding")
    return tuple(values)


def _field_count(field_count: int) -> None:
    if type(field_count) is not int or not 2 <= field_count <= 16:
        raise EncodingError("field count must be between 2 and 16")


def encode_disclosure_mask(indices: Sequence[int], field_count: int) -> bytes:
    _field_count(field_count)
    if not isinstance(indices, (tuple, list)):
        raise EncodingError("disclosure indices must be an ordered tuple or list")
    previous = mask = 0
    for index in indices:
        if type(index) is not int or not previous < index <= field_count:
            raise EncodingError("disclosure indices must be distinct, increasing and in range")
        mask |= 1 << (index - 1)
        previous = index
    return encode_uint(mask, 2)


def decode_disclosure_mask(encoded: bytes, field_count: int) -> tuple[int, ...]:
    _field_count(field_count)
    mask = decode_uint(encoded, 2)
    if mask >> field_count:
        raise EncodingError("unused disclosure mask bits must be zero")
    return tuple(index for index in range(1, field_count + 1) if mask & (1 << (index - 1)))


def project_attributes(schema: Schema, encoded: bytes, indices: Sequence[int]) -> bytes:
    """Validate the complete canonical vector, then select complete padded fields."""
    decode_attributes(schema, encoded)
    encode_disclosure_mask(indices, len(schema.fields))
    selected = set(indices)
    result = []
    offset = 0
    for index, field in enumerate(schema.fields, 1):
        end = offset + 2 + field.capacity
        if index in selected:
            result.append(encoded[offset:end])
        offset = end
    return b"".join(result)


def decode_disclosed_attributes(
    schema: Schema, indices: Sequence[int], encoded: bytes
) -> dict[int, AttributeValue]:
    """Parse only public selected fields; never require the hidden attribute vector."""
    _schema(schema)
    encode_disclosure_mask(indices, len(schema.fields))
    length = sum(2 + schema.field(index).capacity for index in indices)
    if len(require_bytes(encoded)) != length:
        raise EncodingError("incorrect disclosure length")
    values = {}
    offset = 0
    for index in indices:
        field = schema.field(index)
        end = offset + 2 + field.capacity
        values[index] = decode_attribute(field, encoded[offset:end])
        offset = end
    return values
