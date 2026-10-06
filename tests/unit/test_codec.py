"""R-005 and SPEC-001: framing, hostile lengths and raw sibling paths."""

import tracemalloc

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


@pytest.mark.parametrize("width", [1, 2, 4, 8])
def test_integer_boundaries(width):
    maximum = (1 << (width * 8)) - 1
    assert encode_uint(0, width) == bytes(width)
    assert encode_uint(maximum, width) == b"\xff" * width
    assert decode_uint(b"\xff" * width, width) == maximum
    with pytest.raises(EncodingError):
        encode_uint(maximum + 1, width)


@pytest.mark.parametrize("value", [True, False, -1, 1.0, "1", b"1", None])
def test_invalid_integer_types(value):
    with pytest.raises(EncodingError):
        encode_uint(value, 8)


@pytest.mark.parametrize("width", [0, -1, True, 1.5, 2**32])
def test_invalid_integer_width(width):
    with pytest.raises(EncodingError):
        encode_uint(0, width)
    with pytest.raises(EncodingError):
        decode_uint(b"", width)


@pytest.mark.parametrize("encoded", [b"", bytes(7), bytes(9), bytearray(8), "00000000"])
def test_integer_representation(encoded):
    with pytest.raises(EncodingError):
        decode_uint(encoded, 8)


def test_length_prefix_rejects_declared_allocation():
    # Four hostile bytes must not allocate their claimed 4 GiB payload.
    tracemalloc.start()
    try:
        with pytest.raises(EncodingError):
            decode_length_prefixed(b"\xff" * 4)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 100_000


@pytest.mark.parametrize("data", [b"", b"\0", bytes(3), b"\0\0\0\2x", bytes(5)])
def test_bad_length_prefix(data):
    with pytest.raises(EncodingError):
        decode_length_prefixed(data)


@pytest.mark.parametrize("value", ["text", bytearray(b"x"), memoryview(b"x"), 1])
def test_no_implicit_byte_conversions(value):
    with pytest.raises(EncodingError):
        encode_length_prefixed(value)


def test_all_record_truncations_and_trailing_bytes(vectors):
    encoded = bytes.fromhex(vectors["E30"]["expected_hex"])
    for end in range(len(encoded)):
        with pytest.raises(EncodingError):
            decode_record(encoded[:end], "policy")
    with pytest.raises(EncodingError):
        decode_record(encoded + b"\0", "policy")


@pytest.mark.parametrize("tag", ["", "EQ", "unknown", "é", b"eq", None])
def test_reject_invalid_tag(tag):
    with pytest.raises(EncodingError):
        encode_record(tag, (b"", b""))
    with pytest.raises(EncodingError):
        decode_record(b"", tag)


def test_count_tag_and_nested_byte_boundaries(vectors):
    encoded = bytes.fromhex(vectors["E09"]["expected_hex"])
    with pytest.raises(EncodingError):
        decode_record(encoded, "range")
    with pytest.raises(EncodingError):
        encode_record("eq", (b"",))
    with pytest.raises(EncodingError):
        decode_record(bytes.fromhex(vectors["E30"]["expected_hex"]), "policy", expected_count=2)
    with pytest.raises(EncodingError):
        decode_record(encode_length_prefixed(b"did-chain") + encode_uint(65536, 4), "did-chain")
    with pytest.raises(EncodingError):
        decode_record(encode_length_prefixed(b"did-chain") + b"\xff" * 4, "did-chain")
    wrapped = encode_record("binding", (b"x", encoded))
    assert decode_record(wrapped, "binding") == (b"x", encoded)
    assert decode_record(encoded, "eq") == (b"\3", b"\0\1\1")


@pytest.mark.parametrize("count", [0, 19, 21])
def test_incorrect_sibling_count(count):
    with pytest.raises(EncodingError):
        pack_sibling_path((bytes(48),) * count)


@pytest.mark.parametrize("size", [0, 47, 49])
def test_incorrect_sibling_length(size):
    with pytest.raises(EncodingError):
        pack_sibling_path((bytes(48),) * 19 + (bytes(size),))


def test_path_order_and_distinct_update_encodings(vectors):
    path = bytes.fromhex(vectors["E33"]["expected_hex"])
    siblings = unpack_sibling_path(path)
    assert siblings[0] == bytes(48) and siblings[-1] == b"\x13" * 48
    assert pack_sibling_path(tuple(reversed(siblings))) != path
    signed = bytes.fromhex(vectors["E44"]["expected_hex"])
    transport = bytes.fromhex(vectors["E45"]["expected_hex"])
    message_fields = decode_record(signed, "update", expected_count=6)
    transport_fields = decode_record(transport, "rupdate", expected_count=5)
    assert message_fields[5] == transport_fields[3] == path
    assert message_fields[4] == transport_fields[2] == b"\0\0\0\7"
    assert message_fields[0] == b"PQ-DID-MITH-1"
    assert len(decode_record(message_fields[2], "rref")) == 3
    assert len(decode_record(transport_fields[0], "rstate")) == 4
    assert len(transport_fields[4]) == 3309
    with pytest.raises(EncodingError):
        decode_record(transport, "update")
    with pytest.raises(EncodingError):
        unpack_sibling_path(encode_length_prefixed(path))
