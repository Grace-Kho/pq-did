"""SPEC-002 and R-008: deterministic timestamps, not verifier services."""

import pytest

from pqdid.codec import EncodingError
from pqdid.expiry import decode_timestamp, encode_timestamp, is_unexpired


@pytest.mark.parametrize("now,expected", [(99, True), (100, False), (101, False)])
def test_before_at_after_expiry(now, expected):
    assert is_unexpired(100, now=now) is expected


def test_timestamp_range_boundaries():
    maximum = 2**64 - 1
    for value in (0, 1, maximum):
        assert decode_timestamp(encode_timestamp(value)) == value
    assert not is_unexpired(0, now=0)
    assert is_unexpired(1, now=0)
    assert is_unexpired(maximum, now=maximum - 1)
    assert not is_unexpired(maximum, now=maximum)


@pytest.mark.parametrize("value", [-1, 2**64, True, False, 100.0, "100", None])
def test_invalid_timestamp_values(value):
    with pytest.raises(EncodingError):
        encode_timestamp(value)
    with pytest.raises(EncodingError):
        is_unexpired(value, now=0)
    with pytest.raises(EncodingError):
        is_unexpired(100, now=value)


@pytest.mark.parametrize("encoded", [b"", bytes(7), bytes(9), "00000000", bytearray(8)])
def test_invalid_timestamp_representations(encoded):
    with pytest.raises(EncodingError):
        decode_timestamp(encoded)
