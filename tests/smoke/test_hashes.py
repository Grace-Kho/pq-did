"""Fixed NIST FIPS 202 examples; see docs/environment.md for source links.

The 1600-bit input is 200 repetitions of byte A3. SHAKE expected values are
the first 128 bytes of NIST's 512-byte outputs, never computed at test time.
"""

import hashlib

import pytest


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            b"",
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
            "c3713831264adb47fb6bd1e058d5f004",
        ),
        (
            b"\xa3" * 200,
            "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd"
            "76197a31fd55ee989f2d7050dd473e8f",
        ),
    ],
    ids=["empty", "1600-bit-message"],
)
def test_sha3_384_known_answer(message, expected):
    assert hashlib.sha3_384(message).digest() == bytes.fromhex(expected)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            b"",
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            "141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853"
            "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86",
        ),
        (
            b"\xa3" * 200,
            "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"
            "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b"
            "1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628"
            "001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317",
        ),
    ],
    ids=["empty-128-byte-output", "1600-bit-message-128-byte-output"],
)
def test_shake256_128_byte_known_answer(message, expected):
    digest = hashlib.shake_256(message).digest(128)
    assert len(digest) == 128
    assert digest == bytes.fromhex(expected)
