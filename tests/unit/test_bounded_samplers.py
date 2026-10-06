"""Actual fixed-budget sampler logic under deterministic artificial byte streams."""

import hashlib
import json
from pathlib import Path

import pytest

from pqdid import bounded_mldsa as mldsa

from .sampler_streams import CountingReader, ball_stream, ntt_stream


@pytest.mark.parametrize("rejections,consumed", [(0, 768), (1, 771), (85, 1023), (86, 1026)])
def test_ntt_completion_before_and_at_real_cap(rejections, consumed):
    stream = CountingReader(ntt_stream(rejections) + b"forbidden suffix")
    assert mldsa._rej_ntt_poly(stream) == list(range(256))
    assert stream.consumed == consumed
    assert stream.requests == [3] * (256 + rejections)


@pytest.mark.parametrize("data", [ntt_stream(87), b"\xff" * 1032])
def test_ntt_exhaustion_does_not_read_candidate_343(data):
    stream = CountingReader(data)
    with pytest.raises(mldsa._SamplerExhausted) as caught:
        mldsa._rej_ntt_poly(stream)
    assert (caught.value.sampler, caught.value.consumed) == ("RejNTTPoly", 1026)
    assert stream.consumed == 1026
    assert stream.requests == [3] * 342


def test_ntt_candidate_endianness_mask_and_rejection_order():
    candidates = [8380416, 8380417, 8388607, 0x800002, 0x020100]
    data = b"".join(value.to_bytes(3, "little") for value in candidates) + bytes(3 * 253)
    stream = CountingReader(data)
    assert mldsa._rej_ntt_poly(stream) == [8380416, 2, 0x020100] + [0] * 253
    assert stream.consumed == 258 * 3


@pytest.mark.parametrize("rejections,consumed", [(0, 57), (1, 58), (198, 255), (199, 256)])
def test_ball_completion_before_and_at_real_cap(rejections, consumed):
    stream = CountingReader(ball_stream(rejections) + b"forbidden suffix")
    assert mldsa._sample_in_ball(stream) == [0] * 207 + [-1] + [1] * 48
    assert stream.consumed == consumed
    assert stream.requests == [8] + [1] * (49 + rejections)


@pytest.mark.parametrize("data", [ball_stream(200), bytes(8) + b"\xff" * 250])
def test_ball_exhaustion_does_not_read_byte_257(data):
    stream = CountingReader(data)
    with pytest.raises(mldsa._SamplerExhausted) as caught:
        mldsa._sample_in_ball(stream)
    assert (caught.value.sampler, caught.value.consumed) == ("SampleInBall", 256)
    assert stream.consumed == 256
    assert stream.requests == [8] + [1] * 248


def test_ball_sign_bits_and_collision_assignment_order():
    signs = b"\x01\x80" + bytes(6)  # negative bits 0 and 15 in little-endian order
    stream = CountingReader(signs + bytes(49))  # every accepted index is zero
    expected = [0] * 256
    expected[0] = 1  # the last sign replaces c[0]
    expected[208:256] = [-1 if i in (0, 15) else 1 for i in range(48)]
    actual = mldsa._sample_in_ball(stream)
    assert actual == expected
    assert sum(value != 0 for value in actual) == 49
    assert stream.consumed == 57


@pytest.mark.parametrize("bits,limit,rate", [(128, 1026, 168), (256, 256, 136)])
def test_buffered_shake_matches_one_continuous_prefix(bits, limit, rate):
    seed = bytes(range(34 if bits == 128 else 48))
    independent_prefix = getattr(hashlib, f"shake_{bits}")(seed).digest(limit)
    stream = mldsa._shake_reader(bits, seed)
    # Cross native rate boundaries; digest(n) must never restart returned bytes.
    sizes = [rate - 1, 1, 1, limit - rate - 1]
    assert b"".join(stream.read(size) for size in sizes) == independent_prefix
    with pytest.raises(RuntimeError):
        stream.read(1)


def test_budgets_match_unchanged_manifest():
    manifest = json.loads((Path(__file__).resolve().parents[2] / "configs/suite.json").read_text())
    caps = manifest["confirmed"]["bounded_operations"]
    assert mldsa._REJ_NTT_BYTES == caps["RejNTTPoly_max_bytes"] == 1026
    assert mldsa._BALL_BYTES == caps["SampleInBall_max_total_bytes"] == 256


def test_invalid_reader_is_runtime_failure_not_partial_polynomial():
    class BrokenReader:
        def read(self, length):
            return bytes(length - 1)

    for sample in (mldsa._rej_ntt_poly, mldsa._sample_in_ball):
        with pytest.raises(RuntimeError):
            sample(BrokenReader())
