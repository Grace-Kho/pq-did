"""Frozen independent ordinary-native signatures, FIPS boundaries and exhaustion."""

import hashlib
import inspect
from pathlib import Path

import pytest

from pqdid import bounded_mldsa as mldsa

from .mldsa_cases import load_cases, vector_arguments
from .sampler_streams import CountingReader, ball_stream, ntt_stream

CASES = load_cases()
VECTORS = CASES["vectors"]


def verify(item, **changes):
    key, message, signature, context = vector_arguments(item)
    arguments = {"public_key": key, "message": message, "signature": signature, "context": context}
    arguments.update(changes)
    return mldsa._verify_diagnostic(**arguments)


def test_fixture_provenance_and_no_verifier_filtering():
    provenance = CASES["provenance"]
    assert not provenance["bounded_signing"]
    assert not provenance["bounded_verifier_used_to_generate_or_filter"]
    assert not provenance["secret_signing_keys_saved"]
    generator = Path(__file__).resolve().parents[2] / provenance["generator"]
    assert hashlib.sha256(generator.read_bytes()).hexdigest() == provenance["generator_sha256"]
    assert "pqdid.bounded_mldsa" not in "\n".join(
        line for line in generator.read_text().splitlines() if line.startswith(("from ", "import "))
    )


@pytest.mark.parametrize("item", VECTORS, ids=lambda item: item["name"])
def test_independent_valid_signature(item):
    assert item["valid"] is True
    assert verify(item).status is mldsa._Status.VALID
    key, message, signature, context = vector_arguments(item)
    assert mldsa.bounded_verify_mldsa65(key, message, signature, context=context) is True


@pytest.mark.parametrize(
    "component,offset",
    [
        ("public_key", 0),
        ("public_key", 32),
        ("signature", 0),
        ("signature", 48),
        ("signature", 1000),
        ("message", 0),
        ("context", 0),
    ],
)
def test_modified_signed_inputs(component, offset):
    item = VECTORS[1]
    value = bytes.fromhex(item[component])
    changed = value[:offset] + bytes([value[offset] ^ 1]) + value[offset + 1 :]
    assert verify(item, **{component: changed}).status is mldsa._Status.INVALID


@pytest.mark.parametrize("context", [b"", b"PQ-DID/cred/v1", b"PQ-DID/state/v1", b"x" * 256])
def test_wrong_credential_context(context):
    assert verify(VECTORS[1], context=context).status is mldsa._Status.INVALID


def test_no_prehash_or_duplicate_context_framing():
    key, message, signature, context = vector_arguments(VECTORS[1])
    for changed, ctx in [
        (context + message, b""),
        (bytes([0, len(context)]) + context + message, context),
        (hashlib.shake_256(message).digest(64), context),
    ]:
        assert not mldsa.bounded_verify_mldsa65(key, changed, signature, context=ctx)


@pytest.mark.parametrize("component", ["public_key", "message", "signature", "context"])
@pytest.mark.parametrize("value", [None, "text", bytearray(), memoryview(b""), 1])
def test_invalid_input_types(component, value):
    assert verify(VECTORS[0], **{component: value}).status is mldsa._Status.INVALID


@pytest.mark.parametrize(
    "component,size",
    [
        ("public_key", 0),
        ("public_key", 1951),
        ("public_key", 1953),
        ("public_key", 1312),
        ("signature", 0),
        ("signature", 3308),
        ("signature", 3310),
    ],
)
def test_invalid_input_lengths(component, size):
    assert verify(VECTORS[0], **{component: bytes(size)}).status is mldsa._Status.INVALID


def test_public_api_has_no_injection_or_cap_override():
    assert list(inspect.signature(mldsa.bounded_verify_mldsa65).parameters) == [
        "public_key",
        "message",
        "signature",
        "context",
    ]


@pytest.mark.parametrize("position", range(30))
def test_each_matrix_invocation_exhausts_through_top_level(monkeypatch, position):
    real_reader = mldsa._shake_reader
    calls = []
    injected = []

    def reader(bits, seed):
        calls.append((bits, seed))
        if bits == 128 and seed[-1] * 5 + seed[-2] == position:
            stream = CountingReader(ntt_stream(87))
            injected.append(stream)
            return stream
        return real_reader(bits, seed)

    monkeypatch.setattr(mldsa, "_shake_reader", reader)
    result = verify(VECTORS[0])
    assert (result.status, result.sampler, result.consumed) == (
        mldsa._Status.EXHAUSTED,
        "RejNTTPoly",
        1026,
    )
    assert len(calls) == position + 1
    assert all(bits == 128 for bits, _ in calls)
    key, message, signature, context = vector_arguments(VECTORS[0])
    assert mldsa.bounded_verify_mldsa65(key, message, signature, context=context) is False
    assert all(stream.consumed == 1026 and len(stream.requests) == 342 for stream in injected)


def test_ball_exhaustion_through_top_level(monkeypatch):
    real_reader = mldsa._shake_reader
    calls = []
    stream = CountingReader(ball_stream(200))

    def reader(bits, seed):
        calls.append((bits, seed))
        return stream if bits == 256 else real_reader(bits, seed)

    monkeypatch.setattr(mldsa, "_shake_reader", reader)
    result = verify(VECTORS[0])
    assert (result.status, result.sampler, result.consumed) == (
        mldsa._Status.EXHAUSTED,
        "SampleInBall",
        256,
    )
    assert [bits for bits, _ in calls] == [128] * 30 + [256]
    assert stream.consumed == 256
    assert stream.requests == [8] + [1] * 248
    monkeypatch.setattr(
        mldsa,
        "_shake_reader",
        lambda bits, seed: (
            CountingReader(ball_stream(200)) if bits == 256 else real_reader(bits, seed)
        ),
    )
    key, message, signature, context = vector_arguments(VECTORS[0])
    assert mldsa.bounded_verify_mldsa65(key, message, signature, context=context) is False


def test_actual_matrix_seed_order_and_distinct_budgets(monkeypatch):
    calls = []

    def reader(bits, seed):
        stream = CountingReader(ntt_stream(86))
        calls.append((bits, seed, stream))
        return stream

    monkeypatch.setattr(mldsa, "_shake_reader", reader)
    matrix = mldsa._expand_a(bytes(range(32)))
    assert matrix == [[list(range(256)) for _ in range(5)] for _ in range(6)]
    assert [(bits, seed) for bits, seed, _ in calls] == [
        (128, bytes(range(32)) + bytes([column, row])) for row in range(6) for column in range(5)
    ]
    assert len({id(stream) for _, _, stream in calls}) == 30
    assert all(stream.consumed == 1026 for _, _, stream in calls)


def test_runtime_failure_never_falls_back(monkeypatch):
    def unavailable(*args):
        raise RuntimeError("test backend failure")

    monkeypatch.setattr(mldsa, "_shake_reader", unavailable)
    key, message, signature, context = vector_arguments(VECTORS[0])
    with pytest.raises(RuntimeError, match="test backend failure"):
        mldsa.bounded_verify_mldsa65(key, message, signature, context=context)


def test_key_and_signature_decode_extremes():
    rho, t1 = mldsa._decode_public_key(bytes(range(32)) + b"\xff" * 1920)
    assert rho == bytes(range(32))
    assert t1 == [[1023] * 256 for _ in range(6)]
    for packed, expected in [(bytes(3200), 524288), (b"\xff" * 3200, -524287)]:
        challenge, z, hints = mldsa._decode_signature(bytes(range(48)) + packed + bytes(61))
        assert challenge == bytes(range(48))
        assert z == [[expected] * 256 for _ in range(5)]
        assert hints == [[0] * 256 for _ in range(6)]
        assert not mldsa._norm_ok(z)


@pytest.mark.parametrize(
    "coefficient,expected",
    [
        (0, True),
        (524091, True),
        (-524091, True),
        (524092, False),
        (-524092, False),
        (524288, False),
        (-524287, False),
    ],
)
def test_strict_norm_boundary(coefficient, expected):
    z = [[0] * 256 for _ in range(5)]
    z[-1][-1] = coefficient
    assert mldsa._norm_ok(z) is expected


def hint_payload(rows):
    positions = b"".join(bytes(row) for row in rows)
    assert len(positions) <= 55
    ends = []
    count = 0
    for row in rows:
        count += len(row)
        ends.append(count)
    return positions + bytes(55 - len(positions)) + bytes(ends)


@pytest.mark.parametrize("row", range(6))
@pytest.mark.parametrize("damage", ["overflow", "duplicate", "reversed", "decreasing"])
def test_malformed_hint_encoding_each_row(row, damage):
    rows = [[] for _ in range(6)]
    rows[row] = [1, 2]
    payload = bytearray(hint_payload(rows))
    if damage == "overflow":
        payload[55 + row] = 56
    elif damage == "duplicate":
        payload[1] = 1
    elif damage == "reversed":
        payload[:2] = b"\x02\x01"
    elif row:
        payload[55 + row - 1] = 2
        payload[55 + row] = 1
    else:
        payload[55] = 2
        payload[56] = 1
    with pytest.raises(mldsa._InvalidSignature):
        mldsa._decode_hints(bytes(payload))
    key, message, signature, context = vector_arguments(VECTORS[0])
    assert not mldsa.bounded_verify_mldsa65(
        key, message, signature[:3248] + payload, context=context
    )


def test_hint_padding_weight_and_cross_row_index_reuse():
    payload = bytearray(61)
    payload[54] = 1
    with pytest.raises(mldsa._InvalidSignature):
        mldsa._decode_hints(bytes(payload))
    rows = [list(range(50)), [255], [255], [255], [255], [255]]
    hints = mldsa._decode_hints(hint_payload(rows))
    assert sum(map(sum, hints)) == 55
    assert all(hints[row][255] == 1 for row in range(1, 6))


@pytest.mark.parametrize(
    "value,high,low",
    [
        (0, 0, 0),
        (261888, 0, 261888),
        (261889, 1, -261887),
        (523776, 1, 0),
        (8380416, 0, -1),
        (8380417, 0, 0),
        (-1, 0, -1),
    ],
)
def test_decompose_and_use_hint_boundaries(value, high, low):
    assert mldsa._decompose(value) == (high, low)
    assert mldsa._use_hint(0, value) == high
    assert mldsa._use_hint(1, value) == (high + (1 if low > 0 else -1)) % 16


def test_w1_packing_is_low_nibble_first():
    vector = [list(range(16)) * 16 for _ in range(6)]
    assert mldsa._encode_w1(vector) == bytes.fromhex("1032547698badcfe") * 96


@pytest.mark.parametrize(
    "polynomial",
    [[0] * 256, [1] + [0] * 255, [0, 1] + [0] * 254, [i * i - 10000 for i in range(256)]],
)
def test_ntt_against_direct_polynomial_evaluation(polynomial):
    # Independent O(n^2) evaluation at the 256 roots, not another butterfly loop.
    expected = []
    for index in range(256):
        reverse = sum(((index >> bit) & 1) << (7 - bit) for bit in range(8))
        point = pow(1753, 2 * reverse + 1, 8380417)
        value = 0
        for coefficient in reversed(polynomial):
            value = (value * point + coefficient) % 8380417
        expected.append(value)
    assert mldsa._ntt(polynomial) == expected
    assert mldsa._inverse_ntt(expected) == [value % 8380417 for value in polynomial]


def test_ntt_product_against_independent_negacyclic_convolution():
    left = [(i * 17) % 31 - 15 for i in range(256)]
    right = [(i * 13) % 23 - 11 for i in range(256)]
    expected = [0] * 256
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            expected[(i + j) % 256] += a * b * (1 if i + j < 256 else -1)
    product = [a * b % 8380417 for a, b in zip(mldsa._ntt(left), mldsa._ntt(right), strict=True)]
    assert mldsa._inverse_ntt(product) == [value % 8380417 for value in expected]
