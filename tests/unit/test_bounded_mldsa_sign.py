"""Focused reference-core checks. All injection is pytest monkeypatch, never API."""

import inspect
import json
from pathlib import Path

import pytest

from pqdid import bounded_mldsa as v
from pqdid import bounded_mldsa_sign as s

from .sampler_streams import CountingReader, ball_stream, ntt_stream

SEED = bytes(range(32))  # Public synthetic inputs, never operational keys/randomness.
RND = bytes(range(32, 64))
MESSAGE = b"synthetic unit message"
CONTEXT = b"PQ-DID/credential/v1"


@pytest.fixture(scope="module")
def pair():
    return s.reference_keygen_mldsa65(SEED)


@pytest.fixture(scope="module")
def signature(pair):
    return s.reference_sign_mldsa65(pair.secret_key, MESSAGE, context=CONTEXT, randomness=RND)


def failure(reason, operation):
    with pytest.raises(s.BoundedMLDSAError) as caught:
        operation()
    assert caught.value.reason is reason
    assert str(caught.value) == reason.name
    assert set(vars(caught.value)) == {"reason"}


@pytest.mark.parametrize(
    "rejected,final,consumed",
    [
        (0, b"\x44" * 128, 128),
        (383, b"\x44" * 128, 511),
        (384, b"\x44" * 128, 512),
        (383, b"\x44" * 127 + b"\xf4\xf4", 512),
        (383, b"\x44" * 127 + b"\xf4\x4f", 512),
    ],
)
def test_short_sampler_boundary_low_and_high_nibble(rejected, final, consumed):
    stream = CountingReader(b"\xff" * rejected + final + b"unread suffix")
    assert s._rej_bounded_poly(stream) == [0] * 256
    assert stream.consumed == consumed and stream.requests == [1] * consumed


@pytest.mark.parametrize("data", [b"\xff" * 385 + b"\x44" * 128, b"\xff" * 513])
def test_short_sampler_exhaustion_never_reads_513(data):
    stream = CountingReader(data)
    with pytest.raises(v._SamplerExhausted) as caught:
        s._rej_bounded_poly(stream)
    assert (caught.value.sampler, caught.value.consumed) == ("RejBoundedPoly", 512)
    assert stream.consumed == 512 and stream.requests == [1] * 512


def test_short_sampler_order_and_invalid_reader():
    stream = CountingReader(b"\x80\x9f\x27" + b"\x44" * 126)
    assert s._rej_bounded_poly(stream) == [4, -4, -3, 2] + [0] * 252

    class Broken:
        def read(self, _length):
            return b""

    with pytest.raises(RuntimeError):
        s._rej_bounded_poly(Broken())


def test_frozen_caps_and_exact_role_contexts():
    suite = json.loads((Path(__file__).parents[2] / "configs/suite.json").read_text())["confirmed"]
    caps = suite["bounded_operations"]
    assert (v._REJ_NTT_BYTES, s._SHORT_BYTES, v._BALL_BYTES, s._ATTEMPTS) == (1026, 512, 256, 1024)
    assert caps["RejBoundedPoly_max_bytes"] == s._SHORT_BYTES
    assert 1024 in caps.values()
    actual = {
        key.replace("_", "-"): value.encode()
        for key, value in suite["signature"]["external_contexts_ascii"].items()
    }
    assert s._CONTEXTS == actual


def test_expand_s_all_eleven_independent_nonces(monkeypatch):
    calls, readers = [], []

    def reader(seed):
        calls.append(seed)
        stream = CountingReader(b"\xff" * 384 + b"\x44" * 128)
        readers.append(stream)
        return stream

    monkeypatch.setattr(s, "_short_reader", reader)
    with s._Scratch() as scratch:
        s1, s2 = s._expand_s(bytes(64), scratch)
        assert (len(s1), len(s2)) == (5, 6)
        assert all(row == [0] * 256 for row in [*s1, *s2])
    assert calls == [bytes(64) + i.to_bytes(2, "little") for i in range(11)]
    assert [r.consumed for r in readers] == [512] * 11


@pytest.mark.parametrize("position", [0, 5, 10])
def test_keygen_short_exhaustion_aborts_without_partial_key(monkeypatch, position):
    calls = []

    def reader(seed):
        calls.append(seed)
        return CountingReader(b"\xff" * 513 if len(calls) - 1 == position else b"\x44" * 128)

    monkeypatch.setattr(s, "_short_reader", reader)
    failure(s.Failure.SAMPLER_EXHAUSTED, lambda: s.reference_keygen_mldsa65(SEED))
    assert len(calls) == position + 1


@pytest.mark.parametrize("operation", ["keygen", "import", "sign"])
def test_matrix_exhaustion_propagates_without_retry(monkeypatch, pair, operation):
    calls = []
    original = v._shake_reader

    def reader(bits, seed):
        calls.append((bits, seed))
        return CountingReader(ntt_stream(87)) if bits == 128 else original(bits, seed)

    monkeypatch.setattr(v, "_shake_reader", reader)
    operations = {
        "keygen": lambda: s.reference_keygen_mldsa65(SEED),
        "import": lambda: s.reference_public_key_mldsa65(pair.secret_key),
        "sign": lambda: s.reference_sign_mldsa65(
            pair.secret_key, MESSAGE, context=CONTEXT, randomness=RND
        ),
    }
    failure(s.Failure.SAMPLER_EXHAUSTED, operations[operation])
    assert len(calls) == 1


def test_keygen_all_matrix_entries_can_finish_exactly_at_cap(monkeypatch):
    readers = []

    def reader(_bits, _seed):
        stream = CountingReader(ntt_stream(86))
        readers.append(stream)
        return stream

    monkeypatch.setattr(v, "_shake_reader", reader)
    result = s.reference_keygen_mldsa65(SEED)
    assert len(result.secret_key) == 4032
    assert len(readers) == 30 and all(stream.consumed == 1026 for stream in readers)


def test_signer_ball_exhaustion_is_not_candidate_rejection(monkeypatch, pair):
    calls = []
    original = v._shake_reader

    def reader(bits, seed):
        if bits == 256:
            calls.append(seed)
            return CountingReader(ball_stream(200))
        return original(bits, seed)

    monkeypatch.setattr(v, "_shake_reader", reader)
    failure(
        s.Failure.SAMPLER_EXHAUSTED,
        lambda: s.reference_sign_mldsa65(pair.secret_key, MESSAGE, context=CONTEXT, randomness=RND),
    )
    assert len(calls) == 1


@pytest.mark.parametrize("accept_last", [True, False])
def test_attempt_1024_boundary_and_nonce_progression(monkeypatch, pair, signature, accept_last):
    nonces = []

    def candidate(_matrix, _hats, _mu, _rho, kappa):
        nonces.append(kappa)
        return signature if accept_last and len(nonces) == 1024 else None

    monkeypatch.setattr(s, "_candidate", candidate)

    def operation():
        return s.reference_sign_mldsa65(pair.secret_key, MESSAGE, context=CONTEXT, randomness=RND)

    if accept_last:
        assert operation() == signature  # Real final bounded verification still runs.
    else:
        failure(s.Failure.ATTEMPTS_EXHAUSTED, operation)
    assert nonces == list(range(0, 5120, 5))


def test_expand_mask_two_byte_nonce_and_endpoints(monkeypatch):
    calls = []

    def hash_parts(*parts, length):
        calls.append((parts, length))
        return bytes(640) if len(calls) % 2 else b"\xff" * 640

    monkeypatch.setattr(s, "_hash", hash_parts)
    with s._Scratch() as scratch:
        rows = s._expand_mask(bytes(64), 5115, scratch)
        assert rows[0] == [524288] * 256 and rows[1] == [-524287] * 256
    assert [item[0][1] for item in calls] == [i.to_bytes(2, "little") for i in range(5115, 5120)]
    assert all(item[1] == 640 for item in calls)


@pytest.mark.parametrize("bound", [v._GAMMA1 - v._BETA, v._GAMMA2 - v._BETA, v._GAMMA2])
def test_three_strict_candidate_norms(bound):
    assert s._within([[bound - 1, 1 - bound]], bound)
    assert not s._within([[bound]], bound)
    assert not s._within([[-bound]], bound)
    assert not s._within([[v._Q - bound]], bound)


@pytest.mark.parametrize("reject", ["z", "r0", "ct0", "hint-weight"])
def test_each_candidate_rejection_returns_only_none(monkeypatch, reject):
    def vector(rows):
        return [[0] * 256 for _ in range(rows)]

    monkeypatch.setattr(s, "_expand_mask", lambda _seed, _nonce, scratch: scratch.keep(vector(5)))
    monkeypatch.setattr(v, "_matrix_vector_product", lambda *_args: vector(6))
    monkeypatch.setattr(v, "_sample_in_ball", lambda _reader: [0] * 256)
    calls = []

    def product(_chat, hat, scratch):
        calls.append(hat)
        result = vector(5 if hat == "s1" else 6)
        if reject == "z" and hat == "s1":
            result[0][0] = v._GAMMA1 - v._BETA
        elif reject == "r0" and hat == "s2":
            result[0][0] = v._GAMMA2 - v._BETA
        elif reject == "ct0" and hat == "t0":
            result[0][0] = v._GAMMA2
        return scratch.keep(result)

    monkeypatch.setattr(s, "_challenge_product", product)
    if reject == "hint-weight":
        hints = iter([1] * 56 + [0] * (6 * 256 - 56))
        monkeypatch.setattr(s, "_make_hint", lambda *_args: next(hints))
    assert s._candidate([], ("s1", "s2", "t0"), bytes(64), bytes(64), 0) is None
    assert calls == (["s1", "s2"] if reject in {"z", "r0"} else ["s1", "s2", "t0"])


def test_hint_encoding_rounding_and_wraparound():
    for value in [0, 4096, 4097, 8191, v._Q - 1]:
        high, low = s._power2round(value)
        assert (high << 13) + low == value and -4096 < low <= 4096
    for value in [0, v._GAMMA2, v._GAMMA2 + 1, v._Q - 1]:
        for delta in [-10, 0, 10]:
            hint = s._make_hint(delta, value)
            assert v._use_hint(hint, value) == v._decompose(value + delta)[0]
    hints = [[int(i < (10 if r < 5 else 5)) for i in range(256)] for r in range(6)]
    encoded = s._encode_signature(bytes(48), [[0] * 256 for _ in range(5)], hints)
    assert len(encoded) == 3309 and v._decode_signature(encoded)[2] == hints
    assert list(encoded[-6:]) == [10, 20, 30, 40, 50, 55]


@pytest.mark.parametrize("status", [v._Status.INVALID, v._Status.EXHAUSTED])
def test_pre_return_verification_failure_never_retries(monkeypatch, pair, signature, status):
    calls = []

    def candidate(*_args):
        calls.append(1)
        return signature

    monkeypatch.setattr(s, "_candidate", candidate)
    monkeypatch.setattr(
        v, "_verify_diagnostic", lambda *_args, **_kwargs: v._VerificationResult(status)
    )
    reason = (
        s.Failure.SAMPLER_EXHAUSTED if status is v._Status.EXHAUSTED else s.Failure.RELEASE_REJECTED
    )
    failure(
        reason,
        lambda: s.reference_sign_mldsa65(pair.secret_key, MESSAGE, context=CONTEXT, randomness=RND),
    )
    assert calls == [1]


def test_import_rejects_malformed_or_inconsistent_keys(pair):
    for offset in [0, 64, 128, 768, 1536, 4031]:
        changed = bytearray(pair.secret_key)
        changed[offset] ^= 1
        failure(s.Failure.INVALID_INPUT, lambda: s.reference_public_key_mldsa65(bytes(changed)))  # noqa: B023
    changed = bytearray(pair.secret_key)
    changed[128] = 0xFF  # Explicitly invalid eta4 nibble.
    failure(s.Failure.INVALID_INPUT, lambda: s.reference_public_key_mldsa65(bytes(changed)))
    failure(
        s.Failure.INVALID_INPUT,
        lambda: s.reference_public_key_mldsa65(pair.secret_key, expected_public_key=bytes(1952)),
    )
    # K has no recoverable provenance test: altering it retains the same valid pk.
    changed = (
        pair.secret_key[:32] + bytes(x ^ 1 for x in pair.secret_key[32:64]) + pair.secret_key[64:]
    )
    assert s.reference_public_key_mldsa65(changed) == pair.public_key


def test_invalid_inputs_fail_before_sampling(monkeypatch, pair):
    def forbidden(*_args):
        pytest.fail("invalid input reached sampling")

    monkeypatch.setattr(v, "_expand_a", forbidden)
    for seed in [None, bytearray(32), bytes(31), bytes(33)]:
        failure(s.Failure.INVALID_INPUT, lambda: s.reference_keygen_mldsa65(seed))  # noqa: B023
    for key, msg, ctx, rnd in [
        (bytes(4031), MESSAGE, CONTEXT, RND),
        (pair.secret_key, "str", CONTEXT, RND),
        (pair.secret_key, MESSAGE, b"x" * 256, RND),
        (pair.secret_key, MESSAGE, CONTEXT, bytes(31)),
        (pair.secret_key, MESSAGE, bytearray(CONTEXT), RND),
    ]:
        failure(
            s.Failure.INVALID_INPUT,
            lambda: s.reference_sign_mldsa65(key, msg, context=ctx, randomness=rnd),  # noqa: B023
        )
    failure(
        s.Failure.INVALID_INPUT,
        lambda: s.bounded_sign_mldsa65(pair.secret_key, MESSAGE, role="unknown"),
    )


@pytest.mark.parametrize(
    "bad", [None, bytes(31), bytearray(32), OSError("synthetic entropy failure")]
)
def test_entropy_failure_is_final_in_both_wrappers(monkeypatch, pair, bad):
    draws = []

    def entropy(length):
        draws.append(length)
        if isinstance(bad, OSError):
            raise bad
        return bad

    monkeypatch.setattr(s.secrets, "token_bytes", entropy)
    failure(s.Failure.ENTROPY_FAILURE, s.bounded_keygen_mldsa65)
    failure(
        s.Failure.ENTROPY_FAILURE,
        lambda: s.bounded_sign_mldsa65(pair.secret_key, MESSAGE, role="credential"),
    )
    assert draws == [32, 32]


@pytest.mark.parametrize("role", list(s._CONTEXTS))
def test_operational_wrappers_fresh_draw_exact_role_and_no_deterministic_default(
    monkeypatch, pair, role
):
    draws = []

    def entropy(length):
        draws.append(length)
        return RND if len(draws) == 1 else SEED

    monkeypatch.setattr(s.secrets, "token_bytes", entropy)
    sig1 = s.bounded_sign_mldsa65(pair.secret_key, MESSAGE, role=role)
    sig2 = s.bounded_sign_mldsa65(pair.secret_key, MESSAGE, role=role)
    assert draws == [32, 32] and sig1 != sig2
    assert v.bounded_verify_mldsa65(pair.public_key, MESSAGE, sig1, context=s._CONTEXTS[role])
    assert v.bounded_verify_mldsa65(pair.public_key, MESSAGE, sig2, context=s._CONTEXTS[role])


def test_keygen_wrapper_consumes_one_seed(monkeypatch, pair):
    calls = []

    def entropy(length):
        calls.append(length)
        return SEED

    monkeypatch.setattr(s.secrets, "token_bytes", entropy)
    assert s.bounded_keygen_mldsa65() == pair and calls == [32]
    assert pair.secret_key.hex() not in repr(pair)


def test_resource_failure_and_mutable_disposal(monkeypatch, pair):
    captured = []

    def candidate(_matrix, hats, _mu, rho, _kappa):
        captured.extend([hats, rho])
        raise MemoryError("synthetic")

    monkeypatch.setattr(s, "_candidate", candidate)
    with pytest.raises(MemoryError):
        s.reference_sign_mldsa65(pair.secret_key, MESSAGE, context=CONTEXT, randomness=RND)
    assert all(x == 0 for vector in captured[0] for row in vector for x in row)
    assert captured[1] == bytearray(64)


def test_no_public_injection_cap_override_or_uncapped_dependency():
    assert set(inspect.signature(s.bounded_keygen_mldsa65).parameters) == set()
    assert set(inspect.signature(s.bounded_sign_mldsa65).parameters) == {
        "secret_key",
        "message",
        "role",
    }
    assert set(inspect.signature(s.reference_sign_mldsa65).parameters) == {
        "secret_key",
        "message",
        "context",
        "randomness",
    }
    source = inspect.getsource(s)
    assert "load_backend" not in source and "import oqs" not in source
    assert "from pqdid.backend" not in source
