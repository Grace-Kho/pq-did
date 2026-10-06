"""Bounded ML-DSA-65 Python reference verifier, version 1.

Original implementation of August 2024 FIPS 204 Algorithms 3/8 and their
verification subroutines, with VII-A.6 sampler exhaustion. Integer arithmetic;
stdlib hashlib SHAKE; no liboqs dependency, signing or circuit implementation.
Source/provenance and limitations: docs/stage2_bounded_mldsa.md.
Only bounded_verify_mldsa65 is the public API. Underscored readers/diagnostics
are internal test boundaries, never caller-selectable verification modes.
"""

import hashlib
from dataclasses import dataclass
from enum import Enum, auto
from hmac import compare_digest
from typing import Protocol

_Q = 8380417
_N = 256
_K = 6
_L = 5
_D = 13
_TAU = 49
_OMEGA = 55
_GAMMA1 = 1 << 19
_GAMMA2 = (_Q - 1) // 32
_BETA = 196
_REJ_NTT_BYTES = 1026
_BALL_BYTES = 256
_PUBLIC_KEY_BYTES = 1952
_SIGNATURE_BYTES = 3309
# FIPS 204 §7.5: zeta=1753, with eight-bit reversal; not Montgomery twiddles.
_ZETAS = tuple(pow(1753, int(f"{i:08b}"[::-1], 2), _Q) for i in range(_N))


class _Status(Enum):
    VALID = auto()
    INVALID = auto()
    EXHAUSTED = auto()


@dataclass(frozen=True)
class _VerificationResult:
    status: _Status
    sampler: str | None = None
    consumed: int | None = None


class _InvalidSignature(Exception):
    pass


class _SamplerExhausted(Exception):
    def __init__(self, sampler: str, consumed: int) -> None:
        super().__init__("bounded sampler exhausted")
        self.sampler = sampler
        self.consumed = consumed


class _Reader(Protocol):
    def read(self, length: int) -> bytes: ...


class _PrefixReader:
    """A single fixed SHAKE prefix. read does not restart or reseed the XOF."""

    def __init__(self, prefix: bytes) -> None:
        self._prefix = prefix
        self._offset = 0

    def read(self, length: int) -> bytes:
        end = self._offset + length
        if end > len(self._prefix):
            raise RuntimeError("internal SHAKE prefix exhausted unexpectedly")
        result = self._prefix[self._offset : end]
        self._offset = end
        return result


def _shake_reader(bits: int, seed: bytes) -> _Reader:
    # hashlib's digest(n) returns a prefix, not advancing reads. Materialise exactly
    # the allowed prefix once. Logical consumption is enforced separately below.
    if bits == 128:
        return _PrefixReader(hashlib.shake_128(seed).digest(_REJ_NTT_BYTES))
    if bits == 256:
        return _PrefixReader(hashlib.shake_256(seed).digest(_BALL_BYTES))
    raise ValueError("unsupported internal SHAKE variant")


class _Budget:
    def __init__(self, reader: _Reader, limit: int, sampler: str) -> None:
        self._reader = reader
        self._limit = limit
        self._sampler = sampler
        self.consumed = 0

    def read(self, length: int) -> bytes:
        # Check BEFORE touching the reader. Final permitted reads remain allowed.
        if self.consumed + length > self._limit:
            raise _SamplerExhausted(self._sampler, self.consumed)
        value = self._reader.read(length)
        if type(value) is not bytes or len(value) != length:
            raise RuntimeError("internal sampler reader returned an invalid block")
        self.consumed += length
        return value


def _rej_ntt_poly(reader: _Reader) -> list[int]:
    """FIPS 204 Algorithms 30/14; exactly three consumed bytes per candidate."""
    stream = _Budget(reader, _REJ_NTT_BYTES, "RejNTTPoly")
    coefficients = []
    while len(coefficients) < _N:
        candidate = int.from_bytes(stream.read(3), "little") & 0x7FFFFF
        if candidate < _Q:
            coefficients.append(candidate)
    return coefficients


def _sample_in_ball(reader: _Reader) -> list[int]:
    """FIPS 204 Algorithm 29; rejected indices also consume the 256-byte budget."""
    stream = _Budget(reader, _BALL_BYTES, "SampleInBall")
    signs = int.from_bytes(stream.read(8), "little")
    coefficients = [0] * _N
    for i in range(_N - _TAU, _N):
        j = stream.read(1)[0]
        while j > i:
            j = stream.read(1)[0]
        coefficients[i] = coefficients[j]
        coefficients[j] = 1 - 2 * (signs & 1)
        signs >>= 1
    return coefficients


def _expand_a(seed: bytes) -> list[list[list[int]]]:
    """Algorithm 32, all 30 independent invocations, row then column order."""
    return [
        [_rej_ntt_poly(_shake_reader(128, seed + bytes((column, row)))) for column in range(_L)]
        for row in range(_K)
    ]


def _unpack_poly(encoded: bytes, width: int) -> list[int]:
    """Algorithms 18/19 via little-endian bit strings, 256 coefficients."""
    if len(encoded) != 32 * width:
        raise _InvalidSignature
    packed = int.from_bytes(encoded, "little")
    mask = (1 << width) - 1
    return [(packed >> (i * width)) & mask for i in range(_N)]


def _decode_public_key(encoded: bytes) -> tuple[bytes, list[list[int]]]:
    # Every 10-bit value is in pkDecode's domain; no invented pk rejection rule.
    return encoded[:32], [
        _unpack_poly(encoded[32 + i * 320 : 32 + (i + 1) * 320], 10) for i in range(_K)
    ]


def _decode_hints(encoded: bytes) -> list[list[int]]:
    """Algorithm 21, including final zero padding and each row's strict order."""
    if len(encoded) != _OMEGA + _K:
        raise _InvalidSignature
    hints = [[0] * _N for _ in range(_K)]
    index = 0
    for row in range(_K):
        end = encoded[_OMEGA + row]
        if not index <= end <= _OMEGA:
            raise _InvalidSignature
        first = index
        while index < end:
            if index > first and encoded[index - 1] >= encoded[index]:
                raise _InvalidSignature
            hints[row][encoded[index]] = 1
            index += 1
    if any(encoded[index:_OMEGA]):
        raise _InvalidSignature
    return hints


def _decode_signature(encoded: bytes) -> tuple[bytes, list[list[int]], list[list[int]]]:
    """Algorithm 27: c-tilde(48), z(5*640), hints(55+6)."""
    z = [
        [_GAMMA1 - value for value in _unpack_poly(encoded[48 + i * 640 : 48 + (i + 1) * 640], 20)]
        for i in range(_L)
    ]
    return encoded[:48], z, _decode_hints(encoded[3248:])


def _ntt(coefficients: list[int]) -> list[int]:
    """Algorithm 41, ordinary integer residues (no Montgomery representation)."""
    result = [value % _Q for value in coefficients]
    m = 0
    length = 128
    while length >= 1:
        for start in range(0, _N, 2 * length):
            m += 1
            zeta = _ZETAS[m]
            for j in range(start, start + length):
                product = zeta * result[j + length] % _Q
                result[j + length] = (result[j] - product) % _Q
                result[j] = (result[j] + product) % _Q
        length //= 2
    return result


def _inverse_ntt(coefficients: list[int]) -> list[int]:
    """Algorithm 42; 8347681 is the inverse of 256 modulo q."""
    result = list(coefficients)
    m = 256
    length = 1
    while length < _N:
        for start in range(0, _N, 2 * length):
            m -= 1
            zeta = -_ZETAS[m]
            for j in range(start, start + length):
                left = result[j]
                result[j] = (left + result[j + length]) % _Q
                result[j + length] = zeta * ((left - result[j + length]) % _Q) % _Q
        length *= 2
    return [value * 8347681 % _Q for value in result]


def _matrix_vector_product(
    matrix: list[list[list[int]]], vector: list[list[int]]
) -> list[list[int]]:
    result = []
    for row in matrix:
        total = [0] * _N
        for column, polynomial in enumerate(row):
            for i in range(_N):
                total[i] = (total[i] + polynomial[i] * vector[column][i] % _Q) % _Q
        result.append(total)
    return result


def _decompose(value: int) -> tuple[int, int]:
    """Algorithm 36; centred remainder belongs to (-gamma2, gamma2]."""
    positive = value % _Q
    low = positive % (2 * _GAMMA2)
    if low > _GAMMA2:
        low -= 2 * _GAMMA2
    if positive - low == _Q - 1:
        return 0, low - 1
    return (positive - low) // (2 * _GAMMA2), low


def _use_hint(hint: int, value: int) -> int:
    """Algorithm 40; the algorithmic output domain is 0..15 for ML-DSA-65."""
    high, low = _decompose(value)
    if hint:
        return (high + (1 if low > 0 else -1)) % 16
    return high


def _encode_w1(vector: list[list[int]]) -> bytes:
    """Algorithm 28/16, four little-endian bits per coefficient."""
    return bytes(row[i] | (row[i + 1] << 4) for row in vector for i in range(0, _N, 2))


def _norm_ok(z: list[list[int]]) -> bool:
    return all(abs(value) < _GAMMA1 - _BETA for row in z for value in row)


def _verify_internal(public_key: bytes, formatted_message: bytes, signature: bytes) -> bool:
    """Algorithm 8 in its displayed order, including the final strict norm check."""
    rho, t1 = _decode_public_key(public_key)
    challenge_hash, z, hints = _decode_signature(signature)
    matrix = _expand_a(rho)
    tr = hashlib.shake_256(public_key).digest(64)
    mu = hashlib.shake_256(tr + formatted_message).digest(64)
    challenge = _sample_in_ball(_shake_reader(256, challenge_hash))
    az = _matrix_vector_product(matrix, [_ntt(row) for row in z])
    c_hat = _ntt(challenge)
    t1_hat = [_ntt([value * (1 << _D) % _Q for value in row]) for row in t1]
    w_approx = [
        _inverse_ntt([(az[row][i] - c_hat[i] * t1_hat[row][i] % _Q) % _Q for i in range(_N)])
        for row in range(_K)
    ]
    w1 = [[_use_hint(hints[row][i], w_approx[row][i]) for i in range(_N)] for row in range(_K)]
    reconstructed = hashlib.shake_256(mu + _encode_w1(w1)).digest(48)
    return _norm_ok(z) and compare_digest(challenge_hash, reconstructed)


def _verify_diagnostic(
    public_key: bytes, message: bytes, signature: bytes, *, context: bytes
) -> _VerificationResult:
    """Internal status only: malformed/invalid versus sampler exhaustion."""
    if any(type(value) is not bytes for value in (public_key, message, signature, context)):
        return _VerificationResult(_Status.INVALID)
    if (
        len(public_key) != _PUBLIC_KEY_BYTES
        or len(signature) != _SIGNATURE_BYTES
        or len(context) > 255
    ):
        return _VerificationResult(_Status.INVALID)
    formatted = bytes((0, len(context))) + context + message
    try:
        valid = _verify_internal(public_key, formatted, signature)
    except _InvalidSignature:
        return _VerificationResult(_Status.INVALID)
    except _SamplerExhausted as error:
        return _VerificationResult(_Status.EXHAUSTED, error.sampler, error.consumed)
    return _VerificationResult(_Status.VALID if valid else _Status.INVALID)


def bounded_verify_mldsa65(
    public_key: bytes, message: bytes, signature: bytes, *, context: bytes
) -> bool:
    """Pure ML-DSA-65 with fixed per-invocation 1026-/256-byte sampling caps.

    Invalid representations/signatures and exhaustion return False. Unexpected
    runtime/resource failures propagate, never become acceptance or native fallback.
    No verifier injection, cap override, prehash or external-mu API is exposed.
    This is a local Python reference, not constant-time code or a BC-1 circuit.
    """
    return (
        _verify_diagnostic(public_key, message, signature, context=context).status is _Status.VALID
    )
