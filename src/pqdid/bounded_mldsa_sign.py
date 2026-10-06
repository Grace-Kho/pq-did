"""Bounded ML-DSA-65 keygen/signing reference; NOT a production service adapter.

FIPS 204 (August 2024) Algorithms 1/2/6/7 and subroutines, with the project's
1026/512/256-byte sampler caps and 1024 candidate cap. Reuses the unchanged
bounded verifier's integer arithmetic. Explicit-input ``reference_*`` functions
are reproducibility interfaces, not operational randomness policies. The two
``bounded_*`` wrappers obtain fresh OS entropy; none is connected to live roles.

Python is not constant-time and cannot reliably erase immutable values, allocator
copies, hashlib state or traceback frames. Explicitly retained mutable work arrays
are cleared on normal return and exceptions; temporary copies are not guaranteed
erased. No logging, retry, native fallback or test hooks
are exposed by these interfaces. See docs/stage2_bounded_mldsa_keygen_sign.md.
"""

import hashlib
import secrets
from dataclasses import dataclass, field
from enum import Enum, auto
from hmac import compare_digest
from types import MappingProxyType

from pqdid import bounded_mldsa as v

_ETA = 4
_SHORT_BYTES = 512
_ATTEMPTS = 1024
_SECRET_KEY_BYTES = 4032
_CONTEXTS = MappingProxyType(
    {
        role: ("PQ-DID/" + role + "/v1").encode("ascii")
        for role in (
            "credential",
            "state",
            "update",
            "did-record",
            "did-read",
            "control",
            "request",
            "current",
            "revreq",
        )
    }
)


class Failure(Enum):
    INVALID_INPUT = auto()
    SAMPLER_EXHAUSTED = auto()
    ATTEMPTS_EXHAUSTED = auto()
    ENTROPY_FAILURE = auto()
    RELEASE_REJECTED = auto()


class BoundedMLDSAError(Exception):
    """Constant failure category only: no partial output or secret diagnostics."""

    def __init__(self, reason: Failure):
        self.reason = reason
        super().__init__(reason.name)


@dataclass(frozen=True)
class ReferenceKeyPair:
    public_key: bytes
    secret_key: bytes = field(repr=False)


class _Scratch:
    """Best-effort clearing of owned mutable arrays; not a secure-erasure claim."""

    def __init__(self):
        self.arrays = []

    def keep(self, value):
        self.arrays.append(value)
        return value

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        for value in self.arrays:
            _clear(value)
        self.arrays.clear()


def _clear(value):
    if isinstance(value, bytearray):
        for i in range(len(value)):
            value[i] = 0
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, list | bytearray):
                _clear(item)
            else:
                value[i] = 0


def _bytes(value, length=None):
    if type(value) is not bytes or (length is not None and len(value) != length):
        raise BoundedMLDSAError(Failure.INVALID_INPUT)


def _message(message, context):
    _bytes(message)
    _bytes(context)
    if len(context) > 255:
        raise BoundedMLDSAError(Failure.INVALID_INPUT)


def _hash(*parts, length):
    # Incremental absorption avoids making another complete copy of the message.
    state = hashlib.shake_256()
    for part in parts:
        state.update(part)
    return state.digest(length)


def _short_reader(seed):
    return v._PrefixReader(_hash(seed, length=_SHORT_BYTES))


def _rej_bounded_poly(reader):
    """Algorithms 15/31 for eta=4: low nibble first; charge the entire byte."""
    stream = v._Budget(reader, _SHORT_BYTES, "RejBoundedPoly")
    coefficients = []
    try:
        while len(coefficients) < v._N:
            value = stream.read(1)[0]
            for nibble in (value & 15, value >> 4):
                if nibble < 9 and len(coefficients) < v._N:
                    coefficients.append(_ETA - nibble)
        return coefficients
    except BaseException:
        _clear(coefficients)
        raise


def _expand_s(seed, scratch):
    # Per-polynomial independent caps, nonces 0..4 then 5..10, two-byte LE.
    rows = scratch.keep([])
    for nonce in range(v._L + v._K):
        rows.append(_rej_bounded_poly(_short_reader(seed + nonce.to_bytes(2, "little"))))
    return rows[: v._L], rows[v._L :]


def _pack_poly(values, width):
    if len(values) != v._N or any(not 0 <= x < 1 << width for x in values):
        raise BoundedMLDSAError(Failure.INVALID_INPUT)
    return sum(x << (width * i) for i, x in enumerate(values)).to_bytes(32 * width, "little")


def _power2round(value):
    positive = value % v._Q
    high = (positive + (1 << (v._D - 1)) - 1) >> v._D
    return high, positive - (high << v._D)


def _public_parts(rho, matrix, s1, s2, scratch):
    s1hat = scratch.keep([v._ntt(row) for row in s1])
    product = scratch.keep(v._matrix_vector_product(matrix, s1hat))
    t1, t0 = [], scratch.keep([])
    for r in range(v._K):
        row = scratch.keep(v._inverse_ntt(product[r]))
        pairs = [_power2round(row[i] + s2[r][i]) for i in range(v._N)]
        t1.append([high for high, _low in pairs])
        t0.append([low for _high, low in pairs])
    return rho + b"".join(_pack_poly(row, 10) for row in t1), t0


def _encode_secret(rho, key, tr, s1, s2, t0):
    return (
        rho
        + key
        + tr
        + b"".join(_pack_poly([_ETA - x for x in row], 4) for row in [*s1, *s2])
        + b"".join(_pack_poly([(1 << 12) - x for x in row], 13) for row in t0)
    )


def _decode_secret(secret_key, scratch):
    _bytes(secret_key, _SECRET_KEY_BYTES)
    short = scratch.keep([])
    for i in range(v._L + v._K):
        row = scratch.keep(v._unpack_poly(secret_key[128 + 128 * i : 256 + 128 * i], 4))
        if any(value > 2 * _ETA for value in row):
            raise BoundedMLDSAError(Failure.INVALID_INPUT)
        short.append([_ETA - value for value in row])
    t0 = scratch.keep([])
    for i in range(v._K):
        row = scratch.keep(v._unpack_poly(secret_key[1536 + 416 * i : 1952 + 416 * i], 13))
        t0.append([(1 << 12) - value for value in row])
    return secret_key[:32], secret_key[32:64], secret_key[64:128], short[:5], short[5:], t0


def _checked_secret(secret_key, scratch):
    rho, key, tr, s1, s2, t0 = _decode_secret(secret_key, scratch)
    matrix = v._expand_a(rho)
    public_key, expected_t0 = _public_parts(rho, matrix, s1, s2, scratch)
    # Algebraic import consistency, not proof of entropy, ownership or authority.
    if t0 != expected_t0 or not compare_digest(tr, _hash(public_key, length=64)):
        raise BoundedMLDSAError(Failure.INVALID_INPUT)
    return public_key, matrix, key, tr, s1, s2, t0


def reference_keygen_mldsa65(seed: bytes) -> ReferenceKeyPair:
    """Algorithm 6 with explicit 32-byte seed for synthetic reproducibility."""
    _bytes(seed, 32)
    try:
        with _Scratch() as scratch:
            expanded = scratch.keep(bytearray(_hash(seed, bytes((v._K, v._L)), length=128)))
            rho, rho_prime, key = bytes(expanded[:32]), bytes(expanded[32:96]), bytes(expanded[96:])
            matrix = v._expand_a(rho)
            s1, s2 = _expand_s(rho_prime, scratch)
            public_key, t0 = _public_parts(rho, matrix, s1, s2, scratch)
            secret_key = _encode_secret(rho, key, _hash(public_key, length=64), s1, s2, t0)
            return ReferenceKeyPair(public_key, secret_key)
    except v._SamplerExhausted:
        raise BoundedMLDSAError(Failure.SAMPLER_EXHAUSTED) from None


def reference_public_key_mldsa65(
    secret_key: bytes, *, expected_public_key: bytes | None = None
) -> bytes:
    """Derive/check an expanded secret key with bounded matrix expansion.

    Checks length, eta ranges, recomputed t0/tr and optional exact expected pk.
    K is a free 32-byte PRF seed: provenance/freshness cannot be recovered from sk.
    This returns no activation, registration or proof of key ownership.
    """
    if expected_public_key is not None:
        _bytes(expected_public_key, v._PUBLIC_KEY_BYTES)
    try:
        with _Scratch() as scratch:
            public_key = _checked_secret(secret_key, scratch)[0]
            if expected_public_key is not None and not compare_digest(
                public_key, expected_public_key
            ):
                raise BoundedMLDSAError(Failure.INVALID_INPUT)
            return public_key
    except v._SamplerExhausted:
        raise BoundedMLDSAError(Failure.SAMPLER_EXHAUSTED) from None


def _centre(value):
    return (value + v._Q // 2) % v._Q - v._Q // 2


def _expand_mask(seed, kappa, scratch):
    rows = scratch.keep([])
    for r in range(v._L):
        packed = scratch.keep(bytearray(_hash(seed, (kappa + r).to_bytes(2, "little"), length=640)))
        unpacked = scratch.keep(v._unpack_poly(packed, 20))
        rows.append([v._GAMMA1 - value for value in unpacked])
    return rows


def _challenge_product(challenge_hat, vector_hat, scratch):
    result = scratch.keep([])
    for row in vector_hat:
        pointwise = scratch.keep([challenge_hat[i] * row[i] % v._Q for i in range(v._N)])
        result.append([_centre(x) for x in v._inverse_ntt(pointwise)])
    return result


def _within(vector, bound):
    return all(abs(_centre(value)) < bound for row in vector for value in row)


def _make_hint(delta, value):
    return int(v._decompose(value)[0] != v._decompose(value + delta)[0])


def _encode_signature(challenge_hash, z, hints):
    positions = bytearray()
    counts = bytearray()
    for row in hints:
        positions.extend(i for i, bit in enumerate(row) if bit)
        counts.append(len(positions))
    if len(positions) > v._OMEGA:
        raise BoundedMLDSAError(Failure.INVALID_INPUT)
    return (
        challenge_hash
        + b"".join(_pack_poly([v._GAMMA1 - _centre(x) for x in row], 20) for row in z)
        + bytes(positions)
        + bytes(v._OMEGA - len(positions))
        + bytes(counts)
    )


def _candidate(matrix, hats, mu, rho_prime, kappa):
    """One candidate; None is ordinary rejection, sampler exhaustion is an exception."""
    with _Scratch() as scratch:
        y = _expand_mask(rho_prime, kappa, scratch)
        yhat = scratch.keep([v._ntt(row) for row in y])
        product = scratch.keep(v._matrix_vector_product(matrix, yhat))
        w = scratch.keep([v._inverse_ntt(row) for row in product])
        w1 = scratch.keep([[v._decompose(value)[0] for value in row] for row in w])
        challenge_hash = _hash(mu, v._encode_w1(w1), length=48)
        challenge = scratch.keep(v._sample_in_ball(v._shake_reader(256, challenge_hash)))
        chat = scratch.keep(v._ntt(challenge))
        cs1 = _challenge_product(chat, hats[0], scratch)
        cs2 = _challenge_product(chat, hats[1], scratch)
        z = scratch.keep([[y[r][i] + cs1[r][i] for i in range(v._N)] for r in range(v._L)])
        r0 = scratch.keep(
            [[v._decompose(w[r][i] - cs2[r][i])[1] for i in range(v._N)] for r in range(v._K)]
        )
        if not _within(z, v._GAMMA1 - v._BETA) or not _within(r0, v._GAMMA2 - v._BETA):
            return None
        ct0 = _challenge_product(chat, hats[2], scratch)
        hints = scratch.keep(
            [
                [_make_hint(-ct0[r][i], w[r][i] - cs2[r][i] + ct0[r][i]) for i in range(v._N)]
                for r in range(v._K)
            ]
        )
        if not _within(ct0, v._GAMMA2) or sum(sum(row) for row in hints) > v._OMEGA:
            return None
        return _encode_signature(challenge_hash, z, hints)


def reference_sign_mldsa65(
    secret_key: bytes, message: bytes, *, context: bytes, randomness: bytes
) -> bytes:
    """Pure ML-DSA, explicit 32-byte synthetic randomness, bounded pre-return verify.

    No deterministic-mode default, prehash/external-mu, cap override or injection
    argument exists. Exhaustion/final verification failure never retries signing.
    """
    _bytes(secret_key, _SECRET_KEY_BYTES)
    _message(message, context)
    _bytes(randomness, 32)
    try:
        with _Scratch() as scratch:
            public_key, matrix, key, tr, s1, s2, t0 = _checked_secret(secret_key, scratch)
            hats = scratch.keep([[v._ntt(row) for row in vector] for vector in (s1, s2, t0)])
            mu = _hash(tr, bytes((0, len(context))), context, message, length=64)
            rho_prime = scratch.keep(bytearray(_hash(key, randomness, mu, length=64)))
            for attempt in range(_ATTEMPTS):
                signature = _candidate(matrix, hats, mu, rho_prime, v._L * attempt)
                if signature is None:
                    continue
                checked = v._verify_diagnostic(public_key, message, signature, context=context)
                if checked.status is v._Status.EXHAUSTED:
                    raise BoundedMLDSAError(Failure.SAMPLER_EXHAUSTED)
                if checked.status is not v._Status.VALID:
                    raise BoundedMLDSAError(Failure.RELEASE_REJECTED)
                return signature
            raise BoundedMLDSAError(Failure.ATTEMPTS_EXHAUSTED)
    except v._SamplerExhausted:
        raise BoundedMLDSAError(Failure.SAMPLER_EXHAUSTED) from None


def _entropy():
    try:
        result = secrets.token_bytes(32)
    except OSError:
        raise BoundedMLDSAError(Failure.ENTROPY_FAILURE) from None
    if type(result) is not bytes or len(result) != 32:
        raise BoundedMLDSAError(Failure.ENTROPY_FAILURE)
    return result


def bounded_keygen_mldsa65() -> ReferenceKeyPair:
    """Reference-only OS-random wrapper, no caller seed or entropy override."""
    return reference_keygen_mldsa65(_entropy())


def bounded_sign_mldsa65(secret_key: bytes, message: bytes, *, role: str) -> bytes:
    """Reference-only hedged wrapper for the nine fixed roles; no service wiring.

    Caller selects a trusted role and supplies its already canonical message body.
    This core does not authorise a role, construct application messages or commit
    state. Each invocation draws fresh randomness once; failure is final.
    """
    if type(role) is not str or role not in _CONTEXTS:
        raise BoundedMLDSAError(Failure.INVALID_INPUT)
    _bytes(secret_key, _SECRET_KEY_BYTES)
    _bytes(message)
    return reference_sign_mldsa65(
        secret_key, message, context=_CONTEXTS[role], randomness=_entropy()
    )
