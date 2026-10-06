"""Complete source lowering for bounded ML-DSA-65 private verification.

Experimental, not canonical BC-1. All private choices are fixed Boolean wiring.
The approved hint and forward/public-multiply kernels are reused unchanged;
inverse, accumulation and decomposition retain generic checked signed64 gadgets.
Complete source coverage does not imply completed counting, evaluation or a proof.
"""

from dataclasses import dataclass

from experiments.mldsa_forward_ntt_stage_1.candidate import _from_canonical_producers
from experiments.mldsa_modmul_lowering_1.candidate import ntt_mul_public_q
from experiments.private_hint_lowering_1.candidate import decode_hints
from pqdid.bounded_mldsa import _ZETAS
from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import mod64
from pqdid.circuits.keccak import shake256
from pqdid.circuits.parsing import check_bytes, equal_bytes, public_bytes
from pqdid.circuits.signature import decode_responses, response_norm

Q = 8_380_417
N, K, L, TAU = 256, 6, 5, 49


@dataclass(frozen=True, repr=False)
class SamplerResult:
    coefficients: tuple
    completed: object
    next_index: tuple


@dataclass(frozen=True, repr=False)
class SignatureResult:
    valid: object
    reconstructed_challenge: tuple
    challenge_hash: tuple
    encoded_w1: tuple


def _live(scope):
    return scope.e.and_(scope.active, scope.e.not_(scope.rejected))


def _masked(scope, values):
    usable = _live(scope)
    return tuple(tuple(scope.e.and_(usable, bit) for bit in word) for word in values)


def _sample_from_prefix(scope: Scope, prefix) -> SamplerResult:
    """Fixed-flow Algorithm 29 over exactly 256 bytes (test-only stream boundary).

    i starts at 207 and reaches 256 after exactly49 accepted candidates. Every
    index byte advances the public scan, including rejected j>i; after completion
    all remaining updates are masked. Writes are sequential: c[i]=old c[j], then
    c[j]=sign, including i=j. The 64 sign bits are consumed only on acceptance.
    Exhaustion rejects; inactive or rejected outputs are unusable zeroes.
    """
    e = scope.e
    check_bytes(e, prefix, length=256)
    # Algorithm 29 reads its first eight bytes as a little-endian integer.
    signs = tuple(
        bit for offset in range(0, 64, 8) for bit in reversed(prefix[offset : offset + 8])
    )
    index = w.constant(e, N - TAU, 64)
    cells = tuple(w.constant(e, 0, 64) for _ in range(N))
    for offset in range(8, 256):
        candidate = (*reversed(prefix[8 * offset : 8 * (offset + 1)]), *((e.zero,) * 56))
        pending = w.less64(e, index, w.constant(e, N, 64))
        in_range = w.less_equal64(e, candidate, index)
        step = Scope(e, active=e.and_(_live(scope), e.and_(pending, in_range)))
        previous = step.read(cells, candidate)
        cells = step.write(cells, index, previous)
        sign = w.mux_word(e, signs[0], w.constant(e, 1, 64), w.constant(e, -1, 64, signed=True))
        cells = step.write(cells, candidate, sign)
        incremented = step.checked(w.add64(e, index, w.constant(e, 1, 64)))
        index = w.mux_word(e, step.active, index, incremented)
        signs = w.mux_word(e, step.active, signs, (*signs[1:], e.zero))
        scope.rejected = e.or_(scope.rejected, step.rejected)
    completed = w.equal(e, index, w.constant(e, N, 64))
    scope.require(completed)
    return SamplerResult(_masked(scope, cells), completed, index)


def sample_in_ball(scope: Scope, challenge_hash) -> SamplerResult:
    check_bytes(scope.e, challenge_hash, length=48)
    # No external reader or prefix override exists in the production composition.
    return _sample_from_prefix(scope, shake256(scope.e, challenge_hash, 256))


def _polynomial(scope, coefficients):
    if type(coefficients) is not tuple or len(coefficients) != N:
        raise ValueError("exactly 256 signed64 coefficients required")
    for value in coefficients:
        w.check_word(scope.e, value, 64)


def forward_ntt(scope: Scope, coefficients):
    """All eight stages /1,024 butterflies, ordinary residues, signed64 entry.

    Complete SPEC-004 entry normalisation establishes canonical [0,q) values.
    Every subsequent producer is the already-reviewed canonical butterfly. No
    caller-supplied canonicality flag or host witness value changes topology.
    """
    _polynomial(scope, coefficients)
    state = list(_masked(scope, tuple(scope.checked(mod64(scope.e, v, Q)) for v in coefficients)))
    m = 0
    for stage in range(8):
        length = 128 >> stage
        for start in range(0, N, 2 * length):
            m += 1
            for j in range(start, start + length):
                result = _from_canonical_producers(
                    scope,
                    ring.Scalar(state[j], ring.Domain.NTT),
                    ring.Scalar(state[j + length], ring.Domain.NTT),
                    _ZETAS[m],
                )
                state[j], state[j + length] = result.left.value, result.right.value
    return _masked(scope, tuple(state))


def inverse_ntt(scope: Scope, coefficients):
    """Algorithm42 in the existing generic checked integer representation.

    The complete verifier passes canonical inputs from checked mod-q subtraction.
    Entry normalisation also makes this helper's signed64 domain explicit. For
    canonical a,b, sum/difference fit signed64 and |zeta*(a-b modq)|<q²<2^46.
    Negative zeta is kept as the signed reference value. Final factor8347681 is
    applied to every coefficient; outputs are ordinary residues, no Montgomery
    scaling. This is not a claim that the forward pilot validated this transform.
    """
    _polynomial(scope, coefficients)
    state = [scope.checked(mod64(scope.e, value, Q)) for value in coefficients]
    m = 256
    for stage in range(8):
        length = 1 << stage
        for start in range(0, N, 2 * length):
            m -= 1
            for j in range(start, start + length):
                state[j], state[j + length] = inverse_butterfly(
                    scope, state[j], state[j + length], -_ZETAS[m]
                )
    factor = ring.Scalar(w.constant(scope.e, 8_347_681, 64), ring.Domain.NTT)
    return _masked(
        scope,
        tuple(
            ring.multiply(scope, ring.Scalar(value, ring.Domain.NTT), factor).value
            for value in state
        ),
    )


def inverse_butterfly(scope, left, right, negative_twiddle):
    """Exact checked Algorithm42 pair; inputs are signed64, as ring gadgets require."""
    if type(negative_twiddle) is not int or not -Q < negative_twiddle <= 0:
        raise ValueError("inverse twiddle must be a public negative residue")
    a = ring.Scalar(left, ring.Domain.NTT)
    b = ring.Scalar(right, ring.Domain.NTT)
    twiddle = ring.Scalar(w.constant(scope.e, negative_twiddle, 64, signed=True), ring.Domain.NTT)
    total = ring.add(scope, a, b)
    difference = ring.subtract(scope, a, b)
    product = ring.multiply(scope, twiddle, difference)
    return total.value, product.value


def multiply_public(scope, value, factor):
    """The fully guarded approved public-constant kernel; no private factor."""
    return ntt_mul_public_q(scope, ring.Scalar(value, ring.Domain.NTT), factor).value.value


def accumulate_public_product(scope, total, value, factor):
    product = multiply_public(scope, value, factor)
    return ring.add(
        scope,
        ring.Scalar(total, ring.Domain.NTT),
        ring.Scalar(product, ring.Domain.NTT),
    ).value


def subtract_public_product(scope, total, value, factor):
    product = multiply_public(scope, value, factor)
    return ring.subtract(
        scope,
        ring.Scalar(total, ring.Domain.NTT),
        ring.Scalar(product, ring.Domain.NTT),
    ).value


def matrix_vector(scope: Scope, matrix, vector):
    if len(matrix) != K or len(vector) != L:
        raise ValueError("ML-DSA-65 matrix/vector dimensions required")
    for polynomial in vector:
        _polynomial(scope, polynomial)
    output = []
    for row in matrix:
        if len(row) != L or any(len(poly) != N for poly in row):
            raise ValueError("ML-DSA-65 matrix dimensions required")
        total = [w.constant(scope.e, 0, 64) for _ in range(N)]
        for column in range(L):
            for i in range(N):
                total[i] = accumulate_public_product(
                    scope, total[i], vector[column][i], row[column][i]
                )
        output.append(tuple(total))
    return tuple(output)


def challenge_subtract(scope, az, challenge, t1_hat):
    if len(az) != K or len(t1_hat) != K:
        raise ValueError("six matrix output/key polynomials required")
    _polynomial(scope, challenge)
    result = []
    for row in range(K):
        _polynomial(scope, az[row])
        if len(t1_hat[row]) != N:
            raise ValueError("256 public key NTT slots required")
        result.append(
            tuple(
                subtract_public_product(scope, az[row][i], challenge[i], t1_hat[row][i])
                for i in range(N)
            )
        )
    return tuple(result)


def encode_w1(scope: Scope, vector):
    """Algorithm28: low coefficient's nibble first; complete canonical guard."""
    if type(vector) is not tuple or len(vector) != K:
        raise ValueError("six high-bit polynomials required")
    encoded = []
    for polynomial in vector:
        _polynomial(scope, polynomial)
        for value in polynomial:
            scope.require(w.less_equal64(scope.e, w.constant(scope.e, 0, 64), value))
            scope.require(w.less64(scope.e, value, w.constant(scope.e, 16, 64)))
        for i in range(0, N, 2):
            encoded.extend(reversed((*polynomial[i][:4], *polynomial[i + 1][:4])))
    return tuple(encoded)


def verify_signature(scope: Scope, prepared, signature, formatted_message):
    """All private Algorithm8 checks jointly; no host verification shortcut."""
    e = scope.e
    decoded = decode_responses(scope, signature)
    hints = decode_hints(scope, decoded.encoded_hints)
    mu = shake256(e, public_bytes(e, prepared.public_key_hash) + formatted_message, 64)
    challenge = sample_in_ball(scope, decoded.challenge_hash)
    z_hat = tuple(forward_ntt(scope, polynomial) for polynomial in decoded.responses)
    az = matrix_vector(scope, prepared.matrix, z_hat)
    c_hat = forward_ntt(scope, challenge.coefficients)
    approximate = tuple(
        inverse_ntt(scope, polynomial)
        for polynomial in challenge_subtract(scope, az, c_hat, prepared.t1_hat)
    )
    high = tuple(
        tuple(ring.use_hint(scope, hints.hints[row][i][0], approximate[row][i]) for i in range(N))
        for row in range(K)
    )
    encoded = encode_w1(scope, high)
    reconstructed = shake256(e, mu + encoded, 48)
    norm = response_norm(scope, decoded.responses)
    scope.require(norm.within_bound)
    scope.require(equal_bytes(e, decoded.challenge_hash, reconstructed))
    return SignatureResult(scope.output(()), reconstructed, decoded.challenge_hash, encoded)
