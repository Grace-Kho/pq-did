"""FIPS 202 Algorithms 1–9 lowered to BC-1 gates, with 24 unabridged rounds.

State storage is A[x][y][z]. Triple loops visit x, then y, then z; string mapping
is z+64*(x+5*y). No native hash computes private data. Lengths are public bytes.
"""

from pqdid.circuits.emitter import Emitter
from pqdid.circuits.parsing import (
    MAX_DEVELOPMENT_BYTES,
    Bytes,
    check_bytes,
    public_bytes,
    reverse_byte_bits,
)


def _rc(t: int) -> int:
    # FIPS 202 Algorithm 5, entirely public; no secret-indexed table.
    if t % 255 == 0:
        return 1
    register = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(t % 255):
        register = [0, *register]
        for index in (0, 4, 5, 6):
            register[index] ^= register[8]
        register = register[:8]
    return register[0]


ROUND_CONSTANTS = tuple(
    sum(_rc(j + 7 * ir) << ((1 << j) - 1) for j in range(7)) for ir in range(24)
)


def _round(e: Emitter, a: tuple, ir: int) -> tuple:
    # Theta: the written five-term expression is a four-XOR left association.
    c = []
    for x in range(5):
        column = []
        for z in range(64):
            value = a[x][0][z]
            for y in range(1, 5):
                value = e.xor(value, a[x][y][z])
            column.append(value)
        c.append(tuple(column))
    d = tuple(
        tuple(e.xor(c[(x - 1) % 5][z], c[(x + 1) % 5][(z - 1) % 64]) for z in range(64))
        for x in range(5)
    )
    theta = tuple(
        tuple(tuple(e.xor(a[x][y][z], d[x][z]) for z in range(64)) for y in range(5))
        for x in range(5)
    )
    # Rho follows the public coordinate walk; copies and rotations only rewire.
    rho = [[None] * 5 for _ in range(5)]
    rho[0][0] = theta[0][0]
    x, y = 1, 0
    for t in range(24):
        offset = (t + 1) * (t + 2) // 2
        rho[x][y] = tuple(theta[x][y][(z - offset) % 64] for z in range(64))
        x, y = y, (2 * x + 3 * y) % 5
    pi = tuple(tuple(rho[(x + 3 * y) % 5][x] for y in range(5)) for x in range(5))
    # Chi reads the preceding state, uses the literal XOR 1, then AND, then XOR.
    chi = tuple(
        tuple(
            tuple(
                e.xor(
                    pi[x][y][z], e.and_(e.xor(pi[(x + 1) % 5][y][z], e.one), pi[(x + 2) % 5][y][z])
                )
                for z in range(64)
            )
            for y in range(5)
        )
        for x in range(5)
    )
    result = [list(column) for column in chi]
    result[0][0] = tuple(
        e.xor(chi[0][0][z], e.constant((ROUND_CONSTANTS[ir] >> z) & 1)) for z in range(64)
    )
    return tuple(tuple(column) for column in result)


def _permutation(e: Emitter, bits: Bytes) -> Bytes:
    # Internal string bits already in FIPS 202 order (not protocol integer order).
    a = tuple(
        tuple(bits[64 * (5 * y + x) : 64 * (5 * y + x + 1)] for y in range(5)) for x in range(5)
    )
    for ir in range(24):
        e.poll()
        a = _round(e, a, ir)
    return tuple(bit for y in range(5) for x in range(5) for bit in a[x][y])


def keccak_f1600(e: Emitter, state: Bytes) -> Bytes:
    """200 serialised bytes in/out; full permutation, without domain/padding."""
    check_bytes(e, state, length=200)
    return reverse_byte_bits(e, _permutation(e, reverse_byte_bits(e, state)))


def _sponge(e: Emitter, message: Bytes, rate_bytes: int, suffix: int, output_bytes: int) -> Bytes:
    check_bytes(e, message)
    if type(output_bytes) is not int or not 0 <= output_bytes <= MAX_DEVELOPMENT_BYTES:
        raise ValueError("output length must be a bounded public byte count")
    # Public byte padding encodes the suffix followed by pad10*1 (FIPS 202 B.2).
    remaining = rate_bytes - (len(message) // 8) % rate_bytes
    padding = bytearray(remaining)
    padding[0] = suffix
    padding[-1] |= 0x80
    padded = reverse_byte_bits(e, message) + reverse_byte_bits(e, public_bytes(e, bytes(padding)))
    rate = rate_bytes * 8
    state = (e.zero,) * 1600
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate] + (e.zero,) * (1600 - rate)
        # Keep even private XOR zero in the capacity; no partial simplification.
        state = tuple(e.xor(a, b) for a, b in zip(state, block, strict=True))
        state = _permutation(e, state)
    output = []
    # Algorithm 8 absorbs even when d=0; no private-dependent shortcut.
    while len(output) < 8 * output_bytes:
        output.extend(state[: min(rate, 8 * output_bytes - len(output))])
        if len(output) < 8 * output_bytes:
            state = _permutation(e, state)
    return reverse_byte_bits(e, tuple(output))


def sha3_384(e: Emitter, message: Bytes) -> Bytes:
    return _sponge(e, message, 104, 0x06, 48)


def shake128(e: Emitter, message: Bytes, output_bytes: int) -> Bytes:
    return _sponge(e, message, 168, 0x1F, output_bytes)


def shake256(e: Emitter, message: Bytes, output_bytes: int) -> Bytes:
    return _sponge(e, message, 136, 0x1F, output_bytes)
