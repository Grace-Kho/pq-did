"""Independent integer/lane FIPS 202 oracle for permutation tests only.

Row-major words, fixed rotation/round tables, native integer operations; never used
to implement private circuits. Hash-wrapper expectations additionally use NIST CAVP
and hashlib/OpenSSL, so this reference is not the sole correctness oracle.
"""

ROTATIONS = (
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
)
ROUND_CONSTANTS = (
    0x1,
    0x8082,
    0x800000000000808A,
    0x8000000080008000,
    0x808B,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8A,
    0x88,
    0x80008009,
    0x8000000A,
    0x8000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
)
MASK = (1 << 64) - 1


def rotate(value, amount):
    return ((value << amount) | (value >> (64 - amount))) & MASK


def permutation(data):
    assert len(data) == 200
    state = [int.from_bytes(data[i : i + 8], "little") for i in range(0, 200, 8)]
    for constant in ROUND_CONSTANTS:
        parity = [
            state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x]
            for x in range(5)
        ]
        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                value = state[5 * y + x] ^ parity[(x - 1) % 5] ^ rotate(parity[(x + 1) % 5], 1)
                moved[5 * ((2 * x + 3 * y) % 5) + y] = rotate(value, ROTATIONS[5 * y + x])
        state = [
            moved[5 * y + x] ^ ((~moved[5 * y + (x + 1) % 5]) & moved[5 * y + (x + 2) % 5])
            for y in range(5)
            for x in range(5)
        ]
        state[0] ^= constant
    return b"".join(value.to_bytes(8, "little") for value in state)
