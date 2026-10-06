"""Independent exact-integer expectations and a test-only Boolean trace reader.

No production imports. Outputs are observed from existing wires, not supplied as
private quotient/remainder advice. The production evaluator is checked separately.
"""

import struct
from fractions import Fraction
from math import floor

Q = 8380417
GAMMA2 = (Q - 1) // 32


def floor_pair(a, b):
    if b <= 0:
        raise ValueError("positive divisor required")
    quotient = floor(Fraction(a, b))
    return quotient, a - quotient * b


def centred(a, modulus):
    remainder = floor_pair(a, modulus)[1]
    return remainder if remainder <= modulus // 2 else remainder - modulus


def decompose(value):
    positive = floor_pair(value, Q)[1]
    # Nearest multiple with ties towards the smaller multiple. The top bucket
    # wraps to q rather than q-1; this is independent of Algorithm 36's branches.
    bucket = floor(Fraction(positive + GAMMA2 - 1, 2 * GAMMA2))
    if bucket == 16:
        return 0, positive - Q
    return bucket, positive - bucket * 2 * GAMMA2


def use_hint(hint, value):
    high, low = decompose(value)
    if not hint:
        return high
    return floor_pair(high + (1 if low > 0 else -1), 16)[1]


def trace_words(serialised, witness, indices):
    """Read signed words from a finite trace independently of production evaluation."""
    inputs = struct.unpack_from(">Q", serialised, 16)[0]
    records = memoryview(serialised)[56:-33]
    values = bytearray(2 + inputs + len(records) // 17)
    values[1] = 1
    for i in range(inputs):
        values[2 + i] = (witness[i // 8] >> (7 - i % 8)) & 1
    for output, (opcode, left, right) in enumerate(struct.iter_unpack(">BQQ", records), 2 + inputs):
        if opcode == 1:
            values[output] = values[left] ^ values[right]
        elif opcode == 2:
            values[output] = values[left] & values[right]
        elif opcode == 3:
            values[output] = 1 ^ values[left]
        else:
            raise AssertionError("invalid opcode")
    return tuple(
        sum(values[index] << bit for bit, index in enumerate(word))
        - (values[word[-1]] << len(word))
        for word in indices
    )
