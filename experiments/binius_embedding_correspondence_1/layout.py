"""Isolated strict even/odd embedding; descriptors are local, not commitments."""

from dataclasses import dataclass

from field_model import element, mul

ENCODING = "ghash-polynomial-lsb-u128-v1"
ORDER = "variable-index-low-first"


def power_two(n):
    return type(n) is int and n > 0 and n & (n - 1) == 0


@dataclass(frozen=True)
class EmbeddingSpec:
    oracle_id: str
    k: int
    m: int
    rate: int
    field_encoding: str = ENCODING
    point_order: str = ORDER
    data_parity: int = 1
    version: int = 1

    def validate(self, expected):
        if self != expected or not isinstance(self.oracle_id, str) or not self.oracle_id:
            raise ValueError("trusted descriptor mismatch")
        if not power_two(self.k) or not power_two(self.m) or not self.k <= self.m <= 8:
            raise ValueError("dimensions")
        if self.k > 4 or type(self.rate) is not int or self.rate not in (2, 4):
            raise ValueError("component dimension/rate cap")
        if self.field_encoding != ENCODING or self.point_order != ORDER:
            raise ValueError("representation/order")
        if (
            type(self.data_parity) is not int
            or self.data_parity != 1
            or type(self.version) is not int
            or self.version != 1
        ):
            raise ValueError("layout parity/version")


def words(xs, length):
    if type(xs) not in (list, tuple) or len(xs) != length:
        raise ValueError("vector length")
    for x in xs:
        element(x)


def embed(spec, expected, logical, randomness):
    spec.validate(expected)
    words(logical, spec.k)
    words(randomness, spec.m)
    result = [0] * (2 * spec.m)
    result[::2] = randomness
    result[1 : 2 * spec.k : 2] = logical
    return result


def embed_from_entropy(spec, expected, logical, entropy):
    spec.validate(expected)
    random_words = entropy(spec.m)
    return embed(spec, expected, logical, random_words)


def decode(spec, expected, physical):
    spec.validate(expected)
    words(physical, 2 * spec.m)
    if any(physical[2 * spec.k + 1 :: 2]):
        raise ValueError("nonzero odd padding")
    return list(physical[1 : 2 * spec.k : 2])


def transport_operand(spec, expected, logical):
    spec.validate(expected)
    words(logical, spec.k)
    result = [0] * (2 * spec.m)
    result[1 : 2 * spec.k : 2] = logical
    return result


def mle(values, point):
    words(point, len(values).bit_length() - 1)
    work = list(values)
    for y in point:
        work = [a ^ mul(y, a ^ b) for a, b in zip(work[::2], work[1::2], strict=True)]
    return work[0]


def eval_transported_operand(spec, expected, logical, point, order=ORDER):
    spec.validate(expected)
    if order != ORDER:
        raise ValueError("point order requires explicit conversion")
    words(point, spec.m.bit_length())
    words(logical, spec.k)
    d = spec.k.bit_length() - 1
    value = mul(point[0], mle(logical, point[1 : 1 + d]))
    for y in point[1 + d :]:
        value = mul(value, 1 ^ y)
    return value


def binding_to_variable(point):
    return list(reversed(point))


def terminal_operand(spec, expected, index):
    if type(index) is not int or not 0 <= index < spec.k:
        raise ValueError("selector range")
    logical = [int(j == index) for j in range(spec.k)]
    return transport_operand(spec, expected, logical)
