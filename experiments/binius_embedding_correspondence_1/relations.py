"""Restricted algebraic component helpers, never proof or commitment verification."""

from field_model import GENERATOR, dot, element, inverse, mul


def equality_operand(z, y):
    if len(z) != 16 or len(y) != 16:
        raise ValueError("IntMul point dimension")
    value = 1
    for a, b in zip(z, y, strict=True):
        value = mul(value, 1 ^ element(a) ^ element(b))
    return value


def table_operand(point):
    if len(point) != 16:
        raise ValueError("IntMul table dimension")
    value, base = 1, GENERATOR
    for y in point:
        value = mul(value, 1 ^ mul(element(y), base ^ 1))
        base = mul(base, base)
    return value


class QueryBudget:
    def __init__(self, bound):
        self.bound = bound
        self.answers = {}

    def query(self, position, read):
        if type(position) is not int or position < 0:
            raise ValueError("query position")
        if position not in self.answers:
            if len(self.answers) >= self.bound:
                raise ValueError("distinct original-query budget")
            self.answers[position] = read(position)
        return self.answers[position]


def fold_pair(p, omega, gamma):
    element(gamma)
    if gamma == 0:
        raise ValueError("zero gamma outside restricted simulator")
    return [mul(1 ^ gamma, a) ^ mul(gamma, b) for a, b in zip(p, omega, strict=True)]


def aggregate_mask_claim(vectors, operands, public_b, gamma):
    if gamma == 0:
        raise ValueError("zero gamma outside restricted simulator")
    value = mul(1 ^ gamma, public_b)
    for v, u in zip(vectors, operands, strict=True):
        value ^= dot(v, u)
    return mul(value, inverse(gamma))
