"""Independent exact-integer odd-root Horner oracle; no production imports.

Derivation: negacyclic polynomial evaluations in Algorithm 41 output order.
No butterfly, partition, root table or candidate schedule helper is shared.
"""

Q = 8_380_417


def reverse8(value):
    result = 0
    for _ in range(8):
        result = 2 * result + value % 2
        value //= 2
    return result


def transform(values):
    coefficients = [v % Q for v in values]
    result = []
    for index in range(256):
        root = pow(1753, 2 * reverse8(index) + 1, Q)
        accumulator = 0
        for coefficient in reversed(coefficients):
            accumulator = (accumulator * root + coefficient) % Q
        result.append(accumulator)
    return result
