"""Independent exact polynomial oracle; imports no candidate functions."""

from functools import lru_cache

MODULUS = (1 << 128) | 0x87
EVENTS = 0


def multiply(a, b):
    global EVENTS
    EVENTS += 256
    if EVENTS > 1 << 24:
        raise RuntimeError("reference work-event cap")
    wide = 0
    while b:
        bit = b & -b
        wide ^= a << (bit.bit_length() - 1)
        b ^= bit
    while wide.bit_length() > 128:
        wide ^= MODULUS << (wide.bit_length() - 129)
    return wide


def inv(a):
    if not a:
        raise ValueError("zero inverse")
    u, v, x, y = a, MODULUS, 1, 0
    while u != 1:
        shift = u.bit_length() - v.bit_length()
        if shift < 0:
            u, v, x, y = v, u, y, x
            shift = -shift
        u ^= v << shift
        x ^= y << shift
    while x.bit_length() > 128:
        x ^= MODULUS << (x.bit_length() - 129)
    return x


def exponent(a, n):
    out = 1
    for bit in bin(n)[2:]:
        out = multiply(out, out)
        if bit == "1":
            out = multiply(out, a)
    return out


@lru_cache(maxsize=6)
def domain_basis(log_size):
    # (Frobenius+I)^n: binomial coefficients are odd exactly for j subset n.
    frobenius = [1 << 121]
    for _ in range(127):
        frobenius.append(multiply(frobenius[-1], frobenius[-1]))
    out = []
    for i in range(log_size):
        n = 127 - i
        value = 0
        for j in range(n + 1):
            if j & ~n == 0:
                value ^= frobenius[j]
        out.append(value)
    assert out[0] == 1
    return tuple(out)


def point_at(basis, index):
    result = 0
    for i, b in enumerate(basis):
        if index & (1 << i):
            result ^= b
    return result


@lru_cache(maxsize=128)
def subspace_values(log_size, x):
    basis = domain_basis(log_size)
    values = []
    space = [0]
    for beta in basis:
        numerator = denominator = 1
        for point in space:
            numerator = multiply(numerator, x ^ point)
            denominator = multiply(denominator, beta ^ point)
        values.append(multiply(numerator, inv(denominator)))
        space += [s ^ beta for s in space]
    return tuple(values)


def raw_polynomial(raw, w):
    # Raw MSB corresponds to W_0: independently expressed, no reversal helper.
    d = len(raw).bit_length() - 1
    result = 0
    for address, coefficient in enumerate(raw):
        term = coefficient
        for j in range(d):
            if address & (1 << (d - 1 - j)):
                term = multiply(term, w[j])
        result ^= term
    return result


def expected_pair(logical, random, companion, m, rate):
    log_size = (2 * m * rate).bit_length() - 1
    ell = m.bit_length() - 1
    basis = domain_basis(log_size)
    outputs = []
    for address in range(2 * m * rate):
        w = subspace_values(log_size, point_at(basis, address))
        r = raw_polynomial(random, w)
        padded = list(logical) + [0] * (m - len(logical))
        g = raw_polynomial(padded, w)
        outputs += [r ^ multiply(w[ell], g), raw_polynomial(companion, w)]
    return outputs, list(basis)


def dot(a, b):
    result = 0
    for x, y in zip(a, b, strict=True):
        result ^= multiply(x, y)
    return result


def evaluate_table(table, point):
    result = 0
    for j, value in enumerate(table):
        weight = 1
        for bit, y in enumerate(point):
            weight = multiply(weight, y if j >> bit & 1 else 1 ^ y)
        result ^= multiply(value, weight)
    return result


def rank(rows):
    a = [list(row) for row in rows]
    pivots = 0
    for col in range(len(a[0])):
        choice = next((i for i in range(pivots, len(a)) if a[i][col]), None)
        if choice is None:
            continue
        a[pivots], a[choice] = a[choice], a[pivots]
        scale = inv(a[pivots][col])
        a[pivots] = [multiply(v, scale) for v in a[pivots]]
        for i in range(len(a)):
            if i != pivots:
                scale = a[i][col]
                a[i] = [v ^ multiply(scale, w) for v, w in zip(a[i], a[pivots], strict=True)]
        pivots += 1
    return pivots
