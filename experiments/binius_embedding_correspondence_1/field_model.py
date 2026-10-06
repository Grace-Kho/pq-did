"""Scalar GHASH Python model; no constant-time or native execution claim."""

MASK = (1 << 128) - 1
GENERATOR = 0x494EF99794D5244F9152DF59D87A9186
TRACE_ONE = 1 << 121
EVENTS = 0


def element(x):
    if type(x) is not int or not 0 <= x <= MASK:
        raise ValueError("noncanonical field word")
    return x


def mul(a, b):
    global EVENTS
    EVENTS += 128
    if EVENTS > 1 << 24:
        raise RuntimeError("component work-event stop")
    value = 0
    for _ in range(128):
        value ^= a if b & 1 else 0
        b >>= 1
        a = ((a << 1) & MASK) ^ (0x87 if a >> 127 else 0)
    return value


def power(a, n):
    value = 1
    while n:
        if n & 1:
            value = mul(value, a)
        a = mul(a, a)
        n >>= 1
    return value


def inverse(a):
    if not a:
        raise ValueError("zero inverse")
    return power(a, (1 << 128) - 2)


def dot(a, b):
    if len(a) != len(b):
        raise ValueError("dot dimensions")
    result = 0
    for x, y in zip(a, b, strict=True):
        result ^= mul(x, y)
    return result
