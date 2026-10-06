"""Python scalar model of pinned RS permutation/repetition/NTT; never native."""

from field_model import TRACE_ONE, element, mul


def basis(log_size):
    if type(log_size) is not int or not 1 <= log_size <= 6:
        raise ValueError("domain dimension")
    beta = TRACE_ONE
    for _ in range(128 - log_size):
        beta = mul(beta, beta) ^ beta
    out = [0] * log_size
    out[-1] = beta
    for i in range(log_size - 1, 0, -1):
        out[i - 1] = mul(out[i], out[i]) ^ out[i]
    if out[0] != 1:
        raise ValueError("trace correspondence")
    return out


def reverse(value, bits):
    out = 0
    for _ in range(bits):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def encode_pair(physical, companion, rate):
    size = len(physical)
    if size not in (2, 4, 8, 16) or len(companion) != size or rate not in (2, 4):
        raise ValueError("encoder shape")
    data = list(physical) + list(companion)
    for x in data:
        element(x)
    log_dim = size.bit_length() - 1
    log_rate = rate.bit_length() - 1
    domain = basis(log_dim + log_rate)
    bits = log_dim + 1
    permuted = [data[reverse(i, bits)] for i in range(len(data))]
    output = permuted * rate
    log_d = len(output).bit_length() - 1
    for layer in range(log_rate, log_d - 1):
        half = 1 << (log_d - layer - 1)
        for block in range(1 << layer):
            twiddle = 0
            for bit in range(layer):
                if block >> bit & 1:
                    twiddle ^= domain[bit + 1]
            start = block << (log_d - layer)
            for i in range(start, start + half):
                j = i | half
                u = output[i] ^ mul(output[j], twiddle)
                output[j] ^= u
                output[i] = u
    return output, domain
