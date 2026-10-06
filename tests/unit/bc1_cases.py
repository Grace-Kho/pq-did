"""Independent mathematical packing for circuit tests; no emitted computation."""


def integer_bits(value, width):
    return [(value >> i) & 1 for i in range(width)]


def packed(bits):
    # Inputs always serialise MSB-first, even when a test assigns arithmetic
    # bit positions in LSB-first field order explicitly.
    result = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        result[i // 8] |= bit << (7 - i % 8)
    return bytes(result)
