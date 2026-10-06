"""Independent encoding-only fixtures/trace observations; no production imports.

These synthetic signatures are NOT cryptographically valid. Genuine signatures
come separately from the existing native/relation fixtures.
"""

from tests.reference.scalar_oracle import trace_words


def hint_encoding(rows):
    assert len(rows) == 6 and sum(map(len, rows)) <= 55
    flattened = bytes(position for row in rows for position in row)
    ends, total = [], 0
    for row in rows:
        assert list(row) == sorted(set(row))
        total += len(row)
        ends.append(total)
    return flattened.ljust(55, b"\0") + bytes(ends)


def synthetic_signature(responses, rows=((), (), (), (), (), ())):
    assert len(responses) == 1280
    bits = []
    for z in responses:
        packed = (1 << 19) - z
        assert 0 <= packed < 1 << 20
        bits.extend((packed >> i) & 1 for i in range(20))
    payload = bytes(sum(bits[i + j] << j for j in range(8)) for i in range(0, len(bits), 8))
    return bytes(range(48)) + payload + hint_encoding(rows)


def observed(circuit, witness, *, words=(), byte_strings=(), flags=()):
    """Read many outputs in one independent trace pass; no comparison gates."""
    indices = [tuple(b.index for b in word) for word in words]
    for data in byte_strings:
        indices.extend(
            tuple(b.index for b in reversed(data[i : i + 8])) for i in range(0, len(data), 8)
        )
    indices.extend((flag.index,) for flag in flags)
    result = trace_words(circuit.serialised, witness, indices)
    offset = len(words)
    strings = []
    for data in byte_strings:
        count = len(data) // 8
        strings.append(bytes(x & 255 for x in result[offset : offset + count]))
        offset += count
    return result[: len(words)], tuple(strings), tuple(x & 1 for x in result[offset:])
