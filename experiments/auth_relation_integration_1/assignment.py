"""Bounded private assignment input; ordinary proof admission remains unavailable."""

from .stream import R1CSSink, check_stream


def private_bits(payload: bytes, *, expected_bytes: int = 5329) -> bytes:
    if type(payload) is not bytes or len(payload) != expected_bytes:
        raise ValueError("private witness has wrong canonical length")
    if expected_bytes * 8 > 65_536:
        raise ValueError("partition external-input cap")
    return bytes((value >> shift) & 1 for value in payload for shift in range(7, -1, -1))


def assign_private(build, public_identity, payload, *, expected_bytes=5329, **limits):
    """Replay a trusted builder; every row is checked, no assignment file emitted."""
    sink = R1CSSink(
        public_identity,
        witness_bits=private_bits(payload, expected_bytes=expected_bytes),
        **limits,
    )
    build(sink)
    descriptor = sink.completed()
    return descriptor, check_stream(sink)
