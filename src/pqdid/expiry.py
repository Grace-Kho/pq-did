"""SPEC-002: unsigned POSIX seconds and the strict now < texp predicate.

No clock is read here. Callers must supply trusted time and later recheck atomically
before consumption; this helper supplies neither freshness nor replay protection.
"""

from pqdid.codec import decode_uint, encode_uint, require_uint


def encode_timestamp(seconds: int) -> bytes:
    return encode_uint(seconds, 8)


def decode_timestamp(encoded: bytes) -> int:
    return decode_uint(encoded, 8)


def is_unexpired(texp: int, *, now: int) -> bool:
    """Validate both integer-second timestamps; equality means expired."""
    return require_uint(now, 64) < require_uint(texp, 64)
