"""Canonical protocol bytes (VII, p. 14), not FIPS internal representations.

Record framing checks tags/counts/lengths. Typed callers must additionally validate
field domains, nested objects and instance agreement; framing is not verification.
"""

from collections.abc import Sequence

MAX_FIELD_BYTES = (1 << 32) - 1
SIBLING_BYTES = 48
PATH_SIBLINGS = 20
PATH_BYTES = SIBLING_BYTES * PATH_SIBLINGS


class EncodingError(ValueError):
    """An input is outside the canonical encoding or its declared domain."""


# Literal tags and arities from VII-A.1–A.8. Variable lists contribute one field
# per element; schema/policy typed decoders enforce the relationship to contents.
_ARITIES = {
    "iref": (3, 3),
    "field": (3, 3),
    "schema": (5, 19),
    "parameters": (6, 6),
    "meta": (2, 2),
    "rstate": (4, 4),
    "rref": (3, 3),
    "eq": (2, 2),
    "range": (3, 3),
    "policy": (1, 33),
    "context": (8, 8),
    "leaf": (3, 3),
    "node": (5, 5),
    "state": (4, 4),
    "did-id": (4, 4),
    "did-body": (7, 7),
    "did-record": (2, 2),
    "did-chain": (0, 1 << 16),
    "did-read": (6, 6),
    "holder": (3, 3),
    "binding": (2, 2),
    "cred": (4, 4),
    "certificate": (2, 2),
    "credential": (5, 5),
    "enrol-statement": (7, 7),
    "auth-statement": (6, 6),
    "current": (4, 4),
    "revreq": (5, 5),
    "update": (6, 6),
    "rupdate": (5, 5),
    "view": (7, 7),
    "challenge": (5, 5),
}


def require_bytes(value: bytes) -> bytes:
    """Require immutable bytes; never implicitly encode text or mutable buffers."""
    if type(value) is not bytes:
        raise EncodingError("expected immutable bytes")
    return value


def require_uint(value: int, bits: int) -> int:
    """Reject bool as well as negative, non-integer and overflowing values."""
    if type(bits) is not int or bits < 1:
        raise EncodingError("invalid unsigned integer width")
    if type(value) is not int or value < 0 or value.bit_length() > bits:
        raise EncodingError("value outside unsigned integer domain")
    return value


def _width(width: int) -> None:
    if type(width) is not int or not 1 <= width <= MAX_FIELD_BYTES:
        raise EncodingError("invalid byte width")


def encode_uint(value: int, width: int) -> bytes:
    """Encode [value]_width in unsigned big-endian protocol order."""
    _width(width)
    return require_uint(value, 8 * width).to_bytes(width, "big")


def decode_uint(encoded: bytes, width: int) -> int:
    _width(width)
    if len(require_bytes(encoded)) != width:
        raise EncodingError("incorrect integer length")
    return int.from_bytes(encoded, "big")


class _Reader:
    def __init__(self, encoded: bytes):
        self.data = memoryview(require_bytes(encoded))
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, length: int) -> memoryview:
        # Check before slicing/copying or advancing. A declared size never drives
        # an allocation until the complete corresponding input has been checked.
        if length > self.remaining:
            raise EncodingError("truncated input or inconsistent length")
        start = self.offset
        self.offset += length
        return self.data[start : self.offset]

    def word(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def field(self) -> memoryview:
        return self.take(self.word())

    def finish(self) -> None:
        if self.remaining:
            raise EncodingError("trailing bytes")


def encode_length_prefixed(payload: bytes) -> bytes:
    require_bytes(payload)
    if len(payload) > MAX_FIELD_BYTES:
        raise EncodingError("length-prefixed field exceeds L")
    return encode_uint(len(payload), 4) + payload


def decode_length_prefixed(encoded: bytes) -> bytes:
    reader = _Reader(encoded)
    payload = reader.field()
    reader.finish()
    return bytes(payload)


def _tag(tag: str) -> bytes:
    if type(tag) is not str or tag not in _ARITIES:
        raise EncodingError("unknown protocol tag")
    return tag.encode("ascii")


def _count(tag: str, count: int) -> None:
    low, high = _ARITIES[tag]
    if type(count) is not int or not low <= count <= high:
        raise EncodingError("incorrect record field count")


def encode_record(tag: str, fields: Sequence[bytes]) -> bytes:
    """Frame already-encoded fields once; validate literal tag and arity."""
    tag_bytes = _tag(tag)
    if not isinstance(fields, (tuple, list)):
        raise EncodingError("record fields must be a tuple or list")
    _count(tag, len(fields))
    return b"".join(
        [encode_length_prefixed(tag_bytes), encode_uint(len(fields), 4)]
        + [encode_length_prefixed(field) for field in fields]
    )


def decode_record(
    encoded: bytes, expected_tag: str, *, expected_count: int | None = None
) -> tuple[bytes, ...]:
    """Reject other tags, invalid arity, inconsistent lengths and trailing bytes.

    Pass expected_count when a variable-arity object's count is already known.
    Return payloads without recursively interpreting their contents.
    """
    tag_bytes = _tag(expected_tag)
    reader = _Reader(encoded)
    if reader.field() != tag_bytes:
        raise EncodingError("incorrect record tag")
    count = reader.word()
    _count(expected_tag, count)
    if expected_count is not None:
        _count(expected_tag, expected_count)
        if count != expected_count:
            raise EncodingError("unexpected record field count")
    if count > reader.remaining // 4:
        raise EncodingError("field count exceeds available length prefixes")
    fields = tuple(reader.field() for _ in range(count))
    reader.finish()
    return tuple(bytes(field) for field in fields)


def pack_sibling_path(siblings: Sequence[bytes]) -> bytes:
    """SPEC-001: s0 || ... || s19, without per-sibling framing."""
    if not isinstance(siblings, (tuple, list)) or len(siblings) != PATH_SIBLINGS:
        raise EncodingError("path must contain exactly twenty siblings")
    for sibling in siblings:
        if len(require_bytes(sibling)) != SIBLING_BYTES:
            raise EncodingError("sibling must contain exactly 48 bytes")
    return b"".join(siblings)


def unpack_sibling_path(encoded: bytes) -> tuple[bytes, ...]:
    if len(require_bytes(encoded)) != PATH_BYTES:
        raise EncodingError("path must contain exactly 960 bytes")
    return tuple(encoded[i : i + SIBLING_BYTES] for i in range(0, PATH_BYTES, SIBLING_BYTES))
