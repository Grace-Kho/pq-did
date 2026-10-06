"""Versioned, bounded LOCAL containers. No pickle, dynamic imports or wire changes."""

from dataclasses import fields

from pqdid.issuance import SessionPhase
from pqdid.recovery_records import RECORD_TYPES, Role

CAP = 65536
TYPES = (*RECORD_TYPES, Role, SessionPhase)


class Unavailable(Exception):
    """Fixed public failure labels; never include private SQL/payload diagnostics."""


def require(ok, reason="invalid-local-record"):
    if not ok:
        raise Unavailable(reason)


def encode(value):
    result = bytearray(b"PQL1")
    nodes = 0

    def put(data):
        require(len(result) + len(data) <= CAP, "payload-cap")
        result.extend(data)

    def visit(item, depth=0):
        nonlocal nodes
        nodes += 1
        require(nodes <= 8192 and depth <= 16, "structure-cap")
        kind = type(item)
        if kind is bytes:
            require(len(item) <= CAP, "payload-cap")
            put(b"b" + len(item).to_bytes(4))
            put(item)
        elif kind is int:
            require(0 <= item < 1 << 64)
            put(b"i" + item.to_bytes(8))
        elif kind is bool:
            put(b"t" if item else b"f")
        elif item is None:
            put(b"n")
        elif kind is tuple:
            require(len(item) <= 8192)
            put(b"(" + len(item).to_bytes(4))
            for child in item:
                visit(child, depth + 1)
        elif kind in (Role, SessionPhase):
            put(b"e" + bytes([TYPES.index(kind), list(kind).index(item)]))
        elif kind in RECORD_TYPES:
            put(b"r" + bytes([TYPES.index(kind)]))
            for field in fields(item):
                visit(getattr(item, field.name), depth + 1)
        else:
            raise Unavailable("unsupported-local-type")

    visit(value)
    return bytes(result)


def decode(data):
    require(type(data) is bytes and len(data) <= CAP and data[:4] == b"PQL1")
    offset, nodes = 4, 0

    def take(count):
        nonlocal offset
        require(offset + count <= len(data), "truncated-local-record")
        value = data[offset : offset + count]
        offset += count
        return value

    def visit(depth=0):
        nonlocal nodes
        nodes += 1
        require(nodes <= 8192 and depth <= 16, "structure-cap")
        tag = take(1)
        if tag == b"b":
            return take(int.from_bytes(take(4)))
        if tag == b"i":
            return int.from_bytes(take(8))
        if tag in (b"n", b"t", b"f"):
            return {b"n": None, b"t": True, b"f": False}[tag]
        if tag == b"(":
            count = int.from_bytes(take(4))
            require(count <= 8192 - nodes, "structure-cap")
            return tuple(visit(depth + 1) for _ in range(count))
        if tag in (b"r", b"e"):
            index = int.from_bytes(take(1))
            require(index < len(TYPES))
            kind = TYPES[index]
            if tag == b"e":
                require(kind in (Role, SessionPhase))
                index = int.from_bytes(take(1))
                require(index < len(list(kind)))
                return list(kind)[index]
            require(kind in RECORD_TYPES)
            return kind(*(visit(depth + 1) for _ in fields(kind)))
        raise Unavailable("unknown-local-tag")

    result = visit()
    require(offset == len(data), "trailing-local-data")
    return result
