"""Bounded draft envelope inspection and permanently inactive proof adapter.

The caller supplies a trusted finite *synthetic* schedule for parsing experiments.
No finite authentication proof profile or query derivation is admitted here.
"""

import hashlib
import struct
from dataclasses import dataclass

from pqdid.statements import encode_auth_statement
from pqdid.verifier_state import ProofVerdict

HEADER_BYTES = 208
PROFILE = b"PQDID-AURORA-AUTH-DRAFT1/"
MAX_ENVELOPE = 1_048_576  # existing ordinary input cap, not the proposed 10 MiB proof target


def framed(tag: bytes, parts: tuple[bytes, ...]) -> bytes:
    tag = PROFILE + tag
    if len(tag) > 65535 or len(parts) > 65535:
        raise ValueError("framing limit")
    return (
        struct.pack(">H", len(tag))
        + tag
        + struct.pack(">I", len(parts))
        + b"".join(struct.pack(">Q", len(value)) + value for value in parts)
    )


def statement_tag(encoded: bytes) -> bytes:
    if type(encoded) is not bytes or len(encoded) > 65_536:
        raise ValueError("experimental statement-shape capacity")
    return hashlib.blake2b(framed(b"statement", (encoded,)), digest_size=64).digest()


def decode_field(encoded: bytes) -> int:
    if type(encoded) is not bytes or len(encoded) != 24:
        raise ValueError("field encoding must be exactly 24 bytes")
    # Every 192-bit polynomial encoding is canonical in this binary field.
    return int.from_bytes(encoded, "little")


@dataclass(frozen=True)
class Round:
    identifier: int
    roots: int
    direct_fields: int


@dataclass(frozen=True)
class Opening:
    oracle: int
    index: int
    height: int


@dataclass(frozen=True)
class ParseSchedule:
    parameter_id: bytes
    relation_id: bytes
    rounds: tuple[Round, ...]
    openings: tuple[Opening, ...]
    max_bytes: int = MAX_ENVELOPE

    def length(self):
        if (
            type(self.parameter_id) is not bytes
            or type(self.relation_id) is not bytes
            or len(self.parameter_id) != 64
            or len(self.relation_id) != 64
        ):
            raise ValueError("trusted identity length")
        if not 208 <= self.max_bytes <= MAX_ENVELOPE:
            raise ValueError("unapproved parser cap")
        if len(self.rounds) > 128 or len(self.openings) > 4096:
            raise ValueError("trusted schedule bound")
        previous = -1
        total = HEADER_BYTES + 4
        for row in self.rounds:
            values = (row.identifier, row.roots, row.direct_fields)
            if any(type(n) is not int or not 0 <= n < 2**32 for n in values):
                raise ValueError("invalid round shape")
            if row.identifier <= previous:
                raise ValueError("noncanonical trusted round order")
            previous = row.identifier
            total += 12 + 64 * row.roots + 24 * row.direct_fields
        for slot in self.openings:
            if (
                type(slot.height) is not int
                or not 0 <= slot.height <= 32
                or type(slot.index) is not int
                or not 0 <= slot.index < 2**slot.height
                or type(slot.oracle) is not int
                or not 0 <= slot.oracle < 2**32
            ):
                raise ValueError("invalid trusted opening shape")
            total += 152 + 64 * slot.height
        if total > self.max_bytes:
            raise ValueError("trusted schedule exceeds parser cap")
        return total


def parse_envelope(raw: bytes, *, schedule: ParseSchedule, encoded_statement: bytes):
    """Bounds checked before slicing; parsed fields are not verified proof evidence."""
    expected = schedule.length()
    if type(raw) is not bytes or len(raw) > schedule.max_bytes or len(raw) < HEADER_BYTES:
        raise ValueError("envelope input bound")
    if raw[:8] != b"PQDAUR01" or raw[8:12] != b"\x00\x01\x01\x00":
        raise ValueError("magic/version/kind/flags")
    if raw[12:76] != schedule.parameter_id:
        raise ValueError("trusted parameter identity mismatch")
    if raw[76:140] != schedule.relation_id:
        raise ValueError("trusted relation identity mismatch")
    if raw[140:204] != statement_tag(encoded_statement):
        raise ValueError("public statement mismatch")
    body = int.from_bytes(raw[204:208], "big")
    if body != expected - HEADER_BYTES or len(raw) != expected:
        raise ValueError("body size/truncation/trailing data")
    cursor = HEADER_BYTES
    field_count = 0
    for row in schedule.rounds:
        if struct.unpack_from(">III", raw, cursor) != (
            row.identifier,
            row.roots,
            row.direct_fields,
        ):
            raise ValueError("scheduled round/root/direct-message mismatch")
        cursor += 12 + 64 * row.roots
        for _ in range(row.direct_fields):
            decode_field(raw[cursor : cursor + 24])
            cursor += 24
            field_count += 1
    if int.from_bytes(raw[cursor : cursor + 4], "big") != len(schedule.openings):
        raise ValueError("opening closure count mismatch")
    cursor += 4
    seen = {}
    for slot in schedule.openings:
        size = 152 + 64 * slot.height
        opening = raw[cursor : cursor + size]
        decode_field(opening[:24])
        key = (slot.oracle, slot.index)
        if key in seen and opening != seen[key]:
            raise ValueError("conflicting duplicate opening")
        seen[key] = opening
        cursor += size
    if cursor != len(raw):
        raise ValueError("incomplete envelope consumption")
    return {
        "parsed": True,
        "verified": False,
        "direct_fields": field_count,
        "opening_slots": len(schedule.openings),
        "bytes": cursor,
    }


class InactiveProofAdapter:
    """Exact existing lifecycle Protocol. No configuration can enable acceptance."""

    def __init__(self, parameters):
        self._parameters = parameters

    def verify(self, statement, proof):
        try:
            encode_auth_statement(self._parameters, statement)
        except TypeError, ValueError:
            return ProofVerdict.INVALID
        if type(proof) is not bytes or not 0 < len(proof) <= MAX_ENVELOPE:
            return ProofVerdict.INVALID
        return ProofVerdict.UNSUPPORTED
