"""Integer-only enrolment projections using d=256; never the auth d=42632."""

from pqdid.circuits.accounting import REPETITIONS, _count
from pqdid.codec import MAX_FIELD_BYTES


def enrolment_view_bytes(and_gates: int) -> int:
    _count(and_gates)
    return (256 + 2 * and_gates + 7) // 8


def enrolment_proof_bytes(and_gates: int) -> int:
    """Calculated transcript size, not an actually generated proof."""
    return 64 + REPETITIONS * (515 + 2 * enrolment_view_bytes(and_gates))


def enrolment_count_admitted(and_gates: int) -> bool:
    return enrolment_view_bytes(and_gates) <= MAX_FIELD_BYTES
