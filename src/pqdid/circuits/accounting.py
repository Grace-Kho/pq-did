"""Integer-only frozen raw authentication proof-size arithmetic, not a proof."""

from pqdid.codec import MAX_FIELD_BYTES

AUTH_INPUT_BITS = 42632
REPETITIONS = 480


def _count(and_gates: int):
    if type(and_gates) is not int or and_gates < 0:
        raise ValueError("AND-gate count must be a non-negative integer")


def authentication_proof_bytes(and_gates: int) -> int:
    """Projection only unless g is a completed full authentication circuit count.

    Component counts are neither full-circuit counts nor automatic lower bounds.
    This calculator allocates integers only, never a proof-sized buffer.
    """
    _count(and_gates)
    view_bytes = (AUTH_INPUT_BITS + 2 * and_gates + 7) // 8
    return 64 + REPETITIONS * (515 + 2 * view_bytes)


def authentication_view_bytes(and_gates: int) -> int:
    _count(and_gates)
    return (AUTH_INPUT_BITS + 2 * and_gates + 7) // 8


def authentication_count_admitted(and_gates: int) -> bool:
    """Only VII's view encoding bound; not public-domain or practical admission."""
    return authentication_view_bytes(and_gates) <= MAX_FIELD_BYTES
