"""Complete twenty-level, same-identifier private SHA3-384 non-revocation path."""

from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.keccak import sha3_384
from pqdid.circuits.parsing import check_bytes, equal_bytes, public_bytes
from pqdid.circuits.signature_inputs import _record
from pqdid.codec import encode_uint
from pqdid.hash_domain import encode_metadata


def non_revocation(scope: Scope, prepared, identifier, siblings):
    """No independent rid/root advice: consume the parsed credential's own wires.

    Bits are LSB-first for the identifier and MSB-first inside hash bytes. The
    public zero leaf is independently recomputed by prepare_public; a prover
    cannot supply an initial leaf/status. Twenty private sibling strings remain
    inside the relation, including direction, level framing and the final root.
    """
    e = scope.e
    w.check_word(e, identifier, 64)
    if type(siblings) is not tuple or len(siblings) != 20:
        raise ValueError("exactly twenty symbolic sibling strings required")
    scope.require(w.less64(e, identifier, w.constant(e, 1 << 20, 64)))
    pp = prepared.parameters
    current = public_bytes(e, prepared.zero_leaf)
    for j, sibling in enumerate(siblings):
        check_bytes(e, sibling, length=48)
        left = tuple(e.mux(identifier[j], a, b) for a, b in zip(current, sibling, strict=True))
        right = tuple(e.mux(identifier[j], a, b) for a, b in zip(sibling, current, strict=True))
        message = _record(
            e,
            b"node",
            (
                public_bytes(e, pp.suite),
                public_bytes(e, encode_metadata(pp.domain)),
                public_bytes(e, encode_uint(j + 1, 1)),
                left,
                right,
            ),
        )
        current = sha3_384(e, message)
    matches = equal_bytes(e, current, public_bytes(e, prepared.statement.state.root))
    scope.require(matches)
    return current, matches
