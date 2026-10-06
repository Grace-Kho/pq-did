"""Generate NEW exact-integer boundary fixtures without production imports."""

import hashlib
import json
from pathlib import Path

from scalar_oracle import GAMMA2, Q, centred, decompose, floor_pair, use_hint

ROOT = Path(__file__).resolve().parents[2]
MIN, MAX = -(1 << 63), (1 << 63) - 1
DIVIDENDS = (MIN, MIN + 1, -Q - 1, -Q, -Q + 1, -17, -2, -1, 0, 1, 2, 17, Q - 1, Q, Q + 1, MAX)
DIVISORS = (1, 2, 16, 2 * GAMMA2, Q, MAX)
DECOMPOSE = sorted(
    {
        MIN,
        MAX,
        -Q,
        -1,
        0,
        1,
        Q - 2,
        Q - 1,
        Q,
        Q + 1,
        *[k * 2 * GAMMA2 + GAMMA2 + delta for k in (0, 1, 7, 14, 15) for delta in (-1, 0, 1)],
    }
)
data = {
    "meaning": "Synthetic independent exact-integer expectations; not official FIPS vectors",
    "oracle": "Fractions/floor, centred interval and independent nearest-multiple decomposition",
    "source_sha256": {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (Path(__file__), Path(__file__).with_name("scalar_oracle.py"))
    },
    "division": [
        {
            "dividend": a,
            "divisor": b,
            "quotient": floor_pair(a, b)[0],
            "remainder": floor_pair(a, b)[1],
        }
        for b in DIVISORS
        for a in DIVIDENDS
    ],
    "centred": [
        {"value": a, "modulus": b, "expected": centred(a, b)}
        for b in (1, 2, 16, 2 * GAMMA2, Q)
        for a in (MIN, -b, -(b // 2) - 1, -(b // 2), -1, 0, b // 2, b // 2 + 1, b - 1, b, MAX)
    ],
    "decompose": [
        {
            "value": a,
            "high": decompose(a)[0],
            "low": decompose(a)[1],
            "hint0": use_hint(0, a),
            "hint1": use_hint(1, a),
        }
        for a in DECOMPOSE
    ],
}
if __name__ == "__main__":
    # Never overwrite an existing fixture implicitly.
    with (ROOT / "tests/fixtures/bc1_scalar_vectors.json").open("x") as target:
        target.write(json.dumps(data, indent=2) + "\n")
