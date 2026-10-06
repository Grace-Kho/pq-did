"""Analysis-only framing and theorem-monomial arithmetic; no cryptographic execution."""

import json
from fractions import Fraction
from pathlib import Path

D = Path(__file__).resolve().parent
L = (1 << 32) - 1
BMAX = 2 * L + (1 << 18)
REPETITIONS = 480
A_BYTES = REPETITIONS * (3 + 3 * 128)


def natural(value):
    if type(value) is not int or value < 0:
        raise ValueError("non-negative integer required")
    return value


def view_bytes(statement, witness, gates, kind):
    if kind not in {"enrol", "auth"}:
        raise ValueError("unknown kind")
    s = natural(statement)
    v = (natural(witness) + 2 * natural(gates) + 7) // 8
    if s > L or v > L:
        raise ValueError("canonical field exceeds L")
    return s + v + 120 + len(kind)


def challenge_bytes(statement, kind):
    if kind not in {"enrol", "auth"} or natural(statement) > L:
        raise ValueError("invalid canonical statement/kind")
    return statement + A_BYTES + 114 + len(kind)


def absorb_blocks(message_bytes, rate_bytes=136):
    if type(rate_bytes) is not int or rate_bytes < 1:
        raise ValueError("positive byte rate required")
    return natural(message_bytes) // rate_bytes + 1


def monomial_exponents(logq, logell, minimum):
    # These exponents exclude unspecified constants. They are NOT advantage bounds.
    return [
        str(2 * Fraction(logell) + Fraction(9, 2) * logq - Fraction(minimum, 2)),
        str(3 * Fraction(logell) + Fraction(5, 4) * logq - Fraction(minimum, 4)),
    ]


def record():
    maximum_view = 2 * L + 125
    maximum_challenge = challenge_bytes(L, "enrol")
    return {
        "package": "S3-OUTER-HASH-SECURITY-REVIEW-1",
        "kind": "analysis only; no hash, circuit, proof or zkVM execution",
        "L_bytes": L,
        "Bmax_exclusive_bytes": BMAX,
        "A_bytes": A_BYTES,
        "view_bytes": "S + ceil((d+2*g)/8) + 120 + len(kind)",
        "challenge_bytes": "S + 185760 + 114 + len(kind)",
        "maximum_canonical_view_bytes": maximum_view,
        "maximum_canonical_challenge_bytes": maximum_challenge,
        "maximum_canonical_absorb_blocks": absorb_blocks(maximum_view),
        "Bmax_minus_one_absorb_blocks": absorb_blocks(BMAX - 1),
        "maximum_challenge_absorb_blocks": absorb_blocks(maximum_challenge),
        "auth_g_zero_view_bytes_minus_S": view_bytes(0, 42632, 0, "auth"),
        "honest_outer_calls": {"prove": 1441, "check": 961, "one_each": 2402},
        "canonical_length_power_of_two_envelope": 26,
        "extra_squeeze_permutations_1024_output_bits": 0,
        "formal_theorem": "ACMT arXiv:2504.16887v2 Theorem 7.22",
        "monomials": ["ell^2*q^(9/2)*2^(-min(r,c)/2)", "ell^3*q^(5/4)*2^(-min(r,c)/4)"],
        "scaling_only": [
            {
                "min_rate_capacity": m,
                "log2_q": q,
                "log2_ell": e,
                "log2_monomials": monomial_exponents(q, e, m),
            }
            for m, e in [(512, 0), (512, 26), (800, 27)]
            for q in [64, 80]
        ],
        "scaling_is_probability_bound": False,
        "numerical_instantiation_advantage": None,
        "assumptions_for_scaling": (
            "optimistically q=Q; ell=1 or stated envelope; constants omitted"
        ),
        "balanced_option": {
            "adopted": False,
            "rate_bits": 800,
            "capacity_bits": 800,
            "maximum_absorb_blocks": absorb_blocks(BMAX - 1, 100),
            "squeeze_blocks": 2,
            "extra_squeeze_permutations": 1,
            "large_message_permutation_ratio": "136/100 = 1.36",
        },
        "unknowns": {
            name: None
            for name in [
                "full_auth_AND_gates",
                "full_auth_circuit_size",
                "actual_auth_statement_bytes",
                "adversarial_max_message_blocks",
                "direct_permutation_queries",
                "internal_permutation_queries",
                "simulator_F_queries",
                "simulator_runtime",
                "primitive_correlated_advice",
                "concrete_Keccak_instantiation_loss",
                "knowledge_composition_loss",
                "privacy_composition_loss",
            ]
        },
        "previous_bounds": (
            "docs/data/s2_concrete_security_assessment_1/bounds.json; reused unchanged"
        ),
    }


if __name__ == "__main__":
    output = record()
    (D / "query-mapping.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"mapping_written": True, "numerical_security_claim": False}))
