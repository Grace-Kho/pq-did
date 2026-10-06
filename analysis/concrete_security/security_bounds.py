"""Analysis-only Section VIII arithmetic; no cryptographic/profile/backend calls.

Probability comparisons use exact fractions. Square roots are enclosed by a
dyadic ceiling whose inequality is checked with integers. Decimal displays are
rounded upwards; logarithms are explanatory approximations, never decisions.
"""

import json
from decimal import ROUND_CEILING, Decimal, localcontext
from fractions import Fraction
from math import comb, isqrt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/data/s2_concrete_security_assessment_1"
REPETITIONS = 480
ORACLE_BITS = 1024
SALT_BITS = 512


def integer(value, maximum, *, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("outside bounded integer domain")
    return value


def probability(value):
    if type(value) not in (int, Fraction):
        raise ValueError("exact integer/fraction required")
    return min(Fraction(1), max(Fraction(0), value))


def binomial_cdf(n, p, k):
    integer(n, 2048)
    integer(k, n, minimum=-1)
    if type(p) is not Fraction or not 0 <= p <= 1 or p.denominator > 1 << 24:
        raise ValueError("invalid bounded binomial probability")
    # Common denominator: no rounded intermediate tails and no cancellation.
    a, b = p.numerator, p.denominator
    numerator = sum(comb(n, i) * a**i * (b - a) ** (n - i) for i in range(k + 1))
    return Fraction(numerator, b**n)


def sqrt_upper(value, bits=512):
    if type(value) not in (Fraction, int) or value < 0:
        raise ValueError("non-negative exact square-root input required")
    integer(bits, 1024, minimum=1)
    value = Fraction(value)
    scaled = value.numerator << (2 * bits)
    root = isqrt(scaled // value.denominator)
    if root * root * value.denominator < scaled:
        root += 1
    upper = Fraction(root, 1 << bits)
    assert upper * upper >= value
    if root:
        assert Fraction(root - 1, 1 << bits) ** 2 < value
    return upper


def proof_terms(q, proofs):
    integer(q, 1 << 1024, minimum=1)
    integer(proofs, 1 << 128)
    base = Fraction(2, 3) ** REPETITIONS
    modulo_slack = Fraction(1, 1 << (ORACLE_BITS - REPETITIONS))
    p_star = base + modulo_slack
    collision = Fraction((22 * 3 * REPETITIONS + 60) * q**3, 1 << ORACLE_BITS)
    challenge = 20 * q**2 * p_star
    alpha = sqrt_upper(Fraction(q, 1 << SALT_BITS)) + Fraction(q, 1 << (SALT_BITS + 1))
    programming = proofs * (REPETITIONS + 1) * alpha
    hidden_salt = Fraction(proofs * 2 * REPETITIONS * q, 1 << (SALT_BITS // 2))
    return {
        "base_repetition_error": base,
        "modulo_slack": modulo_slack,
        "p_star": p_star,
        "extraction_collision_term": collision,
        "extraction_challenge_term": challenge,
        "epsilon_ex": probability(collision + challenge),
        "alpha_upper": alpha,
        "privacy_programming_upper": programming,
        "privacy_hidden_salt_term": hidden_salt,
        "delta_zk_upper": probability(programming + hidden_salt),
    }


def cap_counts(keygens, signs, verifies, expansions):
    for n in (keygens, signs, verifies, expansions):
        integer(n, 1 << 128)
    return {
        "T": 30 * (keygens + signs + verifies + expansions),
        "B": 11 * keygens,
        "C": 1024 * signs + verifies,
        "S": signs,
    }


def read_nonce_bound(count):
    integer(count, 1 << 128)
    return probability(Fraction(count * (count - 1), 1 << 257))


def extraction_lower(acceptance, losses):
    if any(type(x) not in (int, Fraction) or not 0 <= x <= 1 for x in [acceptance, *losses]):
        raise ValueError("probability arguments required")
    return probability(acceptance - sum(losses))


def display(value):
    value = Fraction(value)
    with localcontext() as context:
        context.prec = 90
        context.rounding = ROUND_CEILING
        decimal = Decimal(value.numerator) / Decimal(value.denominator)
        upper = f"{decimal:.16E}"
        approximate = str(-(decimal.ln() / Decimal(2).ln())) if value else None
    exponent = None
    if 0 < value < 1:
        exponent = value.denominator.bit_length() - value.numerator.bit_length()
        while value >= Fraction(1, 1 << exponent):
            exponent -= 1
        while value < Fraction(1, 1 << (exponent + 1)):
            exponent += 1
        assert value < Fraction(1, 1 << exponent)
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "decimal_upper": upper,
        "negative_log2_approximate": approximate,
        "strict_power_of_two_upper_exponent": exponent,
    }


def calculate():
    betas = {
        "T": binomial_cdf(342, Fraction(8380417, 1 << 23), 255),
        "B": binomial_cdf(1024, Fraction(9, 16), 255),
        "C": binomial_cdf(248, Fraction(13, 16), 48),
        "S": Fraction(41, 51) ** 1024,
    }
    thresholds = {"T": 594, "B": 304, "C": 325, "S": 322}
    rows = []
    for q_bits in (64, 80):
        terms = proof_terms(1 << q_bits, 1 << 32)
        rows.append(
            {
                "Q": str(1 << q_bits),
                "Q_log2": q_bits,
                "N": 1 << 32,
                "terms": {key: display(value) for key, value in terms.items()},
            }
        )
    space = 3**REPETITIONS
    max_mass = Fraction(((1 << ORACLE_BITS) + space - 1) // space, 1 << ORACLE_BITS)
    result = {
        "package": "S2-CONCRETE-SECURITY-ASSESSMENT-1",
        "authority": "Manuscript VIII-A/C/D/E; formulas in implementation_spec R-049--051",
        "interpretation": (
            "Ideal-QROM and conditional sampler arithmetic only; no overall attack-cost claim"
        ),
        "method": (
            "exact rational arithmetic; integer-certified square-root ceiling; "
            "90-digit upward decimal display"
        ),
        "rows": rows,
        "betas": {
            key: {
                **display(value),
                "manuscript_threshold": thresholds[key],
                "threshold_holds": value < Fraction(1, 1 << thresholds[key]),
            }
            for key, value in betas.items()
        },
        "nonce_q_2pow32": display(read_nonce_bound(1 << 32)),
        "aggregate_cap_model_only_C_2pow64": display(Fraction(1 << 64, 1 << 304)),
        "unresolved_cap_addend": (
            "sum of Delta_tail across distinct reduction simulations; not set to zero"
        ),
        "modulo": {
            "challenge_space": str(space),
            "maximum_vector_probability": display(max_mass),
            "accepting_vectors_without_extraction_at_most": str(1 << REPETITIONS),
            "point_mass_inequality_holds": max_mass
            <= Fraction(1, space) + Fraction(1, 1 << ORACLE_BITS),
        },
        "Bmax_bytes": 2 * ((1 << 32) - 1) + (1 << 18),
        "auth_gate_independent_proof_bytes": 64 + 480 * (515 + 2 * ((42632 + 7) // 8)),
        "one_million_AND_gates_extra_bytes": 240 * 1000000,
        "new_proofs": 0,
        "new_zkvm_executions": 0,
        "estimator_runs": 0,
    }
    return result


if __name__ == "__main__":
    result = calculate()
    path = EVIDENCE / "bounds.json"
    with path.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(path.relative_to(ROOT)),
                "betas": {k: v["negative_log2_approximate"] for k, v in result["betas"].items()},
                "rows": [
                    {
                        "Q_log2": r["Q_log2"],
                        "extraction": r["terms"]["epsilon_ex"]["negative_log2_approximate"],
                        "privacy": r["terms"]["delta_zk_upper"]["negative_log2_approximate"],
                    }
                    for r in result["rows"]
                ],
            }
        )
    )
