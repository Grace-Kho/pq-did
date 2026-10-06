"""Eight analysis checks, independent numerical routes; no production execution."""

# ruff: noqa: E402

import ast
import json
import operator
import sys
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
sys.path.insert(0, str(P / "analysis/concrete_security"))
import security_bounds as bounds


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def exact(row):
    return Fraction(int(row["numerator"]), int(row["denominator"]))


def read(name):
    return json.loads((D / name).read_text())


def profile():
    recorded = json.loads((P / "analysis/concrete_security/security_profile.json").read_text())
    active = json.loads((P / "configs/suite.json").read_text())["confirmed"]
    reference = recorded["manuscript_construction"]
    require(reference["suite"] == active["suite"]["identifier_ascii"], "suite")
    require(
        reference["signature"]["roles"] == active["signature"]["external_contexts_ascii"], "roles"
    )
    for key in ("public_key_bytes", "expanded_secret_key_bytes", "signature_bytes"):
        require(reference["signature"][key] == active["signature"][key], key)
    env = {}
    operations = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.FloorDiv: operator.floordiv,
        ast.LShift: operator.lshift,
    }

    def constant(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name):
            return env[node.id]
        if isinstance(node, ast.BinOp) and type(node.op) in operations:
            return operations[type(node.op)](constant(node.left), constant(node.right))
        raise ValueError("non-constant profile extraction")

    wanted = {
        "_Q": "q",
        "_N": "n",
        "_K": "k",
        "_L": "l",
        "_D": "d",
        "_TAU": "tau",
        "_OMEGA": "omega",
        "_GAMMA1": "gamma1",
        "_GAMMA2": "gamma2",
        "_BETA": "beta",
    }
    for node in ast.parse((P / "src/pqdid/bounded_mldsa.py").read_text()).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                env[name] = constant(node.value)
    require(set(env) == set(wanted), "complete constant inventory")
    for key, target in wanted.items():
        require(env[key] == reference["signature"][target], target)
    require(
        reference["holder_secret_bits"]
        == 8 * active["instance_and_random_values"]["holder_secret_bytes"],
        "holder bits",
    )
    require(
        recorded["target"]["overall_quantum_bits_supported"] is None, "unsupported overall number"
    )
    require(recorded["new_proofs"] == recorded["new_zkvm_executions"] == 0, "execution prohibition")


def tails():
    # Recurrence starts at probability zero successes, independently of comb/sum.
    def recurrence(n, p, k):
        term = (1 - p) ** n
        total = term
        for i in range(1, k + 1):
            term *= Fraction(n - i + 1, i) * p / (1 - p)
            total += term
        return total

    rows = read("bounds.json")["betas"]
    for key, n, p, k in [
        ("T", 342, Fraction(8380417, 2**23), 255),
        ("B", 1024, Fraction(9, 16), 255),
        ("C", 248, Fraction(13, 16), 48),
    ]:
        require(recurrence(n, p, k) == exact(rows[key]), "independent tail " + key)
    require(exact(rows["S"]) == Fraction(41**1024, 51**1024), "signing proxy")
    require(bounds.binomial_cdf(4, Fraction(1, 2), 1) == Fraction(5, 16), "small CDF")
    require(bounds.binomial_cdf(4, Fraction(0), 0) == 1, "p zero")
    require(bounds.binomial_cdf(4, Fraction(1), 3) == 0, "p one")
    require(bounds.binomial_cdf(4, Fraction(1), 4) == 1, "all successes")


def square_roots():
    for value in [Fraction(0), Fraction(1), Fraction(2), Fraction(3, 7), Fraction(3, 2**512)]:
        upper = bounds.sqrt_upper(value)
        require(upper**2 >= value, "root upper")
        if upper:
            require((upper - Fraction(1, 2**512)) ** 2 < value, "minimal dyadic ceiling")


def independent_rows():
    for row in read("bounds.json")["rows"]:
        q, n = int(row["Q"]), row["N"]
        # Two precision levels, direct Decimal operations, not helper formulas.
        values = []
        for precision in (120, 160):
            with localcontext() as context:
                context.prec = precision
                ex = Decimal(22 * 1440 + 60) * q**3 / Decimal(2) ** 1024 + 20 * Decimal(q) ** 2 * (
                    (Decimal(2) / 3) ** 480 + Decimal(2) ** -544
                )
                zk = (
                    Decimal(n)
                    * 481
                    * ((Decimal(q) / Decimal(2) ** 512).sqrt() + Decimal(q) / Decimal(2) ** 513)
                    + Decimal(n) * 960 * q / Decimal(2) ** 256
                )
                values.append((ex, zk))
        for index, name in enumerate(("epsilon_ex", "delta_zk_upper")):
            result = row["terms"][name]
            fraction = exact(result)
            with localcontext() as context:
                context.prec = 150
                independent = values[-1][index]
                require(
                    abs(values[0][index] / independent - 1) < Decimal("1e-115"),
                    "precision stability",
                )
                require(
                    abs(Decimal(fraction.numerator) / fraction.denominator / independent - 1)
                    < Decimal("1e-140"),
                    "independent formula",
                )
            k = result["strict_power_of_two_upper_exponent"]
            require(fraction < Fraction(1, 2**k), "strict exact claimed bound")
            require(fraction >= Fraction(1, 2 ** (k + 1)), "tight integer annotation")


def modulo_mapping():
    for repetitions, bits in [(1, 4), (2, 8), (3, 10)]:
        counts = [0] * 3**repetitions
        for word in range(2**bits):
            counts[word % len(counts)] += 1
        require(sum(counts) == 2**bits, "all challenge words accounted")
        require(max(counts) == (2**bits + len(counts) - 1) // len(counts), "max vector mass")
        bad_set = sum(sorted(counts, reverse=True)[: 2**repetitions])
        require(
            Fraction(bad_set, 2**bits)
            <= Fraction(2, 3) ** repetitions + Fraction(2**repetitions, 2**bits),
            "weighted bad-set bound",
        )
    row = read("bounds.json")["modulo"]
    require(
        exact(row["maximum_vector_probability"]) <= Fraction(1, 3**480) + Fraction(1, 2**1024),
        "full-profile point mass",
    )


def aggregation():
    first, second = (2, 3, 5, 7), (11, 13, 17, 19)
    total = bounds.cap_counts(*(a + b for a, b in zip(first, second, strict=True)))
    for key, value in total.items():
        require(
            value == bounds.cap_counts(*first)[key] + bounds.cap_counts(*second)[key],
            "linear union accounting",
        )
    require(bounds.read_nonce_bound(0) == bounds.read_nonce_bound(1) == 0, "no pairs")
    require(bounds.read_nonce_bound(2) == Fraction(1, 2**256), "one pair")
    require(
        bounds.read_nonce_bound(2**32) == exact(read("bounds.json")["nonce_q_2pow32"]), "nonce row"
    )
    require(
        bounds.extraction_lower(Fraction(1, 2), [Fraction(1, 8), Fraction(1, 4)]) == Fraction(1, 8),
        "lower bound direction",
    )


def domains():
    require(bounds.probability(-1) == 0 and bounds.probability(2) == 1, "probability clipping")
    require(bounds.extraction_lower(Fraction(1, 8), [Fraction(1, 4)]) == 0, "extraction clipping")
    require(bounds.proof_terms(2**1024, 2**128)["epsilon_ex"] == 1, "large budget clipping")
    for function, args in [
        (bounds.proof_terms, (0, 1)),
        (bounds.proof_terms, (True, 1)),
        (bounds.proof_terms, (1, -1)),
        (bounds.probability, (0.1,)),
        (bounds.binomial_cdf, (2049, Fraction(1, 2), 2)),
        (bounds.binomial_cdf, (4, Fraction(2), 1)),
        (bounds.binomial_cdf, (4, Fraction(1, 2), 5)),
        (bounds.sqrt_upper, (Fraction(-1),)),
        (bounds.extraction_lower, (2, [])),
    ]:
        try:
            function(*args)
        except ValueError:
            continue
        raise AssertionError("invalid input accepted")


def displays():
    record = read("bounds.json")
    rows = [*record["betas"].values(), record["nonce_q_2pow32"]]
    rows += [value for row in record["rows"] for value in row["terms"].values()]
    for row in rows:
        require(Fraction(Decimal(row["decimal_upper"])) >= exact(row), "display rounded down")
    require(record["Bmax_bytes"] == 2 * (2**32 - 1) + 2**18, "runtime input bound")
    require(record["auth_gate_independent_proof_bytes"] == 5363104, "byte accounting")
    require(record["unresolved_cap_addend"], "tail discrepancy retained")


if __name__ == "__main__":
    results = []
    for check in [
        profile,
        tails,
        square_roots,
        independent_rows,
        modulo_mapping,
        aggregation,
        domains,
        displays,
    ]:
        try:
            check()
        except Exception as error:
            results.append(
                {
                    "name": check.__name__,
                    "passed": False,
                    "failure": type(error).__name__ + ": " + str(error),
                }
            )
            (D / "calculation-checks.json").write_text(json.dumps(results, indent=2) + "\n")
            raise
        results.append({"name": check.__name__, "passed": True})
    (D / "calculation-checks.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"independent_checks_passed": len(results), "production_tests_repeated": 0}))
