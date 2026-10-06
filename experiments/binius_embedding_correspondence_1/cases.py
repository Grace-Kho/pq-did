"""Twenty-five fixed public synthetic fixtures; one process per counted invocation."""

import dataclasses
import hashlib
import json
import resource
import time

import encoder_model as enc
import field_model as field
import layout
import polynomial_reference as ref
import relations


def fixture_words(n, seed):
    return [((j + seed) * 0x9173A581DF216709FF3145A78DB925E3) & field.MASK for j in range(n)]


def require_rejection(action, expected_reason):
    try:
        action()
    except (ValueError, OSError) as error:
        assert expected_reason in str(error), (expected_reason, str(error))
        return {"expected": "rejection", "actual": str(error), "released": False}
    raise AssertionError("required rejection absent")


def execute(number):
    if number <= 6:
        k, m, rate = ((1, 1, 2), (2, 2, 2), (2, 2, 4), (4, 4, 2), (2, 4, 2), (4, 8, 4))[number - 1]
        spec = layout.EmbeddingSpec("synthetic-P", k, m, rate)
        logical, random, companion = (
            fixture_words(k, 3),
            fixture_words(m, 11),
            fixture_words(2 * m, 19),
        )
        physical = layout.embed(spec, spec, logical, random)
        start = time.perf_counter()
        actual, domain = enc.encode_pair(physical, companion, rate)
        model_seconds = time.perf_counter() - start
        start = time.perf_counter()
        expected, oracle_domain = ref.expected_pair(logical, random, companion, m, rate)
        reference_seconds = time.perf_counter() - start
        assert actual == expected and domain == oracle_domain
        assert layout.decode(spec, spec, physical) == logical
        assert actual[0] == random[0] and actual[1] == companion[0]
        return {
            "shape": [k, m, rate],
            "logical": logical,
            "randomness": random,
            "companion": companion,
            "physical": physical,
            "domain": domain,
            "expected": expected,
            "actual": actual,
            "model_seconds": model_seconds,
            "reference_seconds": reference_seconds,
            "encoded_payload_bytes": 16 * len(actual),
        }
    spec = layout.EmbeddingSpec("synthetic-P", 2, 4, 2)
    logical, random = fixture_words(2, 3), fixture_words(4, 11)
    if number == 7:
        physical = fixture_words(8, 31)
        physical[5] = physical[7] = 0
        decoded = layout.decode(spec, spec, physical)
        operand = fixture_words(2, 7)
        u = layout.transport_operand(spec, spec, operand)
        actual = field.dot(physical, u)
        expected = ref.dot([physical[1], physical[3]], operand)
        assert decoded == [physical[1], physical[3]] and actual == expected
        return {"physical": physical, "operand": operand, "expected": expected, "actual": actual}
    if number == 8:
        wrong = dataclasses.replace(spec, data_parity=0)
        return require_rejection(lambda: layout.embed(wrong, spec, logical, random), "descriptor")
    if number == 9:
        return require_rejection(
            lambda: layout.eval_transported_operand(
                spec, spec, logical, fixture_words(3, 2), "binding-order"
            ),
            "order",
        )
    if number == 10:
        wrong = dataclasses.replace(spec, m=3)
        return require_rejection(
            lambda: layout.embed(wrong, wrong, logical, [1, 2, 3]), "dimensions"
        )
    if number == 11:
        return require_rejection(
            lambda: layout.embed_from_entropy(
                spec, spec, logical, lambda requested: [7] * (requested - 1)
            ),
            "length",
        )
    if number == 12:
        wrong = dataclasses.replace(spec, oracle_id="different-oracle")
        return require_rejection(lambda: layout.embed(wrong, spec, logical, random), "descriptor")
    if number == 13:
        physical = layout.embed(spec, spec, logical, random)
        physical[7] = 1
        return require_rejection(lambda: layout.decode(spec, spec, physical), "padding")
    if number in (14, 15):
        m = 2 if number == 14 else 4
        spec = dataclasses.replace(spec, m=m)
        point = fixture_words(m.bit_length(), 37)
        actual = layout.eval_transported_operand(spec, spec, logical, point)
        independent_u = [0, logical[0], 0, logical[1]] + [0] * (2 * m - 4)
        expected = ref.evaluate_table(independent_u, point)
        assert actual == expected
        return {"point": point, "operand": independent_u, "expected": expected, "actual": actual}
    if number == 16:
        actual = layout.terminal_operand(spec, spec, 1)
        expected = [0, 0, 0, 1, 0, 0, 0, 0]
        assert actual == expected
        return {
            "oracle_id": spec.oracle_id,
            "logical_index": 1,
            "physical_index": 3,
            "expected": expected,
            "actual": actual,
        }
    if number in (17, 18):
        address, variable = 0xA631, 7
        point = [(address >> i) & 1 for i in range(16)]
        y = 0x123456789ABCDEF
        point[variable] = y
        low, high = address & ~(1 << variable), address | (1 << variable)
        selector = 0x123456788
        if number == 17:
            z = fixture_words(16, 43)
            actual = field.mul(selector, relations.equality_operand(z, point))

            def at(index):
                value = 1
                for j in range(16):
                    value = ref.multiply(value, z[j] if index >> j & 1 else z[j] ^ 1)
                return value
        else:
            actual = field.mul(selector, relations.table_operand(point))

            def at(index):
                return ref.exponent(0x494EF99794D5244F9152DF59D87A9186, index)

        expected = ref.multiply(selector, ref.multiply(1 ^ y, at(low)) ^ ref.multiply(y, at(high)))
        assert actual == expected
        return {
            "logical_variables": 16,
            "point": point,
            "selector": selector,
            "addresses": [low, high],
            "expected": expected,
            "actual": actual,
            "full_oracle_allocated": False,
        }
    if number == 19:
        domain = ref.domain_basis(3)
        matrix = []
        for position in (0, 1, 2, 3):
            w = ref.subspace_values(3, ref.point_at(domain, position))
            matrix.append([1, w[0], w[1], ref.multiply(w[0], w[1])])
        actual = ref.rank(matrix)
        assert actual == 4
        return {"matrix": matrix, "expected": 4, "actual": actual, "includes_zero": True}
    if number in (20, 21):
        budget = relations.QueryBudget(2)
        reads = []

        def reader(i):
            reads.append(i)
            return (i + 1) * 17

        if number == 20:
            actual = [budget.query(i, reader) for i in (0, 0, 1)]
            assert actual == [17, 17, 34] and reads == [0, 1]
            return {"expected": [17, 17, 34], "actual": actual, "distinct_reads": reads}
        budget.query(0, reader)
        budget.query(1, reader)
        result = require_rejection(lambda: budget.query(2, reader), "budget")
        assert reads == [0, 1]
        return {**result, "distinct_reads": reads}
    if number in (22, 23, 24, 25):
        operands = [[0, 1], [0, 1]]
        physical = [[13, 3], [17, 5]]
        # Same aggregate B for the second logical tuple: 3^5 = 9^15 = 6.
        alternate = [[13, 9], [17, 15]]
        omega = [[19, 23], [29, 31]]
        gamma = 0 if number == 24 else 1 if number == 25 else 7
        if number == 24:
            return require_rejection(
                lambda: relations.fold_pair(physical[0], omega[0], gamma), "zero gamma"
            )
        folded = [relations.fold_pair(p, o, gamma) for p, o in zip(physical, omega, strict=True)]
        public_b = 6
        claim = relations.aggregate_mask_claim(folded, operands, public_b, gamma)
        expected = ref.dot(omega[0], operands[0]) ^ ref.dot(omega[1], operands[1])
        assert claim == expected
        # Independent conditional coupling to same V for alternate logical tuple.
        alt_omega = [
            [
                ref.multiply(v ^ ref.multiply(1 ^ gamma, p), ref.inv(gamma))
                for v, p in zip(vv, pp, strict=True)
            ]
            for vv, pp in zip(folded, alternate, strict=True)
        ]
        assert (ref.dot(alt_omega[0], operands[0]) ^ ref.dot(alt_omega[1], operands[1])) == expected
        result = {
            "gamma": gamma,
            "B": public_b,
            "folded": folded,
            "expected": expected,
            "actual": claim,
            "alternate_mask": alt_omega,
            "conditional_coupling_not_rng_simulation": True,
        }
        if number == 23:
            individual = [field.dot(o, u) for o, u in zip(omega, operands, strict=True)]
            recovered = [
                ref.multiply(ref.dot(v, u) ^ ref.multiply(gamma, c), ref.inv(1 ^ gamma))
                for v, u, c in zip(folded, operands, individual, strict=True)
            ]
            alternate_claims = [ref.dot(o, u) for o, u in zip(alt_omega, operands, strict=True)]
            assert recovered == [3, 5] and alternate_claims != individual
            result.update(
                individual_claims=individual,
                recovered_individual_targets=recovered,
                alternate_individual_claims=alternate_claims,
                negative_control=True,
                meaning=(
                    "Individual claims cannot replace aggregate in the restricted lemma; "
                    "not a native attack"
                ),
            )
        if number == 25:
            assert folded == omega
            result["original_relation_binding"] = False
        return result
    raise ValueError("unknown fixed case")


def run(case_id, output_root):
    started = time.perf_counter()
    record = {
        "id": case_id,
        "execution": "Python-model results",
        "status": "failed",
        "native_execution": False,
        "proof_generated": False,
        "counted_invocations": 1,
    }
    try:
        record["result"] = execute(int(case_id[3:]))
        record["status"] = "pass"
    except Exception as error:
        record["error"] = repr(error)
        raise
    finally:
        record["component_seconds"] = time.perf_counter() - started
        record["process_ru_maxrss_bytes"] = (
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        )
        record["candidate_bit_step_events"] = field.EVENTS
        record["reference_step_events"] = ref.EVENTS
        record["aggregate_work_events"] = field.EVENTS + ref.EVENTS
        record["source_sha256"] = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
        with (output_root / (case_id + ".outcome.json")).open("x") as f:
            json.dump(record, f, separators=(",", ":"))
            f.write("\n")
        print(json.dumps({k: v for k, v in record.items() if k != "result"}))
