"""Retained identity verification and whole-workload resource accounting; no proving."""

import hashlib

from . import run as guard

P, D = guard.P, guard.D
OLD = P / "docs/data/oct31_auth_relation_integration_run_1"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            value.update(chunk)
    return value.hexdigest()


def preflight():
    opening = guard.read(D / "opening.json")
    assert digest(OLD / "validation-closure.json") == opening["prior_closure_sha256"]
    prior = guard.read(OLD / "validation-closure.json")
    assert prior["preservation_complete"] and prior["workload_terminated"]
    assert digest(OLD / "manifest.json") == prior["manifest_sha256"]
    seals = guard.read(OLD / "manifest.json")["sha256"]
    seals.update(prior["finalisation_sha256"])
    for name, expected in seals.items():
        assert digest(P / name) == expected, name
    for name, prefix in guard.read(D / "prefixes.json").items():
        assert seals[name] == prefix["sha256"]
        assert (P / name).stat().st_size == prefix["bytes"]
    assert digest(P / "docs/manuscript/PQ_DID__Implementation.pdf") == (
        "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    assert (
        guard.read(P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json")[
            "attempts_used"
        ]
        == 2
    )
    assert guard.POLICY["historical_work_events"] == 27379838
    assert guard.POLICY["historical_invocations"] == 942
    assert guard.POLICY["historical_builds"] == 10
    assert guard.POLICY["new_evidence_cap_bytes"] == 5541239
    guard.write(
        D / "preflight.json",
        {
            "passed": True,
            "verified_retained_paths": len(seals),
            "storage": guard.storage(),
            "new_build_required": False,
            "comparison_point_v1_reused": True,
            "private_proof_admission": False,
            "contract_sha256": digest(D / "contract.md"),
        },
    )


def power2(value):
    return 1 << (value - 1).bit_length()


def workload(meter):
    summary_path = P / "docs/data/s3_mldsa_full_forward_ntt_pilot_1/pilot-summary.json"
    summary = guard.read(summary_path)
    assert summary["passed"] and summary["completed_partitions"] == 97
    stages = summary["stage_counts"]
    assert set(stages) == set(map(str, range(8)))
    assert all(s["and_"] == 904192 and s["butterflies"] == 128 for s in stages.values())
    core = sum(s["and_"] for s in stages.values())
    native = guard.read(OLD / "cases/AR1-0002.json")["details"]["native"]
    assert native["field_bytes"] == 24
    assert native["term_object_bytes"] == 32 and native["constraint_object_bytes"] == 72
    bounds = []
    for copies in (1, 6):
        and_rows = copies * core
        rows = 42632 + and_rows + 2
        variables = 42632 + and_rows + 1
        m, n = power2(rows), power2(variables + 1)
        t = max(m, n)
        degree = max(2 * t, 2 * m + 1)  # minimum b=1, unknown extra terms only increase
        domain = power2(8 * degree)
        bounds.append(
            {
                "source_core_copies": copies,
                "and_row_subset_lower": and_rows,
                "complete_relation_row_lower": rows,
                "variable_lower_excluding_constant": variables,
                "padded_M_lower": m,
                "padded_N_lower": n,
                "minimum_b": 1,
                "Dconstraint_lower": degree,
                "codeword_elements_lower": domain,
                "single_codeword_payload_lower_bytes": 24 * domain,
                "four_simultaneous_codewords_lower_bytes": 96 * domain,
                "padded_assignment_payload_lower_bytes": 24 * n,
                "three_Az_Bz_Cz_vectors_lower_bytes": 72 * m,
                "unpadded_constraint_objects_lower_bytes": 72 * rows,
                "nonzero_C_terms_for_AND_only_lower_bytes": 32 * and_rows,
                "native_worker_bytes": 1073741824,
                "aggregate_bytes": 2147483648,
                "fits_even_one_codeword": 24 * domain <= 1073741824,
            }
        )
    components = [
        (
            "private parsing/disclosure/final sticky scope",
            "one canonical witness, 42632 bits",
            "unmeasured full cost; previous prefix completed parsing/disclosure",
        ),
        (
            "holder SHA3-384",
            "1 hash; canonical framed private secret",
            "complete retained component, not repeated",
        ),
        (
            "signature response decode/norm",
            "5*256 coefficients; strict abs(z)<524092",
            "full source; norm boundary retained",
        ),
        (
            "hints",
            "61 bytes; 6*256 outputs; <=55 ordered nonzero indices",
            "retained experimental decoding checks",
        ),
        (
            "mu SHAKE256",
            "one hash of tr||formatted_message, output64",
            "full framed length shape-dependent; unmeasured complete relation",
        ),
        (
            "challenge sampling",
            "SHAKE256(48B,256B),2 permutations; 248 private candidate iterations",
            "full private scan unexecuted; exhaustion stays constrained",
        ),
        (
            "forward transforms",
            "6*(256 entry conversions+1024 butterflies+output masks)",
            "internal cores only:6*7233536 measured-subgraph AND lower; wrappers residual",
        ),
        (
            "A*z",
            "7680 public-constant products plus accumulation",
            "one coefficient retained; total cost symbolic",
        ),
        (
            "challenge*t1 subtraction",
            "1536 public-constant products plus subtraction",
            "one coefficient retained; total cost symbolic",
        ),
        (
            "inverse transforms",
            "6*(256 entry conversions+1024 inverse butterflies+256 factor products)",
            "full source; single inverse pair retained, total symbolic",
        ),
        (
            "decomposition/UseHint/w1",
            "1536 coefficients,768-byte output",
            "component evidence retained, full combined cost symbolic",
        ),
        (
            "challenge equality",
            "SHAKE256(mu64||w1[768],48),7 permutations and exact equality",
            "complete final-hash component retained, no full-verifier claim",
        ),
        (
            "same certified identifier non-revocation",
            "20 SHA3-384 nodes,private siblings,direction/level/root checks",
            "full source, no complete circuit measurement",
        ),
        (
            "public preprocessing and lifecycle",
            (
                "trusted PubOK/Ppub, A public sampler30*1026B, t1/tr, canonical X; "
                "separate freshness/consumption"
            ),
            (
                "outside hidden relation only because public and independently bound; "
                "retained validation"
            ),
        ),
    ]
    result = {
        "passed": True,
        "decision": "NO-GO-full-resident-AFFINE-GF192-1",
        "field": "GF(2^192), x^192+x^7+x^2+x+1",
        "field_changed": False,
        "all_original_emitted_AND_rows_preserved": True,
        "codewords_allocated": 0,
        "complete_authentication_count": None,
        "candidate_whole_constraints_measured": False,
        "rows_formula": "42632 + original_ANDs + exact_linear_spills + 2",
        "variables_formula_excluding_constant": "42632 + original_ANDs + exact_linear_spills + 1",
        "spill_bound": "0 <= S <= original_XORs+original_NOTs; at most one spill per affine gate",
        "unknown_residual_terms_are_nonnegative_not_zero": True,
        "whole_workload": [
            {"component": a, "cardinality": b, "evidence_status": c} for a, b, c in components
        ],
        "bounds": bounds,
        "bounds_exclude": [
            "extra masks and polynomial coefficients",
            "FFT/interpolation temporaries",
            "matrix copies and sparse-map allocation overhead",
            "commitment trees/salts/openings",
            "other retained oracles",
        ],
        "prior_24GiB": {
            "premise": "old gate-per-row,27044356 gates,paddedM2^25,minb1,L2^30,24B/element",
            "valid_as_conditional_bound": True,
            "not_full_relation_measurement": True,
        },
        "prior_2M_stop": {
            "governing_call": (
                "experiments/auth_relation_integration_1/count_case.py: "
                "Limits(max_gates=2000000,max_seconds=90)"
            ),
            "mode": "count,stored_bytes0",
            "declared_local_limit_honoured": True,
            "materialised_trace_ceiling": 2000000,
            "count_only_partition_ceiling_unchanged": 32000000,
            "aggregate_work_event_ceiling_not_per_trace": 2**32,
        },
        "full_remaining_21_checks": "not admitted; no complete matrix/assignment fit; no reruns",
        "provenance_sha256": {
            str(path.relative_to(P)): digest(path)
            for path in [
                summary_path,
                P / "experiments/mldsa_full_forward_ntt_1/candidate.py",
                P / "experiments/mldsa_forward_ntt_stage_1/candidate.py",
                P / "experiments/auth_relation_integration_1/mldsa_verify.py",
                OLD / "cases/AR1-0002.json",
            ]
        },
    }
    assert bounds[0]["single_codeword_payload_lower_bytes"] == 6 * 2**30
    assert bounds[1]["single_codeword_payload_lower_bytes"] == 48 * 2**30
    assert not any(b["fits_even_one_codeword"] for b in bounds)
    meter(0)
    guard.write(D / "whole-workload-model.json", result)
    return result
