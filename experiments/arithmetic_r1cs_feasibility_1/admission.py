"""Retained identity verification and whole-workload resource accounting; no proving."""

import hashlib

from . import run as guard

P, D = guard.P, guard.D
OLD = P / "docs/data/oct31_compact_auth_representation_1"


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
    assert guard.POLICY["historical_work_events"] == 27593603
    assert guard.POLICY["historical_invocations"] == 971
    assert guard.POLICY["historical_builds"] == 10
    assert guard.POLICY["new_evidence_cap_bytes"] == 5206313
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


def workload(meter, *, rerun=False):
    """One counted calculation; reuse measured hash data, emit no new circuit."""
    p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    measured_path = P / "docs/data/oct31_auth_relation_integration_run_1/cases/AR1-0054.json"
    measured = guard.read(measured_path)
    assert measured["case_id"] == "M-16" and measured["status"] == "pass"
    descriptor = measured["details"]["descriptor"]
    assert descriptor["complete"] and descriptor["gate_counts"] == [1096322, 269187, 386]
    native_root = P / "experiments/aurora_masking_milestone_1/work"
    field_path = native_root / "libff/libff/algebra/curves/alt_bn128/alt_bn128_fields.cpp"
    native_path = native_root / "libiop/libiop/protocols/encoded/r1cs_rs_iop/r1cs_rs_iop.tcc"
    field_text, native_text = field_path.read_text(), native_path.read_text()
    assert str(p) in field_text and "alt_bn128_Fr::s = 28;" in field_text
    assert "paper masking requires non-holographic additive ZK" in native_text
    assert "domain_type != affine_subspace_type" in native_text
    for vector in ("fw", "fAz", "fBz", "fCz"):
        assert f"submit_oracle(this->{vector}_handle_" in native_text
    assert p.bit_length() == 254 and (p - 1) % (2**28) == 0
    assert (p - 1) % (2**29) != 0 and 2**128 < p

    # Same fixed input/output length as the actual verify_signature caller.
    permutations = (64 + 768) // 136 + 1
    chi_rows = permutations * 24 * 25 * 64
    assert chi_rows == 268800 and descriptor["gate_counts"][1] >= chi_rows
    # No transfer of GF192 XOR counts: this lower bound keeps chi rows only.
    m = 1 << (chi_rows - 1).bit_length()
    n = 1 << chi_rows.bit_length()  # at least one variable per chi plus constant
    min_degree = max(2 * max(m, n), 2 * m + 1)
    domain = 1 << ((8 * min_degree) - 1).bit_length()
    element = (p.bit_length() + 7) // 8
    word = domain * element
    assert (m, n, domain, element) == (2**19, 2**19, 2**24, 32)
    assert 4 * word > guard.POLICY["phase_memory"]["native"]
    assert 4 * word >= guard.POLICY["aggregate_memory_bytes"]
    assert word > guard.POLICY["artifact_cap_bytes"]

    previous = guard.read(OLD / "whole-workload-model.json")["whole_workload"]
    categorised = []
    categories = [
        ("parsing/disclosure/policy", False),
        ("holder binding/hash", False),
        ("arithmetic/norm", True),
        ("parsing/hints", False),
        ("hashing", False),
        ("hashing/bounded sampling", False),
        ("arithmetic", True),
        ("arithmetic", True),
        ("arithmetic", True),
        ("arithmetic", True),
        ("arithmetic/decomposition", False),
        ("hashing/challenge equality", False),
        ("Merkle/hash/same identifier", False),
        ("public admission/lifecycle", False),
    ]
    for item, (category, affected) in zip(previous, categories, strict=True):
        categorised.append(
            {
                "component": item["component"],
                "cardinality": item["cardinality"],
                "category": category,
                "integer_arithmetic_candidate_changes": affected,
                "full_prime_field_constraint_count": None,
                "source_coverage_only_unless_measured_separately": True,
            }
        )
    sources = [
        measured_path,
        field_path,
        native_path,
        P / "src/pqdid/circuits/keccak.py",
        P / "experiments/auth_relation_integration_1/mldsa_verify.py",
        P / "experiments/auth_relation_integration_1/merkle.py",
        P / "experiments/auth_relation_integration_1/private_relation.py",
        P / "experiments/auth_relation_integration_1/relation_cases.py",
        P / "src/pqdid/circuits/scalar_ring.py",
        D / "contract.md",
    ]
    result = {
        "passed": True,
        "decision": "NO-GO-before-arithmetic-gadget-implementation",
        "candidate": "INT-R1CS-FR254-1",
        "field_prime": str(p),
        "field_bit_length": 254,
        "field_two_adicity_from_retained_source": 28,
        "field_definition_reused_not_native_instantiated": True,
        "hash_mapping": "Odd-prime XOR: (2x)y=x+y-z; AND: xy=z; NOT: affine 1-x",
        "reused_component": "M-16, public mu/private w1; no rerun or GF192 XOR transfer",
        "joint_mu_remains_private": True,
        "final_hash_input_bytes": 832,
        "final_hash_output_bytes": 48,
        "permutations": permutations,
        "chi_rows_lower": chi_rows,
        "complete_prime_field_constraint_count": None,
        "whole_workload": categorised,
        "padded_rows_lower": m,
        "padded_variables_lower": n,
        "minimum_b_for_lower_bound_not_protocol_setting": 1,
        "constraint_degree_lower": min_degree,
        "codeword_elements_lower": domain,
        "field_element_payload_lower_bytes": element,
        "single_codeword_payload_lower_bytes": word,
        "four_codewords_payload_lower_bytes": 4 * word,
        "unpadded_chi_auxiliary_values_lower_bytes": chi_rows * element,
        "padded_assignment_payload_lower_bytes": n * element,
        "three_Az_Bz_Cz_payload_lower_bytes": 3 * m * element,
        "chi_matrix_coefficient_payload_lower_bytes": 3 * chi_rows * element,
        "native_worker_limit_bytes": guard.POLICY["phase_memory"]["native"],
        "aggregate_limit_bytes": guard.POLICY["aggregate_memory_bytes"],
        "artifact_limit_bytes": guard.POLICY["artifact_cap_bytes"],
        "native_actual_memory_measurement_for_prime_profile": None,
        "additional_memory_not_in_codeword_subtotal": [
            "input bits, arithmetic and control witnesses",
            "matrix indices, row/vector/map overhead, copies",
            "mask polynomials and degree/repetition expansion",
            "interpolation/FFT scratch",
            "Merkle commitments, salts/openings and retained oracles",
        ],
        "degree_envelope_conditional_on_compatible_masking_port": True,
        "current_native_masking_rejects_multiplicative_domain": True,
        "masking_or_security_settings_reduced": False,
        "resource_admitted": False,
        "codewords_allocated": 0,
        "new_arithmetic_gadgets_implemented": False,
        "new_hash_generation_or_evaluation": False,
        "outstanding_full_relation_checks": guard.read(OLD / "case-summary.json")[
            "previous_unrun_checks"
        ],
        "provenance_sha256": {str(path.relative_to(P)): digest(path) for path in sources},
        "work_accounting": "Source/calculation only: zero emitted gates/rows/terms/evaluations",
    }
    meter(0)
    output = "whole-workload-model-r1.json" if rerun else "whole-workload-model.json"
    guard.write(D / output, result)
    return result
