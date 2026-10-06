"""Retained identity verification and whole-workload resource accounting; no proving."""

import hashlib

from . import run as guard

P, D = guard.P, guard.D
OLD = P / "docs/data/oct31_arithmetic_r1cs_feasibility_1"


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
    assert guard.POLICY["historical_work_events"] == 77593603
    assert guard.POLICY["historical_invocations"] == 973
    assert guard.POLICY["historical_builds"] == 10
    assert guard.POLICY["new_evidence_cap_bytes"] == 4978828
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


def decision(meter):
    """One source/parameter calculation, not circuit or signature evaluation."""
    import os

    from pqdid.codec import encode_record
    from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT
    from pqdid.hash_domain import encode_metadata
    from pqdid.schema import ATTRIBUTE_VECTOR_BYTES
    from tests.unit.relation_cases import parameters

    previous = guard.read(OLD / "whole-workload-model-r1.json")
    assert previous["chi_rows_lower"] == 268800 and not previous["resource_admitted"]
    p = int(previous["field_prime"])
    omega = 19103219067921713944291392827692070036145651957329286315305642004821462161904
    assert pow(omega, 2**28, p) == 1 and pow(omega, 2**27, p) != 1
    assert pow(5, 2**28, p) != 1  # coset is disjoint for every nested allowed S
    m = previous["padded_rows_lower"]
    s = previous["codeword_elements_lower"]
    assert m == 2**19 and s == 2**24
    assert pow(omega, 2**28 // s * s, p) == 1

    # Canonical public shape only; zero byte strings stand for lengths, never
    # accepted credentials, hash results or private inputs in a proof relation.
    pp = parameters()
    metadata = encode_metadata(pp.domain)
    holder = encode_record("holder", (pp.suite, metadata, bytes(32)))
    binding = encode_record("binding", (bytes(48), bytes(ATTRIBUTE_VECTOR_BYTES)))
    message = encode_record("cred", (pp.suite, metadata, binding, bytes(4)))
    mu_length = 64 + 2 + len(CREDENTIAL_SIGNING_CONTEXT) + len(message)
    node = encode_record("node", (pp.suite, metadata, bytes(1), bytes(48), bytes(48)))
    shapes = [
        ("holder SHA3-384", len(holder), 104, 48, 1),
        ("mu SHAKE256", mu_length, 136, 64, 1),
        ("SampleInBall SHAKE256 prefix", 48, 136, 256, 1),
        ("final challenge SHAKE256", 832, 136, 48, 1),
        ("same-rid SHA3-384 path", len(node), 104, 48, 20),
    ]
    hashes = []
    for name, length, rate, output, copies in shapes:
        absorb = length // rate + 1
        squeeze = (output + rate - 1) // rate - 1
        hashes.append(
            dict(
                name=name,
                input_bytes=length,
                rate_bytes=rate,
                output_bytes=output,
                copies=copies,
                absorb_per_call=absorb,
                squeeze_per_call=squeeze,
                total_permutations=copies * (absorb + squeeze),
            )
        )
    permutations = sum(h["total_permutations"] for h in hashes)
    # 3200 theta XORs, 1600 chi products and 1600 chi output XORs per round.
    # NOT, rotation and public-constant XOR may be affine. Absorption <=1600 XORs.
    hash_row_upper = sum(
        h["copies"]
        * (153600 * (h["absorb_per_call"] + h["squeeze_per_call"]) + 1600 * h["absorb_per_call"])
        for h in hashes
    )
    field_columns_min = 4 + 2 * 1 + 1  # a=P=1, no retained folds counted
    field_payload = 32 * field_columns_min * s
    leaves_min = s  # two separate round trees, each S/2 binary-coset leaves
    salts = 128 * leaves_min
    digests = 64 * (2 * leaves_min - 2)
    resident_floor = field_payload + salts + digests
    assert resident_floor == 15 * 2**29 - 128
    mem = dict(
        (line.split(":", 1)[0], int(line.split()[1]) * 1024)
        for line in (P / "/proc/meminfo").read_text().splitlines()
        if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:"))
    )
    disk = os.statvfs(P)
    result = {
        "passed": True,
        "decision": "C",
        "candidate": "JHM-FR254-PACKED-1",
        "route_closed_for_current_delivery_plan": True,
        "exact_obstruction_call": "verify_signature: shake256(mu + encode_w1(high),48)",
        "FIPS204_location": "Algorithm8 line12",
        "outer_transcript_hash": "BLAKE2b-512/EXP2 in experimental backend; not this SHAKE call",
        "chi_products": 268800,
        "root_order_2_to_28_verified_by_modular_exponentiation": True,
        "coset_5_disjoint_for_all_allowed_power_two_domains": True,
        "field_or_masking_native_execution": False,
        "canonical_shape_only": "retained alpha public parameters; no witness/proof evaluation",
        "metadata_bytes": len(metadata),
        "hash_shapes": hashes,
        "total_sponge_permutations_before_public_preprocessing": permutations,
        "hash_only_odd_prime_row_construction_upper_for_this_shape": hash_row_upper,
        "hash_upper_excludes": (
            "free-input guards, packing, final equality, controls, all non-hash work"
        ),
        "complete_relation_rows_columns_nnz": None,
        "complete_implementation_peak_or_runtime_estimate": None,
        "chi_only_lower_bound": previous,
        "minimum_retained_real_field_columns": field_columns_min,
        "minimum_retained_field_payload_bytes": field_payload,
        "minimum_packed_coset_leaves": leaves_min,
        "minimum_retained_salt_bytes": salts,
        "minimum_retained_tree_digest_bytes": digests,
        "conditional_resident_fields_salts_trees_lower_bytes": resident_floor,
        "resident_bound_hypotheses": [
            "candidate packed/salted proposal, not native raw leaf wire format",
            "a=P=1 lower bound, b>=1, zero counted extra fold trees",
            "all registered real oracles, salts and full trees retained through queries",
            "no reductions in rate, masks or finite security settings",
        ],
        "machine_observation_bytes": mem,
        "disk_available_bytes_observed": disk.f_bavail * disk.f_frsize,
        "headroom_requirement_bytes": guard.POLICY["headroom_bytes"],
        "naive_four_base_Horner_coefficient_steps": 4 * s * m,
        "Horner_not_a_lower_bound_for_all_schedulers": True,
        "resource_amendment_proposed": False,
        "reason_no_amendment": (
            "No complete upper bound; projected resident minimum exceeds available host memory"
        ),
        "all_component_coverage_reused": previous["whole_workload"],
        "full_relation_checks_unrun": previous["outstanding_full_relation_checks"],
        "codewords_allocated": 0,
        "new_circuits_tests_builds_or_proofs": 0,
        "provenance_sha256": {
            **previous["provenance_sha256"],
            str((D / "contract.md").relative_to(P)): digest(D / "contract.md"),
        },
        "provenance_note": (
            "Previous contract hash remains its original path; new contract appended separately"
        ),
    }
    assert resident_floor > mem["MemAvailable"]
    assert 4 * s * m > guard.POLICY["work_event_ceiling"]
    meter(0)
    guard.write(D / "decision.json", result)
    return result
