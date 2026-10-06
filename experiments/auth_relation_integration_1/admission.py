"""Early source/evidence admission; never allocates an Aurora codeword."""

import hashlib
from pathlib import Path

P = Path(__file__).resolve().parents[2]
D = P / "docs/data/oct31_auth_relation_integration_run_1"
PREVIOUS = P / "docs/data/oct31_auth_relation_integration_1"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while part := stream.read(65536):
            value.update(part)
    return value.hexdigest()


def preflight():
    from experiments.auth_relation_integration_1 import run as guard

    approval = guard.read(D / "approval.json")
    assert approval["approved"]
    assert digest(PREVIOUS / "manifest.json") == approval["proposal_manifest_sha256"]
    assert digest(PREVIOUS / "validation-closure.json") == approval["proposal_closure_sha256"]
    closure = guard.read(PREVIOUS / "validation-closure.json")
    assert (
        closure["complete"] and digest(PREVIOUS / "execution-plan.json") == approval["plan_sha256"]
    )
    sealed = guard.read(PREVIOUS / "manifest.json")["sha256"]
    sealed.update(closure["finalisation_sha256"])
    for name, expected in sealed.items():
        assert digest(P / name) == expected, name
    version = guard.read(PREVIOUS / "comparison-point.json")
    seal_path = P / version["immutable_manifest"]
    assert digest(seal_path) == version["manifest_sha256"]
    latest = guard.read(seal_path)["sha256"]
    current_docs = guard.read(PREVIOUS / "prefixes.json")
    for name, expected in latest.items():
        if name in current_docs:
            prefix = current_docs[name]
            with (P / name).open("rb") as stream:
                assert hashlib.sha256(stream.read(prefix["bytes"])).hexdigest() == expected
        else:
            assert digest(P / name) == expected, name
    assert digest(P / "docs/manuscript/PQ_DID__Implementation.pdf") == (
        "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    proof = guard.read(
        P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
    )
    assert proof["attempts_used"] == 2 and proof["remaining"] == 1
    assert guard.read(P / "docs/data/s2_concrete_security_assessment_1/host-closure.json")[
        "workload_terminated"
    ]
    guard.write(
        D / "preflight.json",
        {
            "passed": True,
            "proposal_and_v1_preserved": True,
            "no_codewords_allocated": True,
            "storage": guard.storage(),
        },
    )


def capacity_case(meter):
    from experiments.auth_relation_integration_1 import run as guard

    summary_path = P / "docs/data/s3_mldsa_full_forward_ntt_pilot_1/pilot-summary.json"
    summary = guard.read(summary_path)
    assert summary["passed"] and summary["composition_accounted"]
    gates = sum(summary["counts"].values())
    assert gates == summary["aggregate_emitted_gates_or_charged_bound"] == 27044356
    rows_lower = gates
    padded_rows = 1 << (rows_lower - 1).bit_length()
    degree_lower = 2 * padded_rows + 2 * 1 - 1
    domain_lower = 1 << ((8 * degree_lower) - 1).bit_length()
    payload_lower = domain_lower * 24
    assert padded_rows == 2**25 and domain_lower == 2**30
    assert payload_lower == 25769803776 > 1073741824
    result = {
        "decision": "NO-GO-direct-resident-Aurora",
        "count_kind": "conditional lower bound from retained complete component; not full Rauth",
        "retained_summary_sha256": digest(summary_path),
        "measured_component_boolean_gates": gates,
        "conditional_rows_lower": rows_lower,
        "padded_rows_lower": padded_rows,
        "minimum_mask_budget_assumed": 1,
        "codeword_elements_lower": domain_lower,
        "single_codeword_payload_bytes_lower": payload_lower,
        "native_memory_limit_bytes": 1073741824,
        "other_simultaneous_buffers_included_in_lower_bound": False,
        "additional_buffers": [
            "sparse matrices and copies",
            "witness/assignment vectors",
            "Az/Bz/Cz",
            "interpolation/FFT",
            "masks",
            "other codewords",
            "Merkle trees, salts and openings",
        ],
        "complete_authentication_count": None,
        "alternative_representation_admitted": False,
        "large_instance_allocations": 0,
        "route_stopped": "full resident proving/backend allocation",
        "unaffected_work": (
            "complete source, bounded component stream checks, "
            "native small matrices, fail-closed boundary"
        ),
    }
    guard.write(D / "resource-admission.json", result)
    return result
