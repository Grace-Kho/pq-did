"""Read-only preparation and preservation checks; no application tests execute."""

import hashlib
import json
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_testbed_completion_1 import run as guard  # noqa: E402

D = guard.D
A = P / "docs/data/oct31_binius64_g0_1"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main():
    opening = guard.read(D / "opening.json")
    assert digest(A / "manifest.json") == opening["prior_manifest_sha256"]
    assert digest(A / "validation-closure.json") == opening["prior_closure_sha256"]
    assert digest(A / "resource-closure.json") == opening["prior_resource_closure_sha256"]
    closure = guard.read(A / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    assert closure["workload_terminated"] and closure["decision"] == "NO-GO at G0"
    seals = guard.read(A / "manifest.json")["sha256"]
    seals.update(closure["finalisation_sha256"])
    prefixes = guard.read(D / "prefixes.json")
    for name, expected in seals.items():
        if name in prefixes:
            prefix = prefixes[name]
            assert prefix["sha256"] == expected
            with (P / name).open("rb") as stream:
                data = stream.read(prefix["bytes"])
            assert len(data) == prefix["bytes"]
            assert hashlib.sha256(data).hexdigest() == expected
        else:
            assert digest(P / name) == expected, name
    assert digest(P / "docs/manuscript/PQ_DID__Implementation.pdf") == (
        "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    comparison = guard.read(P / "docs/data/oct31_auth_relation_integration_1/comparison-point.json")
    assert comparison["benchmark_trials"] == 276
    for key in ("dataset_sha256", "source_and_binary_sha256"):
        for name, expected in comparison[key].items():
            assert digest(P / name) == expected, name
    plan = guard.read(D / "execution-plan.json")
    assert len(plan["cases"]) == len({r["id"] for r in plan["cases"]}) == 72
    assert all(r["status"] == "unrun" for r in plan["cases"])
    assert plan["planned_distinct_invocations"] + plan["affected_reruns_max"] == 76
    assert not plan["ordinary_execution_admitted"]
    assert not guard.read(D / "ledger.json")["invocations"]
    assert not guard.read(D / "ledger.json")["builds"]
    resources = opening["resources"]
    assert (
        resources["shared_evidence_remaining_bytes"]
        < guard.POLICY["evidence_completion_reserve_bytes"]
    )
    assert resources["shared_evidence_remaining_bytes"] + 1572864 == 3046768
    assert 3046768 < resources["cumulative_evidence_remaining_bytes"]
    guard.write(
        D / "preflight.json",
        {
            "passed": True,
            "programme_complete": False,
            "workstream_complete": False,
            "preparation_only": True,
            "functional_invocations": 0,
            "new_builds": 0,
            "prior_seals_checked": len(seals),
            "dataset_files_checked": len(comparison["dataset_sha256"]),
            "baseline_source_binary_files_checked": len(comparison["source_and_binary_sha256"]),
            "matrix_entries": 72,
            "ordinary_execution_admitted": False,
            "budget_and_mapping_request_pending": True,
            "storage": guard.storage(),
        },
    )
    print(json.dumps({"preparation_checked": True, "application_tests_executed": 0}))


if __name__ == "__main__":
    main()
