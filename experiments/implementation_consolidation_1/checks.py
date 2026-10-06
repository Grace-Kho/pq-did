"""Read-only identity and documentary coverage checks; no functional reruns."""

import hashlib
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.implementation_consolidation_1 import run as guard  # noqa: E402

D = guard.D
OLD = P / "docs/data/oct31_joint_hash_masking_decision_1"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(65536):
            h.update(data)
    return h.hexdigest()


def preflight():
    opening = guard.read(D / "opening.json")
    assert digest(OLD / "validation-closure.json") == opening["prior_closure_sha256"]
    assert digest(OLD / "manifest.json") == opening["prior_manifest_sha256"]
    prior = guard.read(OLD / "validation-closure.json")
    assert prior["complete"] and prior["workload_terminated"]
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
    coverage = guard.read(D / "coverage.json")
    names = [name for row in coverage["groups"] for name in row["requirements"]]
    assert sorted(names) == [f"R-{i:03d}" for i in range(1, 53)]
    assert set(coverage["titles"]) == set(names)
    assert digest(P / coverage["requirements_source"]) == coverage["source_sha256"]
    for row in coverage["groups"]:
        assert row["remaining"] and not row["complete_scheme_requirement_closed"]
        for name in row["evidence"]:
            assert (P / name).is_file(), name
    index = guard.read(D / "reproduction-index.json")
    assert digest(P / index["comparison_point_path"]) == index["comparison_point_sha256"]
    comparison = guard.read(P / index["comparison_point_path"])
    assert comparison["benchmark_trials"] == 276
    assert digest(P / comparison["immutable_manifest"]) == comparison["manifest_sha256"]
    assert digest(P / comparison["closure"]) == comparison["closure_sha256"]
    for field in ("dataset_sha256", "source_and_binary_sha256"):
        for name, expected in comparison[field].items():
            assert digest(P / name) == expected, name
    for row in index["commands"]:
        assert digest(P / row["record"]) == row["record_sha256"]
        assert guard.read(P / row["record"])["argv"] == row["worker_argv"]
        assert not row["execution_now_authorised"]
    assert (
        guard.read(P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json")[
            "attempts_used"
        ]
        == 2
    )
    assert not guard.read(D / "ledger.json")["invocations"]
    guard.write(
        D / "preflight.json",
        {
            "passed": True,
            "programme_complete": False,
            "scope_reduction_approved": False,
            "target": "31 October; full completion commitment unsupported",
            "historical_seals_verified": len(seals),
            "requirements_indexed_once": len(names),
            "dataset_files_verified": len(comparison["dataset_sha256"]),
            "baseline_source_binary_files_verified": len(comparison["source_and_binary_sha256"]),
            "benchmark_trials_reused": 276,
            "documentary_command_records": len(index["commands"]),
            "new_functional_executions": 0,
            "storage": guard.storage(),
        },
    )


if __name__ == "__main__":
    preflight()
