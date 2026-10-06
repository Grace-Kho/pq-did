"""Read-only source identities and documentary arithmetic, never native execution."""

import hashlib
import json
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.binius64_replacement_decision_1 import run as guard  # noqa: E402

D = guard.D
OLD = P / "docs/data/implementation_consolidation_1"


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
    comparison = guard.read(P / "docs/data/oct31_auth_relation_integration_1/comparison-point.json")
    assert comparison["benchmark_trials"] == 276
    assert digest(P / comparison["immutable_manifest"]) == comparison["manifest_sha256"]
    assert digest(P / comparison["closure"]) == comparison["closure_sha256"]
    for field in ("dataset_sha256", "source_and_binary_sha256"):
        for name, expected in comparison[field].items():
            assert digest(P / name) == expected, name
    source_index = guard.read(D / "source-index.json")
    tree = {row["path"]: row for row in guard.read(D / "sources/implementation-tree.json")["tree"]}
    for name, record in source_index["retained_files"].items():
        path = D / "sources" / name
        assert path.stat().st_size == record["bytes"]
        assert digest(path) == record["sha256"]
        if name.startswith("native--"):
            native_path = name.removeprefix("native--").replace("--", "/")
            contents = path.read_bytes()
            blob = b"blob " + str(len(contents)).encode() + b"\0" + contents
            assert hashlib.sha1(blob).hexdigest() == tree[native_path]["sha"]
    assert source_index["implementation_commit"] == ("441fbf51ff0bcb0bcd28f3f1b73f4954029e8577")
    commit = guard.read(D / "sources/implementation-commit.json")
    assert commit["sha"] == source_index["implementation_commit"]
    assert commit["commit"]["tree"]["sha"] == source_index["implementation_tree"]
    assert digest(D / "sources/spec.pdf") == source_index["blueprint_sha256"]
    dependency = guard.read(D / "dependency-requirements.json")
    assert dependency["cargo_lock_in_tree"] is False
    assert dependency["rust"] == "1.98.1"
    decision = guard.read(D / "decision.json")
    assert decision["programme_complete"] is False
    assert decision["new_invocations"] == decision["proofs_authorised"] == 0
    assert decision["full_relation_checks_unrun"] == 21
    assert 16 + 24 + 21 + 12 + 12 + 8 + 8 + 12 + 15 == 128
    assert 1200 + 900 + 1800 + 1200 + 900 + 900 + 300 == 7200
    assert 24 * 25 * 146 == 87600
    assert 224 * (1 << 19) == 112 * (1 << 20)
    assert 224 * (1 << 22) == 896 * (1 << 20)
    ledger = guard.read(D / "ledger.json")
    assert not ledger["invocations"] and not ledger["builds"]
    assert (
        guard.read(P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json")[
            "attempts_used"
        ]
        == 2
    )
    guard.write(
        D / "preflight.json",
        {
            "passed": True,
            "programme_complete": False,
            "new_functional_executions": 0,
            "source_files_checked": len(source_index["retained_files"]),
            "historical_seals_verified": len(seals),
            "dataset_files_verified": len(comparison["dataset_sha256"]),
            "baseline_source_binary_files_verified": len(comparison["source_and_binary_sha256"]),
            "benchmark_trials_reused": 276,
            "full_relation_checks_unrun": 21,
            "documentary_calculations_only": True,
            "source_budget_estimate_exceeded": True,
            "no_further_acquisition": True,
            "storage": guard.storage(),
        },
    )
    print(json.dumps({"documentary_preflight_passed": True, "new_executions": 0}))


if __name__ == "__main__":
    preflight()
