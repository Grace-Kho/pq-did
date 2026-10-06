"""Completion-only identity checks. No native code or masking tests execute."""

import hashlib
import json
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.binius64_g0_1 import run as guard  # noqa: E402

D = guard.D
A = P / "docs/data/oct31_binius64_replacement_decision_1"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            h.update(chunk)
    return h.hexdigest()


def preflight():
    approval = guard.read(D / "opening.json")
    assert digest(A / "manifest.json") == approval["prior_manifest_sha256"]
    assert digest(A / "validation-closure.json") == approval["prior_closure_sha256"]
    closure = guard.read(A / "validation-closure.json")
    assert closure["complete"] and closure["preservation_complete"]
    assert closure["workload_terminated"]
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
            assert hashlib.sha256(data).hexdigest() == expected, name
        else:
            assert digest(P / name) == expected, name
    assert digest(P / "docs/manuscript/PQ_DID__Implementation.pdf") == (
        "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    tree = {r["path"]: r for r in guard.read(A / "sources/implementation-tree.json")["tree"]}
    records = []
    for name in ("source-acquisition.json", "source-acquisition-2.json"):
        records.extend(guard.read(D / name)["sources"])
    assert len(records) == 8 and len({r["path"] for r in records}) == 8
    total = 0
    for r in records:
        data = (D / "sources" / r["path"]).read_bytes()
        assert len(data) == r["bytes"] == tree[r["upstream_path"]]["size"]
        assert hashlib.sha256(data).hexdigest() == r["sha256"]
        blob = b"blob " + str(len(data)).encode() + b"\0" + data
        assert hashlib.sha1(blob).hexdigest() == r["git_blob"] == tree[r["upstream_path"]]["sha"]
        total += len(data)
    assert total == 90955 and total <= approval["read_only_source_budget_bytes"]
    comparison = guard.read(P / "docs/data/oct31_auth_relation_integration_1/comparison-point.json")
    assert comparison["benchmark_trials"] == 276
    for field in ("dataset_sha256", "source_and_binary_sha256"):
        for name, expected in comparison[field].items():
            assert digest(P / name) == expected, name
    assert digest(P / comparison["immutable_manifest"]) == comparison["manifest_sha256"]
    assert digest(P / comparison["closure"]) == comparison["closure_sha256"]
    ledger = guard.read(D / "ledger.json")
    assert not ledger["invocations"] and not ledger["builds"]
    assert ledger["work_events"] == 77593603 and ledger["work_events_reserved"] == 0
    decision = guard.read(D / "decision.json")
    assert decision["decision"] == "NO-GO at G0"
    assert decision["overlay_produced"] is False and decision["native_checks"] == "unrun"
    proof = guard.read(
        P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
    )
    assert proof["attempts_used"] == 2
    guard.write(
        D / "preflight.json",
        {
            "passed": True,
            "programme_complete": False,
            "source_files_verified": len(records),
            "source_bytes_verified": total,
            "historical_seals_verified": len(seals),
            "dataset_files_verified": len(comparison["dataset_sha256"]),
            "baseline_source_binary_files_verified": len(comparison["source_and_binary_sha256"]),
            "benchmark_trials_reused": 276,
            "full_relation_checks_unrun": 21,
            "new_functional_executions": 0,
            "purpose": "Completion identity validation; not construction-test admission",
            "storage": guard.storage(),
        },
    )
    print(json.dumps({"identity_checks_passed": True, "construction_test_executions": 0}))


if __name__ == "__main__":
    preflight()
