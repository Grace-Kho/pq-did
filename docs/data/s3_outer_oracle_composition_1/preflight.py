"""Verify the prior review seal and retain exact append-only report prefixes."""

# ruff: noqa: E402

import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
OLD = P / "docs/data/s3_outer_hash_security_review_1"
BASE = P / "docs/data/s2_concrete_security_assessment_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit


def main():
    expected = "28a2f7384dffeb0e4a89cdd0c8c7f164773c08455e1dd0e1930d726caeccc290"
    assert audit.digest_file(OLD / "manifest.json") == expected
    previous = json.loads((OLD / "manifest.json").read_text())
    for name, digest in previous["sha256"].items():
        assert audit.digest_file(P / name) == digest, name
    source = json.loads((BASE / "source-revision.json").read_text())
    for name, digest in source["sha256"].items():
        assert audit.digest_file(P / name) == digest, name
    closure = json.loads((OLD / "validation-closure.json").read_text())
    config = json.loads((D / "config.json").read_text())
    assert closure["final_evidence_status"] == "complete" and closure["full_audit_passed"]
    assert closure["aggregate_charged_seconds"] == config["prior_security_analysis_charged_seconds"]
    assert closure["aggregate_remaining_seconds"] == 278.04329328099266
    assert closure["isolation_state"] == "safe-stopped-unactivated"
    assert closure["isolation_remaining_seconds_unchanged"] == 250.22
    assert closure["isolation_identity_cases_pending"] == 22
    prefixes = {}
    for name in ["docs/status.md", "docs/traceability.md", "docs/spec_issues.md"]:
        path = P / name
        prefixes[name] = {"bytes": path.stat().st_size, "sha256": audit.digest_file(path)}
    audit.write_report(D / "prior-report-prefixes.json", prefixes)
    audit.write_report(
        D / "preflight-evidence.json",
        {
            "package": config["package"],
            "passed": True,
            "previous_manifest_sha256": expected,
            "sealed_paths_verified": len(previous["sha256"]),
            "source_inventory_sha256": source["inventory_sha256"],
            "source_files_verified": len(source["sha256"]),
            "manuscript_sha256": source["sha256"]["docs/manuscript/PQ_DID__Implementation.pdf"],
            "authority": "Only manuscript II-VIII, agreed clarifications and current specification",
            "task_sha256": audit.digest_file(D / "task-specification.txt"),
            "calculations_reused": "All preceding bounds and query mapping; no new numeric claims",
            "prior_analysis_seconds": closure["aggregate_charged_seconds"],
            "remaining_analysis_seconds_at_start": closure["aggregate_remaining_seconds"],
            "isolation_state": "safe-stopped-unactivated; sealed evidence reused",
            "isolation_invocations": 100,
            "isolation_identity_cases_pending": 22,
            "isolation_remaining_seconds": 250.22,
            "proof_attempts_used": 2,
            "proof_attempts_unused": 1,
            "new_proofs": 0,
            "new_zkvm_executions": 0,
            "activation": False,
        },
    )
    print(json.dumps({"seal_verified": True, "source_and_host_evidence_reused": True}))


if __name__ == "__main__":
    main()
