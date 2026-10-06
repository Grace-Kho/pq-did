"""Verify the prior review seal and retain exact append-only report prefixes."""

# ruff: noqa: E402

import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
OLD = P / "docs/data/s2_durable_verifier_lifecycle_integration_1"
BASE = P / "docs/data/s2_concrete_security_assessment_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit


def main():
    expected = "6e308920f5499a72eadc020f684abccebfae8e24e040376c6446a3ba819870c8"
    assert audit.digest_file(OLD / "manifest.json") == expected
    previous = json.loads((OLD / "manifest.json").read_text())
    for name, digest in previous["sha256"].items():
        assert audit.digest_file(P / name) == digest, name
    source = json.loads((BASE / "source-revision.json").read_text())
    for name, digest in source["sha256"].items():
        assert audit.digest_file(P / name) == digest, name
    closure = json.loads((OLD / "validation-closure.json").read_text())
    config = json.loads((D / "config.json").read_text())
    assert (
        closure["status"] == "complete-isolated-synthetic-proof-verifier-integration"
        and closure["full_audit_passed"]
    )
    assert (
        closure["implementation_aggregate_charged_seconds"]
        == config["prior_implementation_charged_seconds"]
    )
    assert closure["implementation_aggregate_remaining_seconds"] == 183.3405243557645
    assert closure["total_test_invocations"] == config["prior_test_invocations"] == 172
    assert closure["analysis_remaining_seconds_unchanged"] == 270.1814811680233
    assert closure["isolation_state"] == "safe-stopped-unactivated"
    assert closure["isolation_remaining_seconds_unchanged"] == 250.22
    assert closure["isolation_identity_cases_pending"] == 22
    suite = json.loads((P / "configs/suite.json").read_text())["confirmed"]
    assert suite["bounded_operations"]["RejNTTPoly_max_bytes"] == 1026
    assert suite["bounded_operations"]["RejBoundedPoly_max_bytes"] == 512
    assert suite["bounded_operations"]["SampleInBall_max_total_bytes"] == 256
    assert suite["signature"]["fresh_hedging_randomness"] is True
    assert config["synthetic_case_limit"] == 199
    assert config["budget_amendment"]["additional_authorised"] == 27
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
            "task_authority": "Direct user request S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1",
            "implementation_charged_at_start": 116.6594756442355,
            "implementation_remaining_at_start": 183.3405243557645,
            "test_invocations_remaining_at_start": 27,
            "calculations_reused": "No new tail/security probability estimates",
            "prior_analysis_seconds": 29.81851883197669,
            "remaining_analysis_seconds_at_start": closure["analysis_remaining_seconds_unchanged"],
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
