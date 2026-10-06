"""Verify the prior review seal and retain exact append-only report prefixes."""

# ruff: noqa: E402

import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
OLD = P / "docs/data/s3_aurora_transcript_correction_contract_1"
BASE = P / "docs/data/s2_concrete_security_assessment_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit


def main():
    expected = "1dff5c6d002c88b68566924ca499dfd1397f98b99770ee726eee064024fabe77"
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
        closure["status"] == "complete-correction-contract-isolated-regression-proposed"
        and closure["full_audit_passed"]
    )
    assert (
        closure["implementation_aggregate_charged_seconds_unchanged"]
        == config["prior_implementation_charged_seconds"]
    )
    assert closure["implementation_aggregate_remaining_seconds_unchanged"] == 41.82321833795868
    assert closure["total_test_invocations"] == config["prior_test_invocations"] == 386
    assert closure["analysis_aggregate_remaining_seconds"] == 211.51345554180443
    assert closure["isolation_state"] == "safe-stopped-unactivated"
    assert closure["isolation_remaining_seconds_unchanged"] == 250.22
    assert closure["isolation_identity_cases_pending"] == 22
    suite = json.loads((P / "configs/suite.json").read_text())["confirmed"]
    assert suite["bounded_operations"]["RejNTTPoly_max_bytes"] == 1026
    assert suite["bounded_operations"]["RejBoundedPoly_max_bytes"] == 512
    assert suite["bounded_operations"]["SampleInBall_max_total_bytes"] == 256
    assert suite["signature"]["fresh_hedging_randomness"] is True
    assert config["synthetic_case_limit"] == 402
    assert config["test_invocations"] == {"cases": 16}
    pins = json.loads((OLD / "reviewed-inputs.json").read_text())["sha256"]
    for name, digest in pins.items():
        assert audit.digest_file(P / name) == digest, name
    bridge = P / "docs/data/s3_aurora_transcript_bridge_1"
    source_rows = 0
    for inventory in ("sources.json", "sources-supplement.json"):
        for row in json.loads((bridge / inventory).read_text())["rows"]:
            assert audit.digest_file(bridge / row["local"]) == row["sha256"]
            source_rows += 1
    audit.write_report(
        D / "reviewed-inputs.json",
        {"sha256": pins, "kind": "Review input identity only; no historical baseline replacement"},
    )
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
            "pinned_upstream_files_verified": source_rows,
            "manuscript_sha256": source["sha256"]["docs/manuscript/PQ_DID__Implementation.pdf"],
            "authority": "Only manuscript II-VIII, agreed clarifications and current specification",
            "task_authority": "Direct user authorisation S3-AURORA-TRANSCRIPT-REGRESSION-1",
            "implementation_charged_at_start": 332.1767816620413,
            "implementation_remaining_at_start": 41.82321833795868,
            "test_invocations_remaining_at_start": 16,
            "calculations_reused": "No new tail/security probability estimates",
            "prior_analysis_seconds": 88.48654445819557,
            "remaining_analysis_seconds_at_start": closure["analysis_aggregate_remaining_seconds"],
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
