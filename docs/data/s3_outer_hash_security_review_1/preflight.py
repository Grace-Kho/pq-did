"""Verify the completed assessment seal; reuse its host and functional evidence."""

# ruff: noqa: E402

import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
OLD = P / "docs/data/s2_concrete_security_assessment_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit


def main():
    manifest = OLD / "manifest.json"
    assert (
        audit.digest_file(manifest)
        == "6cf03dd4495521e2027961303ab0e7d9033445a005f0f8a640fc73d0e52c1be2"
    )
    previous = json.loads(manifest.read_text())
    for name, expected in previous["sha256"].items():
        assert audit.digest_file(P / name) == expected, name
    source = json.loads((OLD / "source-revision.json").read_text())
    for name, expected in source["sha256"].items():
        assert audit.digest_file(P / name) == expected, name
    closure = json.loads((OLD / "validation-closure.json").read_text())
    assert closure["full_audit_passed"] and closure["isolation_state"] == "safe-stopped-unactivated"
    assert closure["isolation_identity_cases_pending"] == 22
    assert closure["isolation_remaining_seconds_unchanged"] == 250.22
    prefixes = {}
    for name in ["docs/status.md", "docs/traceability.md", "docs/spec_issues.md"]:
        path = P / name
        prefixes[name] = {"bytes": path.stat().st_size, "sha256": audit.digest_file(path)}
    audit.write_report(D / "prior-report-prefixes.json", prefixes)
    audit.write_report(
        D / "preflight-evidence.json",
        {
            "package": "S3-OUTER-HASH-SECURITY-REVIEW-1",
            "passed": True,
            "previous_manifest_sha256": audit.digest_file(manifest),
            "assessment_sealed_paths_verified": len(previous["sha256"]),
            "source_inventory_sha256": source["inventory_sha256"],
            "source_files_verified": len(source["sha256"]),
            "manuscript_sha256": source["sha256"]["docs/manuscript/PQ_DID__Implementation.pdf"],
            "manuscript_authority": "II-VIII and SPEC-001--004 only; reuse verified extraction",
            "previous_calculations_reused": (
                "bounds.json and eight independent checks; not repeated"
            ),
            "previous_security_analysis_seconds": closure["aggregate_charged_seconds"],
            "isolation": (
                "Reuse sealed safe-stopped-unactivated evidence and user's unchanged disposition"
            ),
            "isolation_invocations": 100,
            "isolation_identity_cases_pending": 22,
            "isolation_remaining_seconds": 250.22,
            "new_proofs": 0,
            "new_zkvm_executions": 0,
            "activation": False,
        },
    )
    print(
        json.dumps(
            {
                "seal_matches": True,
                "prior_assessment_reused": True,
                "source_revision": source["inventory_sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
