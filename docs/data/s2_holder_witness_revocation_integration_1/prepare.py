"""Extend the original preservation chain with the completed verifier integration seal."""

# ruff: noqa: E402

import importlib.util
import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
OLD = P / "docs/data/s2_durable_verifier_lifecycle_integration_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit

spec = importlib.util.spec_from_file_location(
    "historical_audit_helpers", P / "docs/data/s2_authority_isolation_pilot_1/audit.py"
)
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
small, require = prior.small_json, prior.require


def main():
    old = small(OLD / "scope.json")
    identities = dict(old["baseline_identities"])
    supplements = dict(old["supplementary_manifests"])
    previous_name = str((OLD / "manifest.json").relative_to(P))
    expected = "6e308920f5499a72eadc020f684abccebfae8e24e040376c6446a3ba819870c8"
    require(audit.digest_file(P / previous_name) == expected, "previous verifier integration seal")
    supplements[previous_name] = len(small(P / previous_name)["sha256"])
    identities[previous_name] = expected
    for name, digest in old["baseline_identities"].items():
        require(audit.digest_file(P / name) == digest, "original baseline: " + name)
    primary = {
        name
        for name, _ in audit.iter_manifest(
            P / "docs/data/s2_revoke_state_1/preservation-before.json"
        )
    }
    require(len(primary) == 8759, "primary metadata count")
    latest = {}
    for name, count in supplements.items():
        rows = small(P / name)["sha256"]
        require(len(rows) == count, "supplement manifest count")
        latest.update(rows)
    known = primary | set(latest) | set(identities)
    roots = old["additional_name_inventory_roots"]
    required = {name for name in known if name.split("/")[0] in roots}
    required.update(old["required_names"])
    required.update(name for name in old["optional_names"] if (P / name).exists())
    new = {str(path.relative_to(P)) for path in D.rglob("*") if path.is_file()}
    new.add("docs/stage2_holder_witness_revocation_integration.md")
    implementation = [
        P / name
        for name in (
            "src/pqdid/holder_lifecycle.py",
            "tests/integration/test_holder_lifecycle.py",
            "tests/integration/holder_lifecycle_cases.py",
        )
    ]
    new.update(str(path.relative_to(P)) for path in implementation)
    required.update(new)
    future = {
        "scope.json",
        "prepare.json",
        "validation.json",
        "phases.json",
        "result.json",
        "full-audit.json",
        "full-audit.log",
        "full-audit.service.json",
        "STOP.json",
        "manifest.json",
        "validation-closure.json",
    }
    optional = {str((D / name).relative_to(P)) for name in future} - required
    inputs = [
        *sorted(D.glob("*.py")),
        *implementation,
        D / "config.json",
        D / "contract.json",
        D / "task-specification.md",
        D / "prior-report-prefixes.json",
        D / "preflight-evidence.json",
    ]
    frozen = {str(path.relative_to(P)): audit.digest_file(path) for path in inputs}
    scope = {
        "package": "S2-HOLDER-WITNESS-REVOCATION-INTEGRATION-1",
        "authority": "New reference holder witness/revocation integration and focused tests; "
        "three existing reports append-only. "
        "No changes to existing code or inputs.",
        "baseline_identities": identities,
        "primary_count": 8759,
        "supplementary_manifests": supplements,
        "supplementary_count": len(set(latest) - primary),
        "known_manifest_union_names": len(known),
        "original_permitted_documentation": [
            "docs/status.md",
            "docs/traceability.md",
            "docs/spec_issues.md",
        ],
        "supplementary_allowed_docs": [],
        "append_only_documentation": small(D / "prior-report-prefixes.json"),
        "additional_name_inventory_roots": roots,
        "required_names": sorted(required),
        "optional_names": sorted(optional),
        "new_authorised_files": sorted(new | optional),
        "frozen_package_inputs": frozen,
        "new_python_files": [name for name in frozen if name.endswith(".py")],
        "new_markdown_files": ["docs/stage2_holder_witness_revocation_integration.md"],
        "post_audit_authorisation": "Only append measured closure to new report and three "
        "existing append-only reports; record exact new manifest/closure and guard result. "
        "No repeated content audit, source change or historical baseline regeneration.",
    }
    inventory = audit.inventory_check(P, roots, required, optional_names=optional)
    require(inventory["passed"], "scope name-only preflight: " + json.dumps(inventory))
    audit.write_report(D / "scope.json", scope)
    print(
        json.dumps(
            {
                "kind": "scope-only; not complete content audit",
                "primary": len(primary),
                "supplement": scope["supplementary_count"],
                "inventory": inventory,
                "original_baselines_regenerated": False,
            }
        )
    )


if __name__ == "__main__":
    main()
