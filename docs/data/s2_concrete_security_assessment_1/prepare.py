"""Prepare explicit scope from unchanged baselines; no complete content audit."""

# ruff: noqa: E402

import importlib.util
import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
E = P / "docs/data/s2_authority_isolation_pilot_1"
sys.path.insert(0, str(P))
from scripts import preservation_audit as audit

spec = importlib.util.spec_from_file_location("historical_audit_helpers", E / "audit.py")
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
small = prior.small_json
require = prior.require


def main():
    old = small(E / "correction-v2/scope.json")
    identities = dict(old["baseline_identities"])
    supplements = dict(old["supplementary_manifests"])
    # Supplement the old baseline with later immutable evidence, never resnapshot it.
    newer = "docs/data/s2_authority_isolation_pilot_1/correction-v2/manifest.json"
    supplements[newer] = len(small(P / newer)["sha256"])
    identities[newer] = audit.digest_file(P / newer)
    later_files = sorted((E / "activation-v2-session").glob("*.json"))
    require(len(later_files) == 4, "exact preceding activation-session inventory")
    continuation = {
        "kind": (
            "Additive preservation of four previously unsealed activation-session records; "
            "no original baseline regeneration"
        ),
        "sha256": {str(path.relative_to(P)): audit.digest_file(path) for path in later_files},
    }
    audit.write_report(D / "prior-continuation.json", continuation)
    continuation_name = str((D / "prior-continuation.json").relative_to(P))
    supplements[continuation_name] = 4
    identities[continuation_name] = audit.digest_file(P / continuation_name)
    for name, expected in old["baseline_identities"].items():
        require(audit.digest_file(P / name) == expected, "original baseline identity: " + name)
    primary_names = {
        name
        for name, _ in audit.iter_manifest(
            P / "docs/data/s2_revoke_state_1/preservation-before.json"
        )
    }
    require(len(primary_names) == 8759, "primary metadata coverage")
    latest = {}
    for name, count in supplements.items():
        rows = small(P / name)["sha256"]
        require(len(rows) == count, "supplement manifest count")
        latest.update(rows)
    known = primary_names | set(latest) | set(identities)
    roots = [*old["additional_name_inventory_roots"], "analysis"]
    require(len(set(roots)) == len(roots), "duplicate inventory root")
    required = {name for name in known if name.split("/")[0] in roots}
    required.update(old["pre_existing_inventory_only_names"])
    required.update(old["new_required_files"])
    required.update(name for name in old["new_optional_evidence_files"] if (P / name).exists())
    new = {str(path.relative_to(P)) for path in D.rglob("*") if path.is_file()}
    new.update(str(path.relative_to(P)) for path in (P / "analysis/concrete_security").glob("*"))
    new.add("docs/stage2_concrete_security_assessment.md")
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
    profile_inputs = [
        *sorted((P / "analysis/concrete_security").glob("*")),
        *sorted(D.glob("*.py")),
        D / "config.json",
        D / "sources.json",
        D / "estimator-plan.json",
        D / "estimator-not-executed.md",
        D / "bounds.json",
        D / "source-revision.json",
        D / "prior-report-prefixes.json",
        D / "host-closure.json",
        D / "calculation-checks.json",
    ]
    frozen = {str(path.relative_to(P)): audit.digest_file(path) for path in profile_inputs}
    scope = {
        "package": "S2-CONCRETE-SECURITY-ASSESSMENT-1",
        "authority": (
            "User analysis/calculation/documentation package. No source, cryptographic, "
            "dependency, parameter, historical-result or host changes."
        ),
        "baseline_identities": identities,
        "primary_count": 8759,
        "supplementary_manifests": supplements,
        "supplementary_count": len(set(latest) - primary_names),
        "known_manifest_union_names": len(known),
        "original_permitted_documentation": old["original_permitted_documentation"],
        "supplementary_allowed_docs": ["docs/stage2_authority_isolation_pilot.md"],
        "append_only_documentation": small(D / "prior-report-prefixes.json"),
        "additional_name_inventory_roots": roots,
        "required_names": sorted(required),
        "optional_names": sorted(optional),
        "new_authorised_files": sorted(new | optional),
        "frozen_analysis_inputs": frozen,
        "new_python_files": [name for name in frozen if name.endswith(".py")],
        "new_markdown_files": [
            "docs/stage2_concrete_security_assessment.md",
            str((D / "estimator-not-executed.md").relative_to(P)),
        ],
        "post_audit_authorisation": (
            "Append measured closure to the new report and four append-only existing documents; "
            "write exact new evidence manifest/closure and guard result. "
            "No repeated full content comparison or historical seal replacement."
        ),
    }
    # Name-only preflight; content comparison is reserved for the one full audit.
    inventory = audit.inventory_check(P, roots, required, optional_names=optional)
    require(inventory["passed"], "scope name-only preflight: " + json.dumps(inventory))
    audit.write_report(D / "scope.json", scope)
    print(
        json.dumps(
            {
                "kind": "scope-only preparation, not a complete preservation audit",
                "primary": len(primary_names),
                "supplement": scope["supplementary_count"],
                "inventory": inventory,
                "original_baselines_regenerated": False,
            }
        )
    )


if __name__ == "__main__":
    main()
