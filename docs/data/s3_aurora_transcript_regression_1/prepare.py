"""Extend the original preservation chain with the sealed transcript bridge."""

# ruff: noqa: E402

import importlib.util
import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
E = P / "experiments/aurora_transcript_regression_1"
OLD = P / "docs/data/s3_aurora_transcript_correction_contract_1"
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
    expected = "1dff5c6d002c88b68566924ca499dfd1397f98b99770ee726eee064024fabe77"
    require(audit.digest_file(P / previous_name) == expected, "previous construction seal")
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
    new.update(str(path.relative_to(P)) for path in E.rglob("*") if path.is_file())
    new.add("docs/stage3_aurora_transcript_regression.md")
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
        *sorted(E.glob("*")),
        D / "config.json",
        D / "execution-inputs.json",
        D / "reviewed-inputs.json",
        D / "prior-report-prefixes.json",
        D / "preflight-evidence.json",
        D / "case-ledger.json",
        D / "case-summary.json",
        *sorted(D.glob("TR-*.json")),
    ]
    frozen = {str(path.relative_to(P)): audit.digest_file(path) for path in inputs}
    scope = {
        "package": "S3-AURORA-TRANSCRIPT-REGRESSION-1",
        "authority": "Isolated public EXP2 reimplementation and authorised sixteen cases; "
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
        "new_markdown_files": ["docs/stage3_aurora_transcript_regression.md"],
        "post_audit_authorisation": "Only append measured closure to new report and three "
        "existing append-only reports; record exact new manifest/closure and guard result. "
        "No repeated content audit, source change or historical baseline regeneration.",
    }
    inventory = audit.inventory_check(P, roots, required, optional_names=optional)
    require(inventory["passed"], "scope name-only preflight: " + json.dumps(inventory))
    scope["inherited_required_names_from"] = str((OLD / "scope.json").relative_to(P))
    scope["required_names"] = sorted(required - set(old["required_names"]))
    scope["inventory_delta_disjoint"] = True
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
