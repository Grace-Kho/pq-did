"""Versioned candidate seal and exact audit scope; never replaces a historical seal."""

# ruff: noqa: E402

import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
E = D.parent
P = E.parents[2]
sys.path.insert(0, str(P))
sys.path.insert(0, str(P / "scripts/isolation_pilot_v2"))
from layout import PROPOSAL, check, digest, json_bytes, read_json
from provision import source_files

from scripts import preservation_audit as audit

OLD_DIGEST = "7fd9f0e1bcedf7ed7756b4f25bdde6458e06650cdece62841100c0f636e09086"
CHANGED_TOOLS = {"activation_guard.py", "control.py", "layout.py", "pilotctl.py", "provision.py"}
NEW_TOOLS = {"emergency_stop.py", "ledger.py", "shared_parent.py", "termination.py"}


def main():
    old_path = PROPOSAL.parent / "source-manifest.json"
    check(digest(old_path) == OLD_DIGEST, "original-seal")
    old = read_json(old_path, 262144)
    current = {str(p.relative_to(P)): digest(p) for p in source_files()}
    delta = []
    for name, value in current.items():
        previous = name.replace("scripts/isolation_pilot_v2/", "scripts/isolation_pilot/").replace(
            "s2_authority_isolation_pilot_1/v2/", "s2_authority_isolation_pilot_1/"
        )
        before = old["sha256"].get(previous)
        leaf = Path(name).name
        if before == value:
            continue
        if before is None:
            check(
                name.startswith("scripts/isolation_pilot_v2/") and leaf in NEW_TOOLS,
                "unexpected-new-runtime-input",
            )
        else:
            check(
                (name.startswith("scripts/isolation_pilot_v2/") and leaf in CHANGED_TOOLS)
                or (name.startswith(str(PROPOSAL.relative_to(P))) and leaf.endswith(".service.in")),
                "unexplained-source-difference",
            )
            check(digest(P / previous) == before, "historical-source-changed")
        delta.append(
            {
                "path": name,
                "previous_path": previous if before else None,
                "previous_sha256": before,
                "sha256": value,
            }
        )
    candidate = {
        "package": "S2-AUTHORITY-ISOLATION-PILOT-1",
        "version": 2,
        "kind": "corrected candidate, not yet privileged activation approval",
        "previous_source_manifest_sha256": OLD_DIGEST,
        "sha256": current,
        "authorised_input_delta": delta,
        "synthetic_inputs_sha256": old["synthetic_inputs_sha256"],
        "native_library_sha256": old["native_library_sha256"],
        "fresh_venv_command": old["fresh_venv_command"],
        "source_files": len(current),
        "source_bytes": sum((P / name).stat().st_size for name in current),
        "control_inputs_sha256": {
            str(path.relative_to(P)): digest(path)
            for path in (
                PROPOSAL / "README.md",
                D / "config.json",
                E / "run-ledger.json",
                E / "activation-preflight/run-ledger.json",
                P / "docs/proposals/s2_authority_isolation_plan_1/acceptance.json",
            )
        },
        "scope": (
            "Only the three authorised corrections; no activation, proofs, "
            "zkVM execution or cryptographic change."
        ),
    }
    (PROPOSAL / "candidate-manifest.json").write_bytes(json_bytes(candidate))
    scope = read_json(E / "scope.json", 1048576)
    # Latest immutable supplementary seals define current historic content. The
    # original 8,759-entry baseline and its digest are never recreated.
    extra = [E / "manifest.json", D / "prior-continuation.json"]
    for path in extra:
        rel = str(path.relative_to(P))
        scope["baseline_identities"][rel] = digest(path)
        scope["supplementary_manifests"][rel] = len(read_json(path, 1048576)["sha256"])
    primary = {
        name
        for name, _ in audit.iter_manifest(
            P / "docs/data/s2_revoke_state_1/preservation-before.json"
        )
    }
    latest = {}
    for name in scope["supplementary_manifests"]:
        latest.update(read_json(P / name, 1048576)["sha256"])
    scope["supplementary_count"] = len(set(latest) - primary)
    scope["known_manifest_union_names"] = len(
        primary | set(latest) | set(scope["baseline_identities"])
    )
    scope["authorised_source_changes"] = []
    scope["supplementary_allowed_docs"] = ["docs/stage2_authority_isolation_pilot.md"]
    scope["append_only_documentation"] = read_json(D / "prior-document-prefixes.json")
    roots = [P / "scripts/isolation_pilot_v2", PROPOSAL, D]
    new = sorted(
        {
            str(path.relative_to(P))
            for root in roots
            for path in root.rglob("*")
            if path.is_file() and not path.is_relative_to(D / "tmp")
        }
    )
    new += ["tests/unit/test_isolation_corrections.py", str((D / "scope.json").relative_to(P))]
    scope["new_required_files"] = sorted(
        set(scope["new_required_files"])
        | set(scope["new_optional_evidence_files"])
        | set(new)
        | set(read_json(D / "prior-continuation.json", 1048576)["sha256"])
    )
    # Do not require optional files that never existed in the previous package.
    scope["new_required_files"] = [
        name
        for name in scope["new_required_files"]
        if (P / name).is_file() or name == str((D / "scope.json").relative_to(P))
    ]
    future = [
        "validation.json",
        "phases.json",
        "result.json",
        "validation-closure.json",
        "manifest.json",
        "v2-audit.log",
        "v2-audit.json",
        "v2-audit.service.json",
        "STOP-v2-audit.json",
        "v2-prepare.json",
        "v2-prepare.service.json",
        "v2-prepare.log",
    ]
    scope["new_optional_evidence_files"] = [
        str((D / name).relative_to(P))
        for name in future
        if str((D / name).relative_to(P)) not in scope["new_required_files"]
    ]
    scope["new_optional_evidence_files"] += [
        str((PROPOSAL / "source-manifest.json").relative_to(P))
    ]
    scope["new_markdown_files"] = [
        str((PROPOSAL / "README.md").relative_to(P)),
        "docs/stage2_authority_isolation_pilot.md",
    ]
    scope["new_python_files"] = [
        str(path.relative_to(P))
        for root in (P / "scripts/isolation_pilot_v2", D)
        for path in root.glob("*.py")
    ] + ["tests/unit/test_isolation_corrections.py"]
    scope["authorisation"] = (
        "User targeted correction pass: versioned sources/templates/runbook and exact new "
        "evidence/tests; append only four reports. Original pilot source, seal, runbook "
        "and preflight evidence protected. No activation."
    )
    (D / "scope.json").write_bytes(json_bytes(scope))
    print(
        json.dumps(
            {
                "candidate_sources": len(current),
                "explained_differences": len(delta),
                "historical_identity_union": scope["known_manifest_union_names"],
                "supplementary_paths": scope["supplementary_count"],
            }
        )
    )


if __name__ == "__main__":
    main()
