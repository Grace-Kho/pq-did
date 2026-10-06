"""Bounded metadata/source-seal preparation, not a historical content audit."""

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
P = BASE.parents[2]
sys.path.insert(0, str(P / "scripts/isolation_pilot"))
from layout import PROPOSAL, check, digest, json_bytes, read_json  # noqa: E402
from provision import source_files  # noqa: E402


def main():
    files = source_files()
    (PROPOSAL / "source-manifest.json").write_bytes(
        json_bytes(
            {
                "package": "S2-AUTHORITY-ISOLATION-PILOT-1",
                "kind": "new authorisation seal; does not replace any historical baseline",
                "sha256": {str(p.relative_to(P)): digest(p) for p in files},
                "synthetic_inputs_sha256": {
                    p.name: digest(p) for p in (BASE / "activation-inputs").iterdir()
                },
                "native_library_sha256": digest(P / "native/.deps/install/lib/liboqs.so"),
                "fresh_venv_command": [
                    "/usr/bin/python3.14",
                    "-I",
                    "-B",
                    "-m",
                    "venv",
                    "--without-pip",
                    "/opt/pqiso/r1/.venv",
                ],
                "source_files": len(files),
                "source_bytes": sum(p.stat().st_size for p in files),
            }
        )
    )
    old = read_json(P / "docs/data/s2_authority_isolation_plan_1/scope.json", 262144)
    name = "docs/data/s2_authority_isolation_plan_1/manifest.json"
    seal = read_json(P / name)
    old["baseline_identities"][name] = digest(P / name)
    old["supplementary_manifests"][name] = len(seal["sha256"])
    old["authorisation"] = (
        "User S2-AUTHORITY-ISOLATION-PILOT-1: exact two IPC source changes and "
        "listed new sources/tests/docs/evidence; original baselines protected. "
        "Activation and actual-identity cases await user section 5 approval."
    )
    old["supplementary_count"] = 492
    old["known_manifest_union_names"] = 9261
    old["authorised_source_changes"] = [
        "src/pqdid/persistence/owner_ipc.py",
        "src/pqdid/persistence/owner_service.py",
    ]
    new_roots = [P / "scripts/isolation_pilot", PROPOSAL, BASE]
    paths = sorted(p for root in new_roots for p in root.rglob("*") if p.is_file())
    old["new_python_files"] = [str(p.relative_to(P)) for p in paths if p.suffix == ".py"]
    old["new_python_files"] += [
        "src/pqdid/persistence/endpoint_policy.py",
        "tests/unit/test_isolation_prerequisites.py",
    ]
    old["new_markdown_files"] = [
        "docs/stage2_authority_isolation_pilot.md",
        "docs/proposals/s2_authority_isolation_pilot_1/README.md",
    ]
    old["new_required_files"] = sorted(
        set(str(p.relative_to(P)) for p in paths)
        | set(old["new_python_files"])
        | set(old["new_markdown_files"])
        | {str((BASE / "scope.json").relative_to(P))}
    )
    optional = ["manifest.json", "validation.json", "result.json", "phases.json"]
    for command in (
        "prepare",
        "format-source-final",
        "quality-final",
        "quality-release",
        "format-release-source",
        "format",
        "static-final",
        "full-audit",
    ):
        optional += [command + suffix for suffix in (".log", ".json", ".service.json")]
    optional += ["STOP-full-audit.json"]
    old["new_optional_evidence_files"] = [
        str((BASE / n).relative_to(P))
        for n in optional
        if str((BASE / n).relative_to(P)) not in old["new_required_files"]
    ]
    (BASE / "scope.json").write_bytes(json_bytes(old))
    check(len(seal["sha256"]) == 80, "preceding-seal-count")
    print(
        json.dumps(
            {
                "metadata_prepared": True,
                "historical_content_compared": False,
                "source_files_sealed": len(files),
                "new_required_files": len(old["new_required_files"]),
                "baseline_identity": old["baseline_identities"][name],
            }
        )
    )


if __name__ == "__main__":
    main()
