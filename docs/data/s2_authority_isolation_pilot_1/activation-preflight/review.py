"""Read-only seal/launcher diagnostic; never calls privileged pilot entry points."""

import importlib
import json
import subprocess
import sys
from pathlib import Path

P = Path("/home/grace/projects/pq-did")
D = Path(__file__).resolve().parent
E = D.parent
sys.path.insert(0, str(P / "scripts/isolation_pilot"))
layout = importlib.import_module("layout")
provision = importlib.import_module("provision")


def main():
    seal_path = layout.PROPOSAL / "source-manifest.json"
    seal_digest = layout.digest(seal_path)
    assert seal_digest == "7fd9f0e1bcedf7ed7756b4f25bdde6458e06650cdece62841100c0f636e09086"
    seal = layout.read_json(seal_path, 262144)
    sources = provision.source_files()
    actual_names = {str(p.relative_to(P)) for p in sources}
    assert actual_names == set(seal["sha256"])
    source_results = {
        name: layout.digest(P / name) == value for name, value in seal["sha256"].items()
    }
    assert all(source_results.values())
    inputs = E / "activation-inputs"
    assert {p.name for p in inputs.iterdir()} == set(seal["synthetic_inputs_sha256"])
    fixture_results = {
        name: layout.digest(inputs / name) == value
        for name, value in seal["synthetic_inputs_sha256"].items()
    }
    assert all(fixture_results.values())
    package_path = E / "manifest.json"
    assert (
        layout.digest(package_path)
        == "daf88fd67840b059fe0e27da351a073a1a67bb037871c399fee2082f6ac1cc17"
    )
    package = layout.read_json(package_path, 262144)
    package_results = {
        name: layout.digest(P / name) == value for name, value in package["sha256"].items()
    }
    assert all(package_results.values())
    ledger = E / "run-ledger.json"
    try:
        layout.read_json(ledger)
    except layout.PilotError as error:
        diagnostic = {"exception": type(error).__name__, "label": str(error)}
    else:
        raise AssertionError("The source-inspection finding was not reproduced")
    assert diagnostic["label"] == "input-size"
    templates = sorted(p.name for p in layout.PROPOSAL.glob("*.in"))
    assert len(templates) == 7
    result = {
        "kind": "targeted-read-only-diagnostic-not-complete-preservation-audit",
        "inspection_completed": True,
        "activation_preflight_passed": False,
        "manifest_sha256": seal_digest,
        "source_inventory_exact": True,
        "source_comparisons": source_results,
        "fixture_inventory_exact": True,
        "fixture_comparisons": fixture_results,
        "preceding_package_manifest_sha256": layout.digest(package_path),
        "preceding_package_comparisons_before_documentation_append": package_results,
        "templates_reviewed": templates,
        "ledger_sha256": layout.digest(ledger),
        "ledger_bytes": ledger.stat().st_size,
        "ledger_reader_limit_bytes": layout.LIMIT,
        "ledger_read_diagnostic": diagnostic,
        "prior_guarded_commands": len(json.loads(ledger.read_text())),
        "prior_guarded_seconds": sum(r["seconds"] for r in json.loads(ledger.read_text())),
        "privileged_entry_points_invoked": [],
        "actual_identity_cases_executed": 0,
        "test_suites_repeated": 0,
        "proofs": 0,
        "zkvm_executions": 0,
    }
    (D / "inspection.json").write_text(json.dumps(result, indent=2) + "\n")
    assert json.loads((D / "inspection.json").read_text()) == result
    print(
        json.dumps(
            {
                "inspection_completed": True,
                "activation_preflight_passed": False,
                "sources": len(source_results),
                "fixtures": len(fixture_results),
                "historical_package_paths": len(package_results),
                "ledger_read": diagnostic,
            }
        )
    )
    core = "/usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-259.so"
    commands = [
        ["/usr/bin/objdump", "-s", "--start-address=0x2013c0", "--stop-address=0x2013e0", core],
        ["/usr/bin/objdump", "-d", "--start-address=0x16afd0", "--stop-address=0x16b200", core],
        ["/usr/bin/objdump", "-d", "--start-address=0x16b3e9", "--stop-address=0x16b477", core],
        ["/usr/bin/objdump", "-d", "--start-address=0x16b71a", "--stop-address=0x16b73e", core],
    ]
    binary = {"path": core, "sha256": layout.digest(core), "commands": []}
    for command in commands:
        output = subprocess.run(command, capture_output=True, text=True, timeout=5, check=True)
        binary["commands"].append(
            {"command": command, "stdout": output.stdout, "stderr": output.stderr}
        )
    (D / "installed-systemd-inspection.json").write_text(json.dumps(binary, indent=2) + "\n")


if __name__ == "__main__":
    main()
