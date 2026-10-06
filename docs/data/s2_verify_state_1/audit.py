"""Preservation/document/data audit; reuse completed implementation checks."""

import ast
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit

D = Path(__file__).resolve().parent
P = D.parents[2]
ALLOWED = {"docs/status.md", "docs/traceability.md", "docs/spec_issues.md"}
NEW = [
    "src/pqdid/verifier_state.py",
    "tests/unit/verifier_state_cases.py",
    "tests/unit/test_verifier_state.py",
    "docs/stage2_verifier_state.md",
]


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(name, data):
    (D / name).write_text(json.dumps(data, indent=2) + "\n")


def seal():
    paths = [P / name for name in [*NEW, *sorted(ALLOWED)]]
    paths += [path for path in D.rglob("*") if path.is_file() and path.name != "manifest.json"]
    save(
        "manifest.json",
        {
            "package": "S2-VERIFY-STATE-1",
            "sha256": {str(path.relative_to(P)): sha(path) for path in sorted(paths)},
            "self_hash_excluded": True,
            "new_proofs": 0,
            "new_zkvm_executions": 0,
            "proof_attempts_used": 2,
            "proof_attempts_unused": 1,
        },
    )
    print("Final manifest sealed; no tests or backend invoked.")


def main():
    before = json.loads((D / "preservation-before.json").read_text())
    assert len(before) == 8694
    missing, changed = [], []
    for name, digest in before.items():
        path = P / name
        if not path.is_file():
            missing.append(name)
        elif sha(path) != digest:
            changed.append(name)
    assert not missing, missing
    assert set(changed) == ALLOWED, changed
    assert sha(P / "docs/manuscript/PQ_DID__Implementation.pdf") == (
        "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    ledger_path = P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
    ledger = json.loads(ledger_path.read_text())
    assert ledger["attempts_used"] == 2 and ledger["remaining"] == 1
    assert sha(ledger_path) == "fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5"
    counts = {}
    for name, expected in [("focused", 58), ("regression", 29)]:
        root = ET.parse(D / (name + ".xml")).getroot()
        suites = root.findall("testsuite")
        count = sum(int(suite.attrib["tests"]) for suite in suites)
        assert count == expected
        assert all(
            int(suite.attrib[key]) == 0
            for suite in suites
            for key in ["failures", "errors", "skipped"]
        )
        counts[name] = count
    assert sum(counts.values()) <= 100
    runs = json.loads((D / "run-ledger.json").read_text())
    completed = [run for run in runs if run["name"] != "final-audit"]
    assert {run["name"] for run in completed} == {"focused", "regression", "quality", "format"}
    for run in completed:
        assert run["status"] == "pass" and run["exit_code"] == 0 and run["stop"] is None
        assert run["seconds"] < 60 and run["sampled_tree_RSS_peak"] <= 268435456
        controls = run["service"]["before"]
        assert controls["memory.max"] == "268435456" and controls["memory.swap.max"] == "0"
        assert run["service"]["allowed_cpus"] == [0, 1]
        events = dict(
            line.split() for line in run["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
    assert sum(run["seconds"] for run in completed) < 300
    assert not (D / "STOP.json").exists()

    scripts = [
        *NEW[:3],
        str(D.relative_to(P) / "run_checks.py"),
        str(D.relative_to(P) / "audit.py"),
    ]
    quality = []
    for operation in ["check", "format"]:
        command = [str(P / ".venv/bin/ruff"), operation]
        if operation == "format":
            command += ["--check"]
        command += ["--no-cache", *scripts]
        result = subprocess.run(
            command, cwd=P, capture_output=True, text=True, timeout=10, check=True
        )
        quality.append(
            {"command": command, "exit_code": result.returncode, "output": result.stdout}
        )
    for name in scripts:
        ast.parse((P / name).read_text(), filename=name)
    json_count = 0
    for path in D.rglob("*.json"):
        json.loads(path.read_text())
        json_count += 1
    links = []
    pending = {D / "validation.json", D / "manifest.json"}
    for name in [*sorted(ALLOWED), NEW[3]]:
        path = P / name
        content = path.read_text()
        assert content.count("```") % 2 == 0, name
        assert not any(line.rstrip() != line for line in content.splitlines()), name
        for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", content):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            assert destination.exists() or destination in pending, (name, target)
            links.append(destination)
    assert sum(path.stat().st_size for path in D.rglob("*") if path.is_file()) < 10 * 1024**2
    save(
        "validation.json",
        {
            "package": "S2-VERIFY-STATE-1",
            "passed": True,
            "test_counts": counts,
            "tests_total": sum(counts.values()),
            "failures": 0,
            "skips": 0,
            "protected_files": len(before),
            "unchanged_protected_files": len(before) - len(changed),
            "allowed_changed_files": sorted(changed),
            "missing_files": missing,
            "manuscript_identity_matches": True,
            "original_source_encodings_vectors_dependencies_preserved": True,
            "historical_evidence_and_ledgers_preserved": True,
            "proof_attempt_ledger_sha256": sha(ledger_path),
            "proof_attempts_used": 2,
            "unused": 1,
            "new_proofs": 0,
            "new_zkvm_executions": 0,
            "dependencies_installed": 0,
            "proof_parameters_changed": False,
            "CPU_proving_paused": True,
            "local_markdown_link_paths_checked": len(links),
            "JSON_files_parsed": json_count,
            "final_lint_and_format": quality,
            "initial_four_check_wall_seconds": sum(run["seconds"] for run in completed),
            "validation_reused": [
                "Earlier reference/circuit validation; only relevant regressions rerun",
                "Original R0 six native tests/35 comparisons and enrolment proof evidence",
            ],
            "scope": "Reference-model lifecycle results only; no knowledge/ZK/proof claim",
        },
    )
    print(
        json.dumps(
            {
                "passed": True,
                "tests": counts,
                "preserved_files": len(before) - 3,
                "links": len(links),
                "attempts": "two used, one unused",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    if "--seal" in sys.argv:
        seal()
    else:
        main()
