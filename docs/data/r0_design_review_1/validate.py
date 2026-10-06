"""Audit this documentation package; never invoke a guest, verifier or prover."""

import ast
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

D = Path(__file__).resolve().parent
P = D.parents[2]
ALLOWED = {"docs/status.md", "docs/spec_issues.md", "docs/traceability.md"}
DOCS = sorted(ALLOWED | {"docs/stage3_r0_design_review.md"})
OUTPUTS = {D / "validation.json", D / "manifest.json"}


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


before = read(D / "preservation-before.json")
assert len(before) == 8670
changed = []
missing = []
for relative, digest in before.items():
    path = P / relative
    if not path.is_file():
        missing.append(relative)
    elif sha(path) != digest:
        changed.append(relative)
assert not missing, missing
assert set(changed) == ALLOWED, changed

ledger_path = P / "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json"
ledger = read(ledger_path)
assert ledger["attempts_used"] == 2 and ledger["remaining"] == 1
assert sha(ledger_path) == "fc64f7efbd2f20cd23fec24d828f36f1460afb0b73a76ea256d0716f309d75c5"
assert sha(P / "docs/manuscript/PQ_DID__Implementation.pdf") == (
    "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
)

# This subprocess is only the new standard-library arithmetic script, with a deadline.
calc_before = sha(D / "calculations.json")
analysis_command = [sys.executable, str(D / "analyse.py")]
analysis = subprocess.run(
    analysis_command, cwd=P, capture_output=True, text=True, timeout=15, check=True
)
assert len(analysis.stdout.encode()) < 65536
assert not analysis.stderr
assert sha(D / "calculations.json") == calc_before, "Analysis was not reproducible"
calc = read(D / "calculations.json")
assert calc["phase_log_UTC_intervals_and_rates_checked"]
for relative, digest in calc["source_sha256"].items():
    assert sha(P / relative) == digest, relative

sources = read(D / "external-sources.json")
for source in sources:
    path = D / source["file"]
    assert path.stat().st_size == source["bytes"], source["file"]
    assert sha(path) == source["sha256"], source["file"]
    assert source["url"].startswith("https://")
    if "immutable_source_matches" in source:
        assert source["immutable_source_matches"]
        assert source["commit"] == "8fcc866dc94dcec3e79c3b2bc8fbc51b22f2d5e1"
assert sum("immutable_source_matches" in source for source in sources) == 5

json_files = sorted(D.rglob("*.json"))
for path in json_files:
    read(path)
for name in ("analyse.py", "validate.py"):
    ast.parse((D / name).read_text(), filename=name)

local_targets = []
link_count = 0
for relative in DOCS:
    path = P / relative
    content = path.read_text()
    assert content.count("```") % 2 == 0, relative
    assert not any(line.rstrip() != line for line in content.splitlines()), relative
    # Check local inline-link paths; old fragment anchors are outside this path-only audit.
    for target in re.findall(r"\[[^\]\n]*\]\(([^)\s]+)\)", content):
        parsed = urlsplit(target.strip("<>"))
        if parsed.scheme or not parsed.path:
            continue
        destination = (path.parent / unquote(parsed.path)).resolve()
        assert destination.exists() or destination in OUTPUTS, (relative, target)
        local_targets.append(destination)
        link_count += 1

review = (P / "docs/stage3_r0_design_review.md").read_text()
for required in (
    "35,615.571973026",
    "16,313,474",
    "50% allowance ONCE",
    "251 permutations",
    "37,952 bytes",
    "S2-VERIFY-STATE-1",
    "two used, one unused",
    "No reliable maximum percentage saving",
):
    assert required in review, required

commands = [
    [".venv/bin/python", "docs/data/r0_design_review_1/analyse.py"],
    [
        ".venv/bin/ruff",
        "format",
        "--check",
        "--no-cache",
        "docs/data/r0_design_review_1/analyse.py",
        "docs/data/r0_design_review_1/validate.py",
    ],
    [
        ".venv/bin/ruff",
        "check",
        "--no-cache",
        "docs/data/r0_design_review_1/analyse.py",
        "docs/data/r0_design_review_1/validate.py",
    ],
    [".venv/bin/python", "docs/data/r0_design_review_1/validate.py"],
]
lint_results = []
for command in commands[1:3]:
    result = subprocess.run(command, cwd=P, capture_output=True, text=True, timeout=15, check=True)
    lint_results.append(
        {"command": command, "exit_code": result.returncode, "stdout": result.stdout}
    )

result = {
    "package": "R0-DESIGN-REVIEW-1",
    "completed_UTC": datetime.now(UTC).isoformat(),
    "passed": True,
    "checks": {
        "preexisting_files_checked": len(before),
        "preexisting_files_unchanged": len(before) - len(changed),
        "allowed_document_changes": sorted(changed),
        "missing_preexisting_files": missing,
        "other_preexisting_changes": [],
        "historical_evidence_and_ledgers_unchanged": True,
        "manuscript_identity_matches": True,
        "arithmetic_reproducible": True,
        "phase_UTC_intervals_and_rates_checked_against_log": True,
        "analysis_source_hashes_checked": len(calc["source_sha256"]),
        "external_source_hashes_and_sizes_checked": len(sources),
        "tag_vs_immutable_source_matches_reused": 5,
        "JSON_files_parsed_before_final_outputs": len(json_files),
        "local_markdown_link_paths_checked": link_count,
        "markdown_check_scope": "Local inline target paths, fence balance, trailing whitespace",
        "analysis_and_validation_AST_parse": True,
        "lint_and_format": lint_results,
    },
    "proof_attempts": {"used": 2, "unused": 1, "ledger_sha256": sha(ledger_path)},
    "new_guest_executions": 0,
    "new_proof_attempts": 0,
    "candidate_installations": 0,
    "resource_limit_changes": 0,
    "new_profile_adopted": False,
    "validation_reused": [
        "Corrected guest six native tests and 35 reference comparisons; source/inputs unchanged",
        "Existing enrolment independent verification/eight tamper results; no new verification",
    ],
    "preparation_notes": [
        "Initial analysis lint found E741/E501; corrected only the new analysis script.",
        "External sources fetched as text for inspection only; no candidate compiled or installed.",
        "Paper PDF screenshot retrieval returned HTTP 403; report uses retrieved text/source code.",
        "No source/native/circuit/proof test suite rerun for this documentation-only review.",
    ],
    "reproduction_commands": commands,
    "preservation_inventory_sha256": sha(D / "preservation-before.json"),
}
write(D / "validation.json", result)
artefacts = [P / relative for relative in DOCS]
artefacts.extend(path for path in D.rglob("*") if path.is_file() and path.name != "manifest.json")
write(
    D / "manifest.json",
    {
        "package": "R0-DESIGN-REVIEW-1",
        "kind": "Review artefacts only; historical evidence not rewritten",
        "sha256": {str(path.relative_to(P)): sha(path) for path in sorted(artefacts)},
        "self_hash_excluded": True,
        "proof_attempts_used": 2,
        "proof_attempts_unused": 1,
        "decision": "Keep current RISC Zero CPU proving paused",
        "one_next_package_proposed_not_started": "S2-VERIFY-STATE-1",
    },
)
for target in local_targets:
    assert target.exists(), target
for path in OUTPUTS:
    read(path)
print(
    json.dumps(
        {
            "passed": True,
            "preserved": 8667,
            "allowed_changes": sorted(changed),
            "source_snapshots": len(sources),
            "local_link_paths": link_count,
            "ledger": "two used, one unused",
        },
        indent=2,
    )
)
