"""Finite configuration, execution-outcome and preservation checks; no zkVM run."""

import ast
import hashlib
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
CYCLE = ROOT.parent / "r0_credvalid_cycle_1"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_text())


def save(name, value):
    (ROOT / "evidence" / name).write_text(json.dumps(value, indent=2) + "\n")


before = load(ROOT / "evidence/protected_before.json")
changed = [name for name, digest in before.items() if sha(PROJECT / name) != digest]
assert set(changed) == {"docs/status.md", "docs/traceability.md"}, changed
build = load(ROOT / "evidence/build-manifest.json")
reg = build["guest"]
for kind in ("elf", "program"):
    assert sha(ROOT / reg[kind]) == sha(CYCLE / reg[kind]) == reg[kind + "_sha256"]
assert build["guest_rebuilt"] is False and reg["features"] == "none"
assert not (ROOT / "methods").exists()
assert sha(ROOT / "host/src/main.rs") == build["host_source_SHA256"]
assert sha(ROOT / "target/release/pqdid-r0-host") == build["host_binary_SHA256"]
assert sha(ROOT / "Cargo.lock") == sha(CYCLE / "Cargo.lock") == build["host_lock_SHA256"]
for path in (ROOT / "relation").rglob("*"):
    if path.is_file():
        assert sha(path) == sha(CYCLE / path.relative_to(ROOT))
for source, digest in reg["source_sha256"].items():
    assert sha(CYCLE / source) == digest
native = load(CYCLE / "evidence/native_after.json")
assert len(native) == 35 and all(row["matched"] for row in native)
assert "6 passed; 0 failed; 0 ignored" in (CYCLE / "evidence/correction-validation.log").read_text()
config = load(ROOT / "config.json")
assert config == build["config"]
assert config["session_limit_user_cycles"] == 1 << 24
assert config["segment_limit_po2"] == 16 and config["memory_bytes"] == 2 << 30
assert config["swap_bytes"] == 0 and config["max_executions"] == 2
source = (ROOT / "host/src/main.rs").read_text()
assert ".session_limit(Some(1 << 24))" in source and ".segment_limit_po2(16)" in source
assert "client.execute(" in source and ".prove(" not in source and "ProverOpts" not in source

ledger = load(ROOT / "evidence/run_ledger.json")
runs = [row for row in ledger["runs"] if row["phase"] == "execute"]
assert len(runs) == ledger["execution_runs"] == 2 and ledger["proof_attempts"] == 0
assert [row["slot"] for row in runs] == [1, 2]
summary = []
for run in runs:
    assert run["status"] == "pass" and run["stop_reason"] is None
    assert run["memory_max"] == 2 << 30 and run["sampled_swap_peak"] == 0
    assert run["wall_seconds"] < run["limit_seconds"] == 60
    assert run["effective_cgroup"]["memory.max"] == str(2 << 30)
    assert run["effective_cgroup"]["memory.swap.max"] == "0"
    assert run["cgroup_memory_peak_bytes"] < 2 << 30
    assert run["sampled_process_tree_RSS_peak"] < 2 << 30
    assert "max 0" in run["memory_events"] and "oom_kill 0" in run["memory_events"]
    assert run["sampled_temporary_bytes_peak"] == run["temporary_bytes_at_exit"] == 0
    name = run["name"]
    result = load(ROOT / f"evidence/{name}.result.json")
    progress = load(ROOT / f"evidence/{name}.progress.json")
    service = load(ROOT / f"evidence/{name}.service.json")
    assert service["available_before_target"] >= (2 << 30) + (2 << 30)
    assert service["external_routes"] == 0
    assert result["image"] == reg["image"] and result["config"] == config
    assert result["proof_attempts"] == 0 and result["receipt_generated"] is False
    assert progress["completed_segments"] == result["completed_segments"]
    assert progress["completed_user_cycles"] == result["completed_segment_user_cycles"]
    assert progress["padded_capacity"] == result["padded_segment_capacity"]
    hist = result["segment_po2_histogram"]
    assert sum(hist.values()) == result["completed_segments"]
    assert (
        sum((1 << int(po2)) * count for po2, count in hist.items())
        == result["padded_segment_capacity"]
    )
    records = (ROOT / f"evidence/{name}.segments.jsonl").read_text().splitlines()
    assert len(records) == progress["retained_segment_records"] == 256
    assert all(json.loads(row)["index"] == i for i, row in enumerate(records))
    assert (ROOT / f"evidence/{name}.stdout").stat().st_size <= 65536
    assert (ROOT / f"evidence/{name}.stderr").stat().st_size <= 65536
    summary.append({"execution": result, "resources": run, "service": service})

valid, negative = (row["execution"] for row in summary)
expected = (ROOT / "fixtures/expected-public-journal.bin").read_bytes()
assert (ROOT / "evidence/valid.public-journal.bin").read_bytes() == expected
assert valid["accepted"] and valid["status"] == "completed" and valid["exit_code"] == "Halted(0)"
assert valid["user_cycles"] == valid["completed_segment_user_cycles"] == 16313474
assert valid["margin_below_cap"] == 16777216 - valid["user_cycles"] == 463742
assert (
    valid["journal_matches_expected"]
    and valid["actual_public_journal_bytes"] == len(expected) == 5147
)
assert valid["actual_public_journal_sha256"] == hashlib.sha256(expected).hexdigest()
assert (
    negative["status"] == "credential_rejected"
    and negative["error"] == "Guest panicked: relation rejected"
)
assert negative["accepted"] is False and negative["returned_session"] is False
assert negative["user_cycles"] is None and negative["actual_public_journal_bytes"] is None
assert not (ROOT / "evidence/negative.public-journal.bin").exists()
reference = load(ROOT / "evidence/negative-reference.json")
assert reference["expected_acceptance"] is False and reference["cryptographic_verifier_called"]
assert reference["bounded_verifier_calls"] == 1
recovery = load(ROOT / "evidence/reference-record-recovery.json")
assert (
    sha(ROOT / "evidence" / recovery["resource_record_preserved_as"]) == recovery["resource_SHA256"]
)
for case in load(ROOT / "fixtures/cases.json")["cases"]:
    for kind, key in [("public", "public_SHA256"), ("private", "private_fixture_SHA256")]:
        assert sha(ROOT / case[kind]) == sha(CYCLE / case[kind]) == case[key]

assert load(ROOT / "evidence/STOP.json")["further_execution_authorised"] is False
probe = subprocess.run(
    [
        "python3",
        str(ROOT / "scripts/run_limited.py"),
        "--seconds",
        "1",
        "--slot",
        "1",
        "execute",
        "forbidden",
        "--",
        "/bin/false",
    ],
    text=True,
    capture_output=True,
    timeout=5,
)
assert probe.returncode and "package resource stop" in probe.stderr
assert load(ROOT / "evidence/run_ledger.json")["execution_runs"] == 2
assert not list(ROOT.glob("receipts/*"))

files = []
for base, dirs, names in os.walk(ROOT):
    if Path(base) == ROOT:
        dirs[:] = [d for d in dirs if d not in ("target", "tooling", "tmp")]
    files.extend(Path(base) / name for name in names)
for path in files:
    if path.suffix == ".json":
        load(path)
    elif path.suffix == ".py":
        ast.parse(path.read_text())
    elif path.suffix in (".toml", ".lock") and path.name != "run.lock":
        tomllib.loads(path.read_text())
diagnostic = sum(p.stat().st_size for p in files)
disk = sum(p.stat().st_size for p in ROOT.parent.rglob("*") if p.is_file())
assert diagnostic < 60 * 1024**2 and disk < 9 * 1024**3
build_seconds = sum(r["wall_seconds"] for r in ledger["runs"] if r["phase"] in ("build", "setup"))
execution_seconds = sum(r["wall_seconds"] for r in runs)
assert build_seconds < 1200 and execution_seconds < 300
excluded = {
    "final-checks.log",
    "final-checks.json",
    "final-checks.service.json",
    "run_ledger.json",
    "run.lock",
    "final-audit.json",
    "manifest.json",
}
assets = {
    str(p.relative_to(ROOT)): {"SHA256": sha(p), "bytes": p.stat().st_size}
    for p in sorted(files)
    if p.name not in excluded
}
save(
    "manifest.json",
    {
        "package": "R0-CREDVALID-EXEC24-1",
        "build": build,
        "runs": summary,
        "native_validation_reused": {"tests": 6, "comparisons": 35},
        "proof_attempts": 0,
        "remaining_proof_attempts": 3,
        "assets": assets,
    },
)
save(
    "final-audit.json",
    {
        "status": "pass",
        "protected_files_checked": len(before),
        "authorised_existing_files_changed": changed,
        "all_other_protected_files_unchanged": True,
        "guest_rebuilt": False,
        "guest_code_and_inputs_unchanged": True,
        "dependency_changes": False,
        "execution_runs": 2,
        "proof_attempts": 0,
        "unused_proof_attempts": 3,
        "valid_complete_user_cycles": valid["user_cycles"],
        "valid_margin_cycles": valid["margin_below_cap"],
        "negative_rejected_without_acceptance_journal": True,
        "negative_total_cycles_unavailable": True,
        "diagnostic_bytes_at_audit": diagnostic,
        "all_experiment_disk_bytes_at_audit": disk,
        "build_setup_seconds": build_seconds,
        "guarded_execution_seconds": execution_seconds,
        "closed_package_replay_refused": True,
    },
)
for document in ["stage3_r0_credvalid_exec24.md", "status.md", "traceability.md"]:
    path = PROJECT / "docs" / document
    for link in re.findall(r"\]\(([^)]+)\)", path.read_text()):
        if not link.startswith(("http", "#", "mailto:")):
            assert (path.parent / link.split("#")[0]).exists(), (document, link)
print("Configuration, two outcomes, identities, preservation and closed-package checks passed")
