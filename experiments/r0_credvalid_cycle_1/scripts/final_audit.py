"""Finite preservation, identity and bounded-result audit; never executes a guest."""

import ast
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
BASE = ROOT.parent / "r0_succinct_feasibility_1"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(name, value):
    (ROOT / "evidence" / name).write_text(json.dumps(value, indent=2) + "\n")


before = json.loads((ROOT / "evidence/protected_before.json").read_text())
changed = [p for p, digest in before.items() if sha(PROJECT / p) != digest]
assert set(changed) == {"docs/status.md", "docs/traceability.md"}, changed
assert sha(PROJECT / "docs/manuscript/PQ_DID__Implementation.pdf") == (
    "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
)
original = json.loads((ROOT / "evidence/baseline.json").read_text())
for name, asset in original["manifest"]["assets"].items():
    path = (
        next(
            (BASE / "tooling/cargo/registry/src").glob(
                "*/risc0-zkos-v1compat-2.2.3/elfs/v1compat.elf"
            )
        )
        if name == "pinned_kernel_v1compat.elf"
        else BASE / name
    )
    assert sha(path) == asset["SHA256"], name

for path in ["Cargo.lock", "methods/guest/Cargo.lock"]:
    sets = []
    for directory in (ROOT, BASE):
        packages = tomllib.loads((directory / path).read_text())["package"]
        sets.append({(p["name"], p["version"], p["checksum"]) for p in packages if "checksum" in p})
    assert sets[0] == sets[1], path

registrations = []
for path in sorted((ROOT / "artifacts").glob("*.json")):
    reg = json.loads(path.read_text())
    for kind in ("elf", "program"):
        assert sha(ROOT / reg[kind]) == reg[kind + "_sha256"]
    bundle = ROOT / "snapshots/builds" / reg["label"]
    for source, digest in reg["source_sha256"].items():
        assert sha(bundle / source) == digest, (reg["label"], source)
    registrations.append(reg)
for row in json.loads((ROOT / "evidence/source_api_review.json").read_text()):
    assert sha(ROOT / row["snapshot"]) == row["SHA256"]

ledger = json.loads((ROOT / "evidence/run_ledger.json").read_text())
runs = [r for r in ledger["runs"] if r["phase"] == "execute"]
assert len(runs) == ledger["execution_runs"] == 5
assert [r["slot"] for r in runs] == [1, 2, 3, 4, 6]
assert ledger["proof_attempts"] == original["old_proof_attempts"] == 0
assert not list(ROOT.glob("receipts/*")) and not list(BASE.glob("receipts/*.bin"))
summary = []
for run in runs:
    assert run["status"] == "pass" and run["memory_max"] == 2 * 1024**3
    assert run["wall_seconds"] < run["limit_seconds"] == 60
    assert run["sampled_swap_peak"] == 0 and run["network"] is False
    assert run["effective_cgroup"]["memory.max"] == str(2 * 1024**3)
    assert run["effective_cgroup"]["memory.swap.max"] == "0"
    name = run["name"]
    result = json.loads((ROOT / f"evidence/{name}.result.json").read_text())
    analysis = json.loads((ROOT / f"evidence/{name}.analysis.json").read_text())
    assert result["session_limit_user_cycles"] == 4194304
    assert result["segment_limit_po2"] == 16 and result["proof_attempts"] == 0
    if run["slot"] in (1, 6):
        assert result["status"] == "cycle_limit"
        assert result["error"] == "Session limit exceeded: 4194304 >= 4194304"
        assert "user_cycles" not in result
    else:
        assert result["status"] == "completed" and result["journal_matches_expected"]
        assert result["user_cycles"] == analysis["completed_segment_user_cycles"]
    raw = (ROOT / f"evidence/{name}.markers").read_bytes()
    assert len(raw) == 16 * analysis["marker_count"] <= 65536
    assert (ROOT / f"evidence/{name}.stdout").stat().st_size == 0
    if run["slot"] == 6:
        assert not raw and analysis["active_phase_at_cap"] is None
    else:
        assert analysis["empty_marker_intervals"] == [153, 153]
    assert len(result["completed_segment_metadata"]) < 256
    memory = re.search(r"Memory peak: (.+)", (ROOT / run["log"]).read_text())
    assert memory and "swap: 0B" in memory[1]
    summary.append(
        {
            "name": name,
            "slot": run["slot"],
            "status": result["status"],
            "user_cycles": result.get("user_cycles"),
            "host_execute_seconds": result["seconds"],
            "reported_systemd_memory_peak": memory[1],
            "marker_bytes": len(raw),
            "segment_prefix": {k: v for k, v in analysis.items() if k.startswith("completed_")},
        }
    )

for suffix in ("before", "after"):
    native = json.loads((ROOT / f"evidence/native_{suffix}.json").read_text())
    assert len(native) == 35 and all(row["matched"] for row in native)
test_log = (ROOT / "evidence/correction-validation.log").read_text()
assert "6 passed; 0 failed; 0 ignored" in test_log and "35 native comparisons passed" in test_log
for case in json.loads((ROOT / "fixtures/cases.json").read_text())["cases"]:
    for field, key in [("public", "public_SHA256"), ("private", "private_fixture_SHA256")]:
        assert sha(ROOT / case[field]) == case[key]
for name in ("component_fixture", "ntt_fixture"):
    fixture = json.loads((ROOT / f"evidence/{name}.json").read_text())
    path = ROOT / fixture["fixture"]
    assert sha(path) == fixture["SHA256"] and path.stat().st_mode & 0o077 == 0

# Reject a closed-package replay before a transient service or guest can start.
assert (ROOT / "evidence/STOP.json").exists()
probe = subprocess.run(
    [
        "python3",
        str(ROOT / "scripts/run_limited.py"),
        "--seconds",
        "1",
        "execute",
        "closed",
        "--",
        "/bin/false",
    ],
    text=True,
    capture_output=True,
    timeout=5,
)
assert probe.returncode and "package resource stop" in probe.stderr
assert json.loads((ROOT / "evidence/run_ledger.json").read_text())["execution_runs"] == 5

files = [
    p
    for p in ROOT.rglob("*")
    if p.is_file() and p.relative_to(ROOT).parts[0] not in ("tooling", "target", "tmp")
]
for path in files:
    if path.suffix == ".py":
        ast.parse(path.read_text())
    if path.suffix == ".json":
        json.loads(path.read_text())
    if path.suffix in (".toml", ".lock") and path.name != "run.lock":
        tomllib.loads(path.read_text())

disk = sum(p.lstat().st_size for p in ROOT.parent.rglob("*") if p.is_file())
diagnostics = sum(p.stat().st_size for p in files)
assert disk < 9 * 1024**3 and diagnostics < 60 * 1024**2
setup = sum(r.get("wall_seconds", 0) for r in ledger["runs"] if r["phase"] in ("setup", "build"))
execution = sum(r["wall_seconds"] for r in runs)
assert setup < 1200 and execution < 300
excluded = {
    "manifest.json",
    "final_audit.json",
    "run_ledger.json",
    "final-checks.log",
    "final-checks.json",
}
assets = {
    str(p.relative_to(ROOT)): {"SHA256": sha(p), "bytes": p.stat().st_size}
    for p in sorted(files)
    if p.name not in excluded and p.name != "run.lock"
}
assets["target/release/pqdid-r0-host"] = {
    "SHA256": sha(ROOT / "target/release/pqdid-r0-host"),
    "bytes": (ROOT / "target/release/pqdid-r0-host").stat().st_size,
}
source_inventory = {
    k: v["SHA256"]
    for k, v in assets.items()
    if k.startswith(("relation/", "host/", "methods/", "scripts/"))
}
save(
    "manifest.json",
    {
        "package": "R0-CREDVALID-CYCLE-1",
        "baseline": "evidence/baseline.json",
        "source_identity_kind": "SHA-256 inventory; project has no Git repository",
        "source_identity": hashlib.sha256(
            json.dumps(source_inventory, sort_keys=True).encode()
        ).hexdigest(),
        "toolchain_and_original_flags": original["manifest"]["compiler"],
        "registry_dependencies_unchanged": True,
        "registrations": registrations,
        "runs": summary,
        "assets": assets,
    },
)
save(
    "final_audit.json",
    {
        "status": "pass",
        "protected_files_checked": len(before),
        "authorised_existing_files_changed": changed,
        "all_other_protected_files_unchanged": True,
        "original_manifest_assets_unchanged": True,
        "original_proof_attempts": 0,
        "new_proof_attempts": 0,
        "unused_prior_proof_attempts": 3,
        "new_execution_runs": 5,
        "unused_execution_slots": [5],
        "closed_package_replay_rejected_before_launch": True,
        "native_comparisons_before_and_after": [35, 35],
        "corrected_native_unit_tests": 6,
        "diagnostic_bytes_at_audit": diagnostics,
        "all_experiment_disk_bytes_at_audit": disk,
        "setup_build_seconds": setup,
        "guarded_execution_seconds": execution,
        "run_summary": summary,
        "note": "Manifest excludes final-check log/ledger and itself to avoid circular hashes.",
    },
)
for document in ["stage3_r0_credvalid_cycle_attribution.md", "status.md", "traceability.md"]:
    path = PROJECT / "docs" / document
    for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
        if target.startswith(("http", "#", "mailto:")):
            continue
        assert (path.parent / target.split("#")[0]).exists(), (document, target)

print("Preservation, identities, dependencies, five-run limits and finite data checks passed")
