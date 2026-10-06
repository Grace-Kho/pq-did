"""Audit frozen files, preservation, receipt accounting and bounded evidence."""

import ast
import hashlib
import json
import re
import time
import tomllib
from pathlib import Path

from run_limited import output_disk, used_disk

R = Path(__file__).resolve().parents[1]
P = R.parents[1]


def read(name):
    return json.loads((R / name).read_text())


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


baseline = read("evidence/protected_before.json")
allowed = {"docs/status.md", "docs/traceability.md"}
changed = [name for name, digest in baseline.items() if sha(P / name) != digest]
assert set(changed) <= allowed, changed
manifest = read("evidence/manifest-before-launch.json")
assert all(sha(R / name) == digest for name, digest in manifest["frozen_sha256"].items())
ledger = read("evidence/run_ledger.json")
proofs = [r for r in ledger["runs"] if r["phase"] == "prove"]
assert len(proofs) == ledger["proof_attempts"] <= 3
assert [r["slot"] for r in proofs] == list(range(1, len(proofs) + 1))
assert all(r["limit_seconds"] <= 600 and r["memory_max"] == 2**31 for r in proofs)
assert sum(r.get("wall_seconds", 600) for r in proofs) <= 1800
for row in proofs[1:]:
    n = row["slot"] - 1
    assert all(
        read(f"evidence/{name}{n}.json")["status"] == "pass"
        for name in ["attempt", "verify", "tamper"]
    )
receipts = [str(p.relative_to(R)) for p in (R / "receipts").glob("*.bin")]
for name in receipts:
    assert (R / name).stat().st_size <= 10 * 2**20
    assert read(name + ".json")["mode"] == "Succinct"
for path in (R / "scripts").glob("*.py"):
    ast.parse(path.read_text())
for path in (R / "evidence").glob("*.json"):
    json.loads(path.read_text())
for path in [R / "Cargo.toml", R / "Cargo.lock", R / "host/Cargo.toml"]:
    tomllib.loads(path.read_text())
for path in [P / "docs/stage3_r0_succinct_proof_1.md", R / "CONTRACT.md"]:
    for link in re.findall(r"\]\(([^)]+)\)", path.read_text()):
        if not link.startswith(("http:", "https:", "#")):
            assert (path.parent / link.split("#")[0]).exists(), link
assert all(p.stat().st_size <= 65536 for p in (R / "evidence").glob("*.log"))
assert (R / "evidence/STOP.json").exists()

result = {
    "package": "R0-SUCCINCT-PROOF-1",
    "checked_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "preserved_files": len(baseline),
    "allowed_changed_files": changed,
    "frozen_launch_files_unchanged": len(manifest["frozen_sha256"]),
    "proof_attempts": len(proofs),
    "proof_attempts_unused": 3 - len(proofs),
    "receipts": receipts,
    "proof_service_wall_seconds": sum(r["wall_seconds"] for r in proofs),
    "setup_build_wall_seconds": sum(
        r["wall_seconds"] for r in ledger["runs"] if r["phase"] in ["setup", "build"]
    ),
    "completed_check_service_seconds": sum(
        r["wall_seconds"]
        for r in ledger["runs"]
        if r["phase"] in ["check", "verify", "adversarial"] and "wall_seconds" in r
    ),
    "experiment_logical_bytes": used_disk(),
    "output_bytes": output_disk(),
    "diagnostic_bytes": output_disk(True),
    "temporary_bytes_at_audit": sum(
        p.stat().st_size for p in (R / "tmp").rglob("*") if p.is_file()
    ),
    "checks": [
        "frozen source/binary/input hashes",
        "historical preservation",
        "attempt sequence and prior verification gates",
        "receipt accounting/bounds",
        "JSON/TOML/Python syntax",
        "new documentation links",
        "bounded stream logs",
    ],
}
assert result["experiment_logical_bytes"] < 9 * 2**30
assert result["output_bytes"] < 240 * 2**20
assert result["diagnostic_bytes"] < 60 * 2**20
(R / "evidence/final-audit.result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
