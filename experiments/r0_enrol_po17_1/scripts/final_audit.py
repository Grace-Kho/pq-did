"""Check preservation, actual receipt evidence and the bounded cumulative ledger."""

import ast
import hashlib
import json
import re
import subprocess
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


preserved = read("evidence/protected_before.json")
changed = [name for name, digest in preserved.items() if sha(P / name) != digest]
assert set(changed) <= {"docs/status.md", "docs/traceability.md"}, changed
frozen = read("evidence/manifest-before-launch.json")
assert all(sha(R / name) == digest for name, digest in frozen["frozen_sha256"].items())
ledger = read("evidence/run_ledger.json")
assert ledger["execution_runs"] == 1 and ledger["proof_attempts"] == 1
proofs = [r for r in ledger["runs"] if r["phase"] == "prove"]
assert len(proofs) == 1 and proofs[0]["slot"] == 2 and proofs[0]["status"] == "pass"
assert proofs[0]["memory_max"] == 2**31 and proofs[0]["limit_seconds"] == 600
assert all(
    read(f"evidence/{name}.json")["status"] == "pass"
    for name in ["execution", "attempt2", "verify2", "tamper2"]
)
execution = read("evidence/execution.result.json")
info = read("receipts/attempt2.bin.json")
assert execution["accepted"] and execution["journal_matches_expected"]
assert execution["segments"] == info["stats"]["segments"] == 3
assert all(s["po2"] == 17 for s in execution["segment_records"])
assert execution["user_cycles"] == info["stats"]["user_cycles"] == 196311
assert execution["padded_capacity"] == info["stats"]["total_cycles"] == 393216
assert info["stats"]["paging_cycles"] + info["stats"]["reserved_cycles"] + 196311 == 393216
assert info["mode"] == "Succinct" and info["hash_suite"] == "poseidon2"
assert info["serialized_receipt_bytes"] == (R / "receipts/attempt2.bin").stat().st_size < 10 * 2**20
assert read("evidence/verify.result.json")["verified"]
negative = read("evidence/adversarial.result.json")
assert negative["verified"] and set(negative["rejection_tests"]) == {
    "journal",
    "public statement",
    "public context",
    "expected image",
    "operation",
    "seal",
    "hash suite",
    "trailing bytes",
}
for name in ["verify2", "tamper2"]:
    service = read(f"evidence/{name}.service.json")
    assert (
        service["after"]["memory.max"] == str(2**30) and service["after"]["memory.swap.max"] == "0"
    )
    assert service["temporary_bytes_at_exit"] is None
cumulative = read("evidence/cumulative_attempt_ledger.json")
assert (
    cumulative["attempts_used"] == 2
    and cumulative["remaining"] == 1
    and cumulative["package_closed"]
)
assert sha(R / cumulative["previous_ledger"]) == cumulative["previous_ledger_sha256"]
assert cumulative["attempts"][-1]["receipt_sha256"] == sha(R / "receipts/attempt2.bin")
assert (R / "evidence/STOP.json").exists()
for p in (R / "scripts").glob("*.py"):
    ast.parse(p.read_text())
for p in (R / "evidence").glob("*.json"):
    json.loads(p.read_text())
for name in ["Cargo.toml", "Cargo.lock", "host/Cargo.toml"]:
    tomllib.loads((R / name).read_text())
for p in [P / "docs/stage3_r0_enrol_po17.md", R / "CONTRACT.md"]:
    for link in re.findall(r"\]\(([^)]+)\)", p.read_text()):
        if not link.startswith(("http:", "https:", "#")):
            assert (p.parent / link.split("#")[0]).exists(), link
assert all(p.stat().st_size <= 65536 for p in (R / "evidence").glob("*.log"))
before = (R / "evidence/run_ledger.json").read_bytes()
q = subprocess.run(
    [
        "/usr/bin/python3",
        str(R / "scripts/run_limited.py"),
        "--seconds",
        "600",
        "--slot",
        "3",
        "prove",
        "attempt3",
        "--",
        "bad",
    ],
    capture_output=True,
    text=True,
    timeout=5,
)
assert q.returncode != 0 and "package resource stop recorded" in q.stderr
assert (R / "evidence/run_ledger.json").read_bytes() == before
out = {
    "passed": True,
    "preserved_files": len(preserved),
    "allowed_changes": changed,
    "frozen_files_unchanged": len(frozen["frozen_sha256"]),
    "execution_only_runs": 1,
    "new_proof_attempts": 1,
    "cumulative_proof_attempts": 2,
    "remaining_proof_attempts": 1,
    "actual_succinct_receipts": 1,
    "independent_verification": True,
    "tamper_rejections": 8,
    "closed_package_probe": q.stderr.strip(),
    "experiment_disk_bytes": used_disk(),
    "output_bytes": output_disk(),
    "diagnostic_bytes": output_disk(True),
    "temporary_bytes_at_audit": sum(
        p.stat().st_size for p in (R / "tmp").rglob("*") if p.is_file()
    ),
}
assert (
    out["experiment_disk_bytes"] < 9 * 2**30
    and out["output_bytes"] < 240 * 2**20
    and out["diagnostic_bytes"] < 60 * 2**20
)
(R / "evidence/final-audit.result.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps(out, indent=2))
