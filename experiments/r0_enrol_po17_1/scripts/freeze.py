"""Freeze the new harness and preserved enrolment identities before execution."""

import hashlib
import json
import subprocess
import time
from pathlib import Path

R = Path(__file__).resolve().parents[1]
P = R.parents[1]


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


before = json.loads((R / "evidence/protected_before.json").read_text())
assert all(sha(P / name) == digest for name, digest in before.items())
ledger = (R / "evidence/run_ledger.json").read_bytes()
probes = []
for args in [
    ["--seconds", "600", "--slot", "3", "prove", "attempt3", "--", "bad"],
    ["--seconds", "601", "--slot", "2", "prove", "attempt2", "--", "bad"],
    ["--seconds", "60", "--slot", "2", "execute", "execution", "--", "bad"],
    ["--seconds", "60", "--slot", "1", "execute", "execution", "--", "bad"],
    [
        "--seconds",
        "600",
        "--slot",
        "2",
        "prove",
        "attempt2",
        "--",
        "target/release/pqdid-r0-host",
        "prove",
        "enrol-alpha-42",
        "receipts/attempt2.bin",
    ],
]:
    q = subprocess.run(
        ["/usr/bin/python3", str(R / "scripts/run_limited.py"), *args],
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert q.returncode != 0 and (R / "evidence/run_ledger.json").read_bytes() == ledger
    probes.append({"args": args, "exit": q.returncode, "reason": q.stderr.strip()})
paths = []
for directory in ["scripts", "host", "relation", "artifacts", "fixtures"]:
    paths.extend(
        p for p in (R / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts
    )
paths += [
    R / p
    for p in [
        "Cargo.toml",
        "Cargo.lock",
        "config.json",
        "CONTRACT.md",
        "target/release/pqdid-r0-host",
    ]
]
record = {
    "package": "R0-ENROL-PO17-1",
    "frozen_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "config": json.loads((R / "config.json").read_text()),
    "frozen_sha256": {str(p.relative_to(R)): sha(p) for p in paths},
    "baseline_sha256": sha(R / "evidence/baseline.json"),
    "preflight": json.loads((R / "evidence/preflight.result.json").read_text()),
    "preserved_files": len(before),
    "admission_probe_results": probes,
    "cumulative_attempts_used": 1,
    "cumulative_attempts_remaining": 2,
    "previous_prover_binary_unchanged": True,
}
path = R / "evidence/manifest-before-launch.json"
assert not path.exists()
path.write_text(json.dumps(record, indent=2) + "\n")
print("Pre-execution manifest and admission probes saved; guest/prover preserved")
