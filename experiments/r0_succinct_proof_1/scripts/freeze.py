"""Preserve launch identities and confirm admission gates without a proof launch."""

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


prior = json.loads((R / "evidence/protected_before.json").read_text())
assert all(sha(P / name) == digest for name, digest in prior.items())
ledger = (R / "evidence/run_ledger.json").read_bytes()
rows = []
for args in [
    ["--seconds", "600", "--slot", "2", "prove", "attempt2"],
    ["--seconds", "601", "--slot", "1", "prove", "attempt1"],
    ["--seconds", "600", "--slot", "4", "prove", "attempt4"],
    ["--seconds", "600", "--slot", "1", "prove", "attempt1", "--", "bad-command"],
]:
    # All failures precede any service launch, including the early slot-2 sequence gate.
    if "--" not in args:
        args += [
            "--",
            "target/release/pqdid-r0-host",
            "prove",
            "enrol-alpha-42",
            "receipts/attempt1.bin",
        ]
    q = subprocess.run(
        ["/usr/bin/python3", str(R / "scripts/run_limited.py"), *args],
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert q.returncode != 0
    assert ledger == (R / "evidence/run_ledger.json").read_bytes()
    rows.append({"args": args, "exit": q.returncode, "reason": q.stderr.strip()})
paths = []
for directory in ["scripts", "host", "relation", "fixtures", "artifacts"]:
    paths.extend(
        p for p in (R / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts
    )
paths += [
    R / name
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "config.json",
        "CONTRACT.md",
        "target/release/pqdid-r0-host",
    ]
]
record = {
    "package": "R0-SUCCINCT-PROOF-1",
    "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "config": json.loads((R / "config.json").read_text()),
    "baseline": json.loads((R / "evidence/baseline.json").read_text()),
    "preflight": json.loads((R / "evidence/preflight.result.json").read_text()),
    "recursion_artifacts": json.loads((R / "evidence/recursion-artifacts.json").read_text()),
    "frozen_sha256": {str(p.relative_to(R)): sha(p) for p in paths},
    "preserved_files_checked": len(prior),
    "proof_attempts_before_launch": 0,
    "launch_gate_probes": rows,
    "setup_assets_reused": json.loads(
        (R.parent / "r0_succinct_feasibility_1/evidence/install_assets.json").read_text()
    ),
}
assert json.loads(ledger)["proof_attempts"] == 0
path = R / "evidence/manifest-before-launch.json"
assert not path.exists()
path.write_text(json.dumps(record, indent=2) + "\n")
print("Frozen identities and limits recorded before launch; preservation checked")
