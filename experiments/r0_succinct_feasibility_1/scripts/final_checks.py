"""Bounded stopped-run data/preservation checks; never launches a guest or prover."""

import ast
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def record(data, tag):
    pos = 0

    def field():
        nonlocal pos
        assert pos + 4 <= len(data)
        n = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        assert pos + n <= len(data)
        b = data[pos : pos + n]
        pos += n
        return b

    assert field() == tag
    count = int.from_bytes(data[pos : pos + 4], "big")
    pos += 4
    values = [field() for _ in range(count)]
    assert pos == len(data)
    return values


def encode(tag, *fields):
    def lp(value):
        return len(value).to_bytes(4, "big") + value

    return lp(tag) + len(fields).to_bytes(4, "big") + b"".join(lp(f) for f in fields)


baseline = json.loads((ROOT / "evidence/protected_before.json").read_text())
changed = [name for name, before in baseline.items() if sha(PROJECT / name) != before]
assert set(changed) == {"docs/status.md", "docs/traceability.md"}, changed
assert (
    sha(PROJECT / "docs/manuscript/PQ_DID__Implementation.pdf")
    == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
)
manifest = json.loads((ROOT / "evidence/manifest.json").read_text())
for name, item in manifest["assets"].items():
    if name == "pinned_kernel_v1compat.elf":
        path = next(
            (ROOT / "tooling/cargo/registry/src").glob(
                "*/risc0-zkos-v1compat-2.2.3/elfs/v1compat.elf"
            )
        )
    else:
        path = ROOT / name
    assert sha(path) == item["SHA256"], name
review = json.loads((ROOT / "evidence/dependency_review.json").read_text())
for name, value in review["lock_SHA256"].items():
    assert sha(ROOT / name) == value, name
ledger = json.loads((ROOT / "evidence/run_ledger.json").read_text())
assert ledger["proof_attempts"] == 0
assert not list((ROOT / "receipts").glob("*.bin"))
assert (ROOT / "evidence/STOP.json").exists()
probe = subprocess.run(
    [
        "python3",
        str(ROOT / "scripts/run_limited.py"),
        "--seconds",
        "1",
        "execute",
        "forbidden-replay",
        "--",
        "/bin/false",
    ],
    capture_output=True,
    text=True,
    timeout=5,
)
assert probe.returncode and "package resource stop" in probe.stderr
assert json.loads((ROOT / "evidence/run_ledger.json").read_text())["proof_attempts"] == 0
native = json.loads((ROOT / "evidence/native_comparisons.json").read_text())
assert len(native) == 35 and all(x["matched"] for x in native)
guest = json.loads((ROOT / "evidence/guest_comparisons.json").read_text())
assert len(guest) == 2 and guest[0]["matched"] and not guest[1]["matched"]
assert guest[1]["error"] == "Session limit exceeded: 4194304 >= 4194304"
assert sum(1 << x for x in guest[0]["segment_po2"]) == 622592
cases = json.loads((ROOT / "fixtures/cases.json").read_text())
privacy = []
for case in cases["cases"]:
    assert sha(ROOT / case["public"]) == case["public_SHA256"]
    assert sha(ROOT / case["private"]) == case["private_fixture_SHA256"]
    if not case["reference_expected"]:
        continue
    public = (ROOT / case["public"]).read_bytes()
    fields = record(public, b"r0-statement")
    assert len(fields) == 5 and fields[0] == b"PQDID-R0S-DIAG1"
    assert fields[1].decode() == case["operation"] and len(fields[3]) == 32
    row = {
        "fixture": case["name"],
        "public_record_fields": 5,
        "journal_is_exact_public_envelope": True,
    }
    if case["operation"] == "cred-valid":
        assert len(record(fields[4], b"meta")) == 2
        private = record((ROOT / case["private"]).read_bytes(), b"r0-credential-witness")
        credential = record(private[0], b"credential")
        cert = record(credential[0], b"certificate")
        pp = record(fields[2], b"parameters")
        message = encode(b"cred", pp[0], credential[4], cert[0], credential[2])
        mu = hashlib.shake_256(
            hashlib.shake_256(pp[3]).digest(64) + b"\0\x14PQ-DID/credential/v1" + message
        ).digest(64)
        checked = [
            private[1],
            credential[1],
            cert[0],
            cert[1],
            message,
            hashlib.sha3_384(message).digest(),
            mu,
        ]
        # Long-byte absence supplements the authoritative field partition; a four-byte
        # identifier may occur by chance, so substring scans do not prove its secrecy.
        assert all(value not in public for value in checked)
        row.update(
            {
                "private_long_values_absent": True,
                "rid_absent_as_field": True,
                "receipt_metadata_inspected": False,
            }
        )
    privacy.append(row)
(ROOT / "evidence/public_output_review.json").write_text(
    json.dumps(
        {
            "scope": "functional envelope/native-journal checks only; no receipt or ZK proof",
            "rows": privacy,
            "diagnostic_fixture_names_are_not_public_presentation_metadata": True,
        },
        indent=2,
    )
    + "\n"
)
json_files = list((ROOT / "evidence").glob("*.json")) + list((ROOT / "fixtures").rglob("*.json"))
for p in json_files:
    json.loads(p.read_text())
for p in [
    ROOT / "Cargo.toml",
    ROOT / "Cargo.lock",
    ROOT / "rust-toolchain.toml",
    ROOT / "host/Cargo.toml",
    ROOT / "relation/Cargo.toml",
    ROOT / "methods/guest/Cargo.toml",
    ROOT / "methods/guest/Cargo.lock",
]:
    tomllib.loads(p.read_text())
for p in (ROOT / "scripts").glob("*.py"):
    ast.parse(p.read_text())
for p in (ROOT / "scripts").glob("*.sh"):
    subprocess.run(["bash", "-n", str(p)], check=True, timeout=5)
links = []
for doc in [
    PROJECT / "docs/stage3_r0_succinct_feasibility_1.md",
    PROJECT / "docs/status.md",
    PROJECT / "docs/traceability.md",
]:
    for target in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
        if "://" not in target and not target.startswith("#"):
            path = (doc.parent / target.split("#")[0]).resolve()
            # final_checks.json is written immediately below.
            assert path.exists() or path == ROOT / "evidence/final_checks.json", target
            links.append(target)
files = [p for p in ROOT.rglob("*") if p.is_file() and not p.is_symlink()]
bytes_used = sum(p.stat().st_size for p in files)
output_bytes = sum(
    p.stat().st_size
    for part in ["fixtures", "receipts", "evidence"]
    for p in (ROOT / part).rglob("*")
    if p.is_file()
)
assert bytes_used < 9 * 1024**3 and output_bytes < 240 * 1024**2
result = {
    "protected_existing_files_checked": len(baseline),
    "existing_files_changed_only": changed,
    "production_validation_reused": (
        "119 focused / 1432 regression, no skips; no production tests rerun"
    ),
    "binary_source_manifest_matches": True,
    "lock_audit_matches": True,
    "JSON_files_parsed": len(json_files),
    "TOML_files_parsed": 7,
    "local_links_checked": len(links),
    "native_comparisons": 35,
    "completed_guest_comparisons": 1,
    "guest_resource_stops": 1,
    "remaining_guest_cases_unrun": 27,
    "proof_attempts": 0,
    "stop_guard_replay_rejected": True,
    "disk_bytes": bytes_used,
    "output_bytes": output_bytes,
    "worker_swap_used": False,
    "functional_public_output_checks": len(privacy),
    "actual_receipt_checks": "not reached",
    "all_checks_passed": True,
}
(ROOT / "evidence/final_checks.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
