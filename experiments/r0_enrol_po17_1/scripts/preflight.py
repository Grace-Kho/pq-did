"""Check identities, supported controls, actual build metadata and WSL headroom."""

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
A = R.parent / "r0_succinct_proof_1"
B = R.parent / "r0_succinct_feasibility_1"
C = R.parent / "r0_credvalid_cycle_1"


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def command(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def load(path):
    return json.loads(path.read_text())


inspected = next(
    json.loads(line)
    for line in (R / "evidence/host-identities.log").read_text().splitlines()
    if line.startswith("{")
)
opts = inspected["prover_options"]
assert opts["max_segment_po2"] == 22 and opts["receipt_kind"] == "Succinct"
assert opts["dev_mode"] is False and opts["hashfn"] == "poseidon2"
assert opts["prove_guest_errors"] is False
assert inspected["host_debug_assertions"] is False
assert inspected["executor_segment_limit_po2"] == 17
assert inspected["session_limit_user_cycles"] == 2**22
old = load(A / "evidence/manifest-before-launch.json")
registry = load(R / "fixtures/public/registry.json")
assert registry == [r for r in old["baseline"]["registry"] if r["operation"] == "enrol"]
for name in [
    "artifacts/enrol.bin",
    "artifacts/enrol.elf",
    "Cargo.toml",
    "Cargo.lock",
    "host/Cargo.toml",
    "relation/src/lib.rs",
    "relation/src/mldsa.rs",
]:
    assert sha(R / name) == sha(A / name), name
prover = B / "tooling/sdk-3.0.6/r0vm"
assert sha(prover) == "751b9b188d341e8bec5e02060086b7b1dc3f7289e90f726c38589bb6735dd6d7"
assert (
    sha(A / "tooling/recursion_zkr.zip")
    == "744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849"
)
crate = next((C / "tooling/cargo/registry/src").iterdir())
control = crate / "risc0-circuit-recursion-4.0.5/src/control_id.rs"
text = control.read_text().split("ALLOWED_CONTROL_IDS")[1].split("];")[0]
supported = {
    int(po2): digest
    for digest, po2 in re.findall(
        r'digest!\("([0-9a-f]+)"\), // recursion lift_rv32im_v2_(\d+)\.zkr', text
    )
}
assert 17 in supported
for digest in supported.values():
    words = [int.from_bytes(bytes.fromhex(digest)[i : i + 4], "little") for i in range(0, 32, 4)]
    assert words in opts["control_ids"]
archive = load(A / "evidence/recursion-artifacts.json")
assert any(e["name"] == "lift_rv32im_v2_17.zkr" for e in archive["entries"])
old_fp = load(
    next((A / "target/release/.fingerprint").glob("pqdid-r0-host-*/bin-pqdid-r0-host.json"))
)
new_fp = load(
    max(
        (R / "target/release/.fingerprint").glob("pqdid-r0-host-*/bin-pqdid-r0-host.json"),
        key=lambda p: p.stat().st_mtime_ns,
    )
)
assert old_fp["profile"] == new_fp["profile"] and old_fp["rustflags"] == new_fp["rustflags"] == []
record = {
    "configuration_compatible": True,
    "known_configuration_incompatibilities": [],
    "supported_segment_po2": sorted(supported),
    "supported_lift_ids": supported,
    "control_source_sha256": sha(control),
    "registry": registry,
    "host_inspection": inspected,
    "host_build_profile": {
        "cargo_command": "cargo build --locked --offline --release -p pqdid-r0-host",
        "opt_level": 3,
        "lto": "thin",
        "codegen_units": 1,
        "overflow_checks": True,
        "debug_assertions": False,
        "fingerprint": new_fp,
    },
    "prover_build_metadata": {
        "sha256": sha(prover),
        "version": command(str(prover), "--version").strip(),
        "ELF_comment": command("readelf", "-p", ".comment", str(prover)),
        "distribution": "unchanged pinned SDK 3.0.6 release binary; not rebuilt here",
        "optimisation_flags": "Exact vendor opt-level/LTO flags not attested",
    },
    "host_compiler_comment": command(
        "readelf", "-p", ".comment", str(R / "target/release/pqdid-r0-host")
    ),
    "CPU_settings": {
        "quota_percent": 200,
        "rayon_threads": 2,
        "OMP_threads": 2,
        "workers": 1,
        "available_affinity": sorted(os.sched_getaffinity(0)),
        "cpu_description": command("lscpu"),
    },
    "cache_state": {
        "host_cache": "copied prior release target; offline host rebuild",
        "prover_process": "fresh process for each execution/proof, no receipt reuse",
        "recursion_archive": "same embedded bytes; existing extracted copy verified read-only",
        "OS_page_cache": "not flushed or controlled",
        "downloads": 0,
    },
    "comparison_limits": [
        "Previous proof timed out, so no exact overall speedup is defined",
        "OS cache and host load are observational; no repeated benchmark",
    ],
    "memory_available": next(
        int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemAvailable:")
    ),
    "disk_free": {"WSL": shutil.disk_usage(R).free, "Windows": shutil.disk_usage("/mnt/c").free},
    "prover_maximum_unchanged": 22,
    "executor_segment_setting": 17,
}
(R / "evidence/preflight.result.json").write_text(json.dumps(record, indent=2) + "\n")
print("Frozen guest/prover, release host, po2-17 control support and WSL headroom checked")
