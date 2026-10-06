"""Pin workload/control support and record headroom without executing a guest."""

import hashlib
import json
import mmap
import shutil
from pathlib import Path

R = Path(__file__).resolve().parents[1]
P = R.parents[1]
C = R.parent / "r0_credvalid_cycle_1"
B = R.parent / "r0_succinct_feasibility_1"


def sha(p):
    return hashlib.file_digest(p.open("rb"), "sha256").hexdigest()


a = json.loads((R / "evidence/recursion-artifacts.json").read_text())
assert all(
    any(e["name"] == f"{n}.zkr" for e in a["entries"])
    for n in ["lift_rv32im_v2_15", "lift_rv32im_v2_16", "join"]
)
root = next((C / "tooling/cargo/registry/src").iterdir())
control = root / "risc0-circuit-recursion-4.0.5/src/control_id.rs"
text = control.read_text()
allowed = text.split("ALLOWED_CONTROL_IDS")[1].split("];")[0]
ids = {
    "lift15": "1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16",
    "lift16": "c32b3627d2b3d60c64adf523a98bd16c0ff607471f3d6630d1f26d5e9406d841",
    "join": "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e",
}
assert all(x in allowed for x in ids.values())
with (
    (B / "tooling/sdk-3.0.6/r0vm").open("rb") as f,
    mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m,
):
    cpu = m.find(b"CpuHal") >= 0
    cuda = m.find(b"libcuda.so") >= 0
assert cpu and not cuda
valid = json.loads((R.parent / "r0_credvalid_exec24_1/evidence/valid.result.json").read_text())
record = {
    "cpu_binary_checks": {
        "CpuHal": cpu,
        "libcuda.so": cuda,
        "gpu_device_namespace": "PrivateDevices=yes; no CUDA_VISIBLE_DEVICES",
    },
    "control_ids": ids,
    "control_source_sha256": sha(control),
    "recursion_archive_sha256": sha(R / "tooling/recursion_zkr.zip"),
    "workload": {
        "enrol": {
            "user_cycles": 196311,
            "segment_count": 10,
            "po2_histogram": {"16": 9, "15": 1},
            "padded_capacity": 622592,
            "segment_proofs": 10,
            "lifts": 10,
            "joins": 9,
        },
        "cred-valid": {
            "user_cycles": 16313474,
            "segment_count": 582,
            "po2_histogram": {"16": 581, "15": 1},
            "padded_capacity": 38109184,
            "other_padded_capacity": 21795710,
            "segment_proofs": 582,
            "lifts": 582,
            "joins": 581,
        },
    },
    "workload_source": "Prior execution + SDK server/prove/mod.rs fold; no new execution",
    "system_paging_separate": "Prior IPC lacks split; residual includes paging/reserved/padding",
    "cycle_limit_meaning": "Executor.cycles.user; not padded segment capacity",
    "recursion_support": "15/16 lifts + join allowed; registry pins root and parameter digest",
    "disk_free_bytes": {
        "wsl": shutil.disk_usage(P).free,
        "windows": shutil.disk_usage("/mnt/c").free,
    },
    "meminfo": Path("/proc/meminfo").read_text(),
    "dependencies_unchanged": sha(R / "Cargo.lock") == sha(C / "Cargo.lock"),
    "reference_validation": "Reuse six native tests + 35 comparisons; no rerun",
}
assert record["dependencies_unchanged"]
(R / "evidence/preflight.result.json").write_text(json.dumps(record, indent=2) + "\n")
print("Archive, CPU, controls, lock and headroom checked; no guest execution")
