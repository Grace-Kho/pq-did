"""Record built identities and resource observations without executing a guest."""

import hashlib
import json
import platform
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def version(command):
    return subprocess.check_output(command, text=True, timeout=5).strip()


ledger = json.loads((ROOT / "evidence/run_ledger.json").read_text())
registry = json.loads((ROOT / "fixtures/public/registry.json").read_text())
paths = [
    "Cargo.toml",
    "Cargo.lock",
    "methods/guest/Cargo.lock",
    "rust-toolchain.toml",
    "scripts/build.sh",
    "target/release/pqdid-r0-host",
    "target/enrol.bin",
    "target/cred_valid.bin",
    "tooling/sdk-3.0.6/r0vm",
]
for part in ["relation", "host", "methods/guest"]:
    paths.extend(str(p.relative_to(ROOT)) for p in (ROOT / part).rglob("*.rs"))
    paths.append(part + "/Cargo.toml")
for stem in ["enrol", "cred_valid"]:
    paths.append("target/guest/riscv32im-risc0-zkvm-elf/release/" + stem)
kernel = next(
    (ROOT / "tooling/cargo/registry/src").glob("*/risc0-zkos-v1compat-2.2.3/elfs/v1compat.elf")
)
assets = {
    name: {"SHA256": digest(ROOT / name), "bytes": (ROOT / name).stat().st_size} for name in paths
}
assets["pinned_kernel_v1compat.elf"] = {"SHA256": digest(kernel), "bytes": kernel.stat().st_size}
locks = {
    p: tomllib.loads((ROOT / p).read_text())["package"]
    for p in ["Cargo.lock", "methods/guest/Cargo.lock"]
}
source_revision = hashlib.sha256(
    json.dumps(
        {k: v["SHA256"] for k, v in assets.items() if k.endswith((".rs", ".toml", ".lock", ".sh"))},
        sort_keys=True,
    ).encode()
).hexdigest()
manifest = {
    "package": "R0-SUCCINCT-FEASIBILITY-1",
    "source_revision_kind": "SHA-256 source/manifest inventory; workspace has no Git repository",
    "source_revision": source_revision,
    "SDK_release_commit": "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9",
    "compiler": version([str(ROOT / "tooling/guest-r0.1.97.0/bin/rustc"), "-vV"]),
    "cargo": version([str(ROOT / "tooling/guest-r0.1.97.0/bin/cargo"), "--version"]),
    "prover": version([str(ROOT / "tooling/sdk-3.0.6/r0vm"), "--version"]),
    "cargo_risczero": version(
        [str(ROOT / "tooling/sdk-3.0.6/cargo-risczero"), "risczero", "--version"]
    ),
    "platform": platform.platform(),
    "machine": platform.machine(),
    "rustc_target": "riscv32im-risc0-zkvm-elf",
    "guest_RUSTFLAGS": (
        "-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 "
        '-C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"'
    ),
    "profiles": {"optimisation": 3, "lto": "thin", "overflow_checks": True, "codegen_units": 1},
    "registry": registry,
    "assets": assets,
    "circuit_versions": {
        p: {x["name"]: x["version"] for x in ps if x["name"].startswith("risc0-")}
        for p, ps in locks.items()
    },
    "proof_attempts": ledger["proof_attempts"],
    "setup_seconds": sum(x["wall_seconds"] for x in ledger["runs"] if x["phase"] == "setup"),
    "build_seconds": sum(x["wall_seconds"] for x in ledger["runs"] if x["phase"] == "build"),
    "execute_seconds": sum(x["wall_seconds"] for x in ledger["runs"] if x["phase"] == "execute"),
    "proof_receipts": list(str(p.relative_to(ROOT)) for p in (ROOT / "receipts").glob("*.bin")),
    "global_tool_homes_absent": {
        str(p): not p.exists()
        for p in [Path.home() / s for s in [".cargo", ".rustup", ".risc0", ".rzup"]]
    },
    "temporary_storage_bytes_at_stop": sum(
        p.stat().st_size for p in (ROOT / "tmp").rglob("*") if p.is_file()
    ),
}
(ROOT / "evidence/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(
    json.dumps(
        {
            "source_revision": source_revision,
            "proof_attempts": ledger["proof_attempts"],
            "registered_guests": len(registry),
        }
    )
)
