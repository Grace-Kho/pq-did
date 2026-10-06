"""Reuse pinned dependencies and compiled host cache without changing the prover."""

import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
(root / "tooling/cargo/registry").symlink_to(
    root.parent / "r0_credvalid_cycle_1/tooling/cargo/registry", target_is_directory=True
)
shutil.copytree(root.parent / "r0_enrol_po17_1/target/release", root / "target/release")
print("Read-only registry and copied host cache; no tool install or guest/prover build")
