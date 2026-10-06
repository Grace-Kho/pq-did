"""Reuse cached crates read-only; copy compiled host cache into this isolated target."""

import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
prior = root.parent / "r0_credvalid_cycle_1"
(root / "tooling/cargo/registry").symlink_to(
    prior / "tooling/cargo/registry", target_is_directory=True
)
shutil.copytree(root.parent / "r0_credvalid_exec24_1/target/release", root / "target/release")
print("Read-only crate cache and copied host build cache prepared; no install or guest build")
