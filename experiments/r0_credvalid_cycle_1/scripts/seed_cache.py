"""Copy already pinned registry files into a new writable offline cache."""

import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
base = root.parent / "r0_succinct_feasibility_1"
shutil.copytree(base / "tooling/cargo/registry", root / "tooling/cargo/registry")
print("Copied existing registry; no network, dependency update or tool installation.")
