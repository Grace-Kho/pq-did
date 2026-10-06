"""Required scoped static checks; no test/build/probe dispatch."""

import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_manager_incremental_storage_1 import run as guard  # noqa: E402

if __name__ == "__main__":
    files = sorted(str(p) for p in guard.N.glob("*.py"))
    for flags in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *flags, "--no-cache", *files], check=True, timeout=3
        )
