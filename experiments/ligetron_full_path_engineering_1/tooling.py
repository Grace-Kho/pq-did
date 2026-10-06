"""Affected source checks only; no native compiler, proof or functional test."""

import hashlib
import json
import subprocess
from pathlib import Path

P = Path(__file__).resolve().parents[2]
N = Path(__file__).resolve().parent
D = P / "docs/data/ligetron_full_path_engineering_1"


def main():
    files = [str(f) for f in sorted(N.glob("*.py"))]
    commands = [
        [str(P / ".venv/bin/ruff"), "check", "--select", "I", "--fix", "--no-cache", *files],
        [str(P / ".venv/bin/ruff"), "format", "--no-cache", *files],
        [str(P / ".venv/bin/ruff"), "check", "--no-cache", *files],
        [str(P / ".venv/bin/ruff"), "format", "--check", "--no-cache", *files],
    ]
    for command in commands:
        subprocess.run(command, check=True, timeout=4)
    subprocess.run(
        ["git", "apply", "--check", str(D / "prepared-overlay.patch")],
        cwd=N / "base",
        check=True,
        timeout=4,
    )
    seal = json.loads((D / "prepared-overlay-seal.json").read_bytes())
    for path, expected in seal["sha256"].items():
        assert hashlib.sha256((P / path).read_bytes()).hexdigest() == expected
    (D / "static-result.json").write_text(
        json.dumps(
            {
                "passed": True,
                "ruff": True,
                "patch_applicability": True,
                "overlay_seal": True,
                "native_compilation": "unrun",
                "functional_invocations": 0,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
