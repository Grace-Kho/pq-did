"""Scoped formatting/build dispatch; no case runs during build or quality."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.auth_relation_integration_1 import run as guard  # noqa: E402


def quality():
    files = sorted(str(path) for path in guard.N.glob("*.py"))
    commands = []
    for flags in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check",),
        ("format", "--check"),
    ):
        command = [str(P / ".venv/bin/ruff"), *flags, "--no-cache", *files]
        subprocess.run(command, check=True, timeout=2)
        commands.append(command)
    print(json.dumps({"passed": True, "commands": commands, "tests": 0, "builds": 0}))


def build():
    source = guard.N / "native"
    build_dir = guard.N / "build"
    inputs = [
        *source.iterdir(),
        P / "experiments/aurora_masking_milestone_1/build/libiop_native.a",
        P / "experiments/aurora_masking_milestone_1/build/libff-build/libff/libff.a",
    ]
    manifest = {
        path.relative_to(P).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in inputs
        if path.is_file()
    }
    commands = [
        [
            "/usr/bin/cmake",
            "-S",
            str(source),
            "-B",
            str(build_dir),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0",
        ],
        [
            "/usr/bin/cmake",
            "--build",
            str(build_dir),
            "--target",
            "relation_adapter",
            "--parallel",
            "1",
        ],
    ]
    attempt = len(guard.read(guard.D / "ledger.json")["builds"])
    guard.write(
        guard.D / f"build-inputs-{attempt}.json", {"sha256": manifest, "commands": commands}
    )
    for command, timeout in zip(commands, (15, 35), strict=True):
        subprocess.run(command, check=True, timeout=timeout)
    binary = build_dir / "relation_adapter"
    guard.write(
        guard.D / "build-result.json",
        {
            "passed": True,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "commands": commands,
            "full_relation": False,
            "proof": False,
        },
    )


if __name__ == "__main__":
    {"quality": quality, "build": build}[sys.argv[1]]()
