"""Check this checkout's Python, native backend and build tools; never fetch anything."""

import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    if Path(sys.prefix).resolve() != (ROOT / ".venv").resolve():
        raise SystemExit(
            "Use the project interpreter: .venv/bin/python scripts/verify_environment.py"
        )
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("This environment targets Linux x86_64 (Ubuntu/WSL2).")
    expected_python = (ROOT / ".python-version").read_text().strip()
    if platform.python_version() != expected_python:
        raise SystemExit(
            f"Python version changed: expected {expected_python}; review and revalidate."
        )
    from pqdid.backend import LIBRARY, load_backend

    with (ROOT / "uv.lock").open("rb") as stream:
        lock = tomllib.load(stream)
    locked = {package["name"]: package["version"] for package in lock["package"]}
    packages = {}
    for name in locked:
        if name == "colorama":  # Windows-only transitive dependency, not installed on WSL.
            continue
        packages[name] = importlib.metadata.version(name)
        if packages[name] != locked[name]:
            raise SystemExit(f"Dependency drift: {name}; run bash scripts/setup.sh.")
    versions = {}
    for command in ("git", "gcc", "g++", "cmake", "ninja", "make", "pkg-config"):
        location = shutil.which(command)
        if not location or not Path(location).resolve().is_relative_to("/usr"):
            raise SystemExit(f"Missing or unexpected Linux tool: {command} ({location}).")
        output = subprocess.check_output([location, "--version"], text=True)
        versions[command] = {"path": location, "version": output.splitlines()[0]}
    binding = load_backend()
    with binding.Signature("ML-DSA-65") as signature:
        backend = signature.details
    report = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "interpreter": sys.executable,
        "prefix": sys.prefix,
        "packages": packages,
        "tools": versions,
        "liboqs": {"version": binding.oqs_version(), "library": str(LIBRARY.resolve())},
        "signature_backend": backend,
        "bounded_operations": "pending validation",
        "protocol_specification": "unresolved; see docs/status.md",
    }
    print(json.dumps(report, indent=2))
    print("Environment checks passed. Run pytest for the cryptographic smoke checks.")


if __name__ == "__main__":
    main()
