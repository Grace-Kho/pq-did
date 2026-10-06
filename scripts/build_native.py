"""Fetch checksum-pinned liboqs source, build locally, then check C and C++ linkage."""

import hashlib
import json
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    for tool in ("gcc", "g++", "cmake", "ninja"):
        if not shutil.which(tool):
            raise SystemExit(f"Missing {tool}; install the Ubuntu prerequisites in README.md.")
    manifest = json.loads((ROOT / "native/dependencies.json").read_text())
    spec = manifest["liboqs"]
    deps = ROOT / "native/.deps"
    deps.mkdir(parents=True, exist_ok=True)
    archive = deps / f"liboqs-{spec['commit']}.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(spec["url"], timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != spec["sha256"]:
            raise SystemExit("liboqs download checksum mismatch.")
        archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec["sha256"]:
        raise SystemExit(f"Checksum mismatch: {archive}; inspect/remove it before retrying.")
    # Re-extract the verified archive, so edits to dependency sources are not used silently.
    with tarfile.open(archive) as source_archive:
        source_archive.extractall(deps / "src", filter="data")
    source = deps / "src" / f"liboqs-{spec['commit']}"
    build = ROOT / "native/build/liboqs"
    prefix = deps / "install"
    run(
        "cmake",
        "-S",
        str(source),
        "-B",
        str(build),
        "-G",
        "Ninja",
        *manifest["cmake_flags"],
        f"-DCMAKE_INSTALL_PREFIX={prefix}",
    )
    run("cmake", "--build", str(build), "--parallel", str(manifest["build_jobs"]))
    run("cmake", "--install", str(build))
    smoke_build = ROOT / "native/build/smoke"
    run(
        "cmake",
        "-S",
        str(ROOT / "native"),
        "-B",
        str(smoke_build),
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_COMPILER=/usr/bin/gcc",
        "-DCMAKE_CXX_COMPILER=/usr/bin/g++",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DCMAKE_PREFIX_PATH={prefix}",
    )
    run("cmake", "--build", str(smoke_build), "--parallel", str(manifest["build_jobs"]))
    run("ctest", "--test-dir", str(smoke_build), "--output-on-failure")


if __name__ == "__main__":
    main()
