"""One counted native configuration/build attempt using the approved local pins."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
N = P / "experiments/aurora_masking_milestone_1"
D = P / "docs/data/oct31_kyc_native_milestone_1"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    attempt = sys.argv[1]
    manifest = json.loads((N / "overlay/patch-manifest.json").read_text())
    old = P / manifest["source_origin"]
    changed = manifest["changes"]
    assert sha(N / "overlay/masking-correction.patch") == manifest["patch_sha256"]
    for path in (N / "work").rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(N).as_posix()
        original = old / path.relative_to(N / "work")
        if relative in changed:
            assert sha(original) == changed[relative]["before_sha256"]
            assert sha(path) == changed[relative]["after_sha256"]
        else:
            assert sha(path) == sha(original), relative
    prefix = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/prefix"
    commands = [
        [
            "cmake",
            "-S",
            str(N / "overlay"),
            "-B",
            str(N / "build"),
            "-G",
            "Ninja",
            "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0",
            "-DCMAKE_C_FLAGS_RELEASE=-O0 -g0",
            "-DPQ_SOURCE=" + str(N / "work"),
            "-DPQ_PREFIX=" + str(prefix),
        ],
        [
            "cmake",
            "--build",
            str(N / "build"),
            "--target",
            "aurora_masking_native",
            "exp2_native",
            "--parallel",
            "1",
        ],
    ]
    record = {
        "patch_manifest_sha256": sha(N / "overlay/patch-manifest.json"),
        "patch_sha256": manifest["patch_sha256"],
        "commands": commands,
        "inputs": {p.name: sha(p) for p in (N / "overlay").iterdir() if p.is_file()},
        "outcomes": [],
    }
    output = D / (attempt + "-commands.json")
    assert not output.exists()
    for command in commands:
        output.write_text(json.dumps(record, indent=2) + "\n")
        completed = subprocess.run(command, check=False, timeout=110)
        record["outcomes"].append(completed.returncode)
        output.write_text(json.dumps(record, indent=2) + "\n")
        if completed.returncode:
            raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
