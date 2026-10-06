"""One counted build attempt, including both translation units and final link."""

import hashlib
import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_domain_mask_correction_1 import run as guard  # noqa: E402

D, N = guard.D, guard.N


def main():
    attempt = sys.argv[1]
    assert attempt in {"1", "2"}
    assert guard.read(D / "source-closure.json")["passed"]
    assert guard.read(P / "docs/data/ligetron_correction_admission_1/link-admission.json")["passed"]
    assert (
        hashlib.sha256((D / "expectations.json").read_bytes()).hexdigest()
        == guard.read(D / "expectation-seal.json")["sha256"]
    )
    gmp = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/prefix/usr"
    dest = N / "build" / ("attempt-" + attempt)
    dest.mkdir()
    registry = guard.read(D / "artifact-outputs.json")
    for name in ("cases.o", "bn254.o", "rng_cases"):
        registry["paths"][str((dest / name).relative_to(P))] = "build-artifact"
    guard.write(D / "artifact-outputs.json", registry)
    common = [
        "/usr/bin/g++",
        "-std=c++20",
        "-O0",
        "-g0",
        "-pipe",
        "-Wall",
        "-Wextra",
        "-include",
        str(P / "experiments/ligetron_correction_admission_1/native/prelude.hpp"),
    ]
    for directory in (
        N / "overlay/include",
        N / "sources/include",
        P / "experiments/ligetron_correction_admission_1/overlay/include",
        P / "experiments/ligetron_correction_admission_1/prefix/usr/include",
        P / "experiments/ligetron_correction_admission_1/prefix/usr/include/x86_64-linux-gnu",
        gmp / "include",
        gmp / "include/x86_64-linux-gnu",
    ):
        common += ["-I", str(directory)]
    commands = [
        common + ["-c", str(N / "native.cpp"), "-o", str(dest / "cases.o")],
        common
        + [
            "-c",
            str(P / "experiments/ligetron_correction_admission_1/overlay/src/bn254.cpp"),
            "-o",
            str(dest / "bn254.o"),
        ],
        [
            "/usr/bin/g++",
            str(dest / "cases.o"),
            str(dest / "bn254.o"),
            str(gmp / "lib/x86_64-linux-gnu/libgmpxx.a"),
            str(gmp / "lib/x86_64-linux-gnu/libgmp.a"),
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "-o",
            str(dest / "rng_cases"),
        ],
    ]
    guard.write(D / ("build-" + attempt + "-commands.json"), commands)
    for command in commands:
        subprocess.run(command, check=True, timeout=50)
    binary = dest / "rng_cases"
    guard.write(
        D / ("build-" + attempt + "-result.json"),
        {
            "passed": True,
            "binary": str(binary.relative_to(P)),
            "bytes": binary.stat().st_size,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "full_prover_compiled": False,
            "full_verifier_compiled": False,
        },
    )


if __name__ == "__main__":
    main()
