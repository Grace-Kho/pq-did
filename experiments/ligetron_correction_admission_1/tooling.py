"""Scoped formatting, exact input seals and CPU dependency admission."""

import difflib
import hashlib
import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_correction_admission_1 import run as guard  # noqa: E402

D, N = guard.D, guard.N


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(262144):
            h.update(chunk)
    return h.hexdigest()


def static():
    files = [str(f) for f in sorted(N.glob("*.py"))]
    for flags in (
        ("check", "--select", "I", "--fix"),
        ("format",),
        ("check", "--fix"),
        ("format", "--check"),
    ):
        subprocess.run(
            [str(P / ".venv/bin/ruff"), *flags, "--no-cache", *files], check=True, timeout=3
        )


def preflight():
    old = P / "docs/data/kyc_testbed_delivery_1"
    opening = guard.read(D / "opening.json")
    assert digest(old / "manifest.json") == opening["prior_manifest_sha256"]
    assert digest(old / "validation-closure.json") == opening["prior_closure_sha256"]
    assert guard.read(D / "source-provenance.json")["passed"]
    assert guard.read(D / "link-admission.json")["passed"]
    for path, expected in guard.read(D / "link-admission.json")["retained_GMP_sha256"].items():
        assert digest(P / path) == expected, path
    for path, expected in guard.read(D / "header-closure.json")["headers"].items():
        assert digest(P / path) == expected, path
    original = guard.read(D / "handover/source-manifest.json")
    for row in original["source_files"]:
        assert digest(N / "base" / row["path"]) == row["sha256"], row["path"]
    allowed = {r["path"] for r in original["changed_files"]} | {"include/zkp/pqdid_rng_exp1.hpp"}
    changes = []
    hashes = {}
    for path in sorted((N / "overlay").rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(N / "overlay").as_posix()
        base = N / "base" / relative
        hashes[str(path.relative_to(P))] = digest(path)
        if base.exists() and digest(base) == digest(path):
            continue
        assert relative in allowed, relative
        changes.extend(
            difflib.unified_diff(
                base.read_text().splitlines(keepends=True) if base.exists() else [],
                path.read_text().splitlines(keepends=True),
                fromfile="a/" + relative,
                tofile="b/" + relative,
            )
        )
    (D / "reviewed-overlay.patch").write_text("".join(changes))
    for path in sorted((N / "native").glob("*")):
        hashes[str(path.relative_to(P))] = digest(path)
    guard.write(
        D / "build-input-seal.json",
        {
            "sha256": hashes,
            "patch_sha256": digest(D / "reviewed-overlay.patch"),
            "exception": (
                "test-only linker wrapper for synthetic entropy; normal helper "
                "always invokes RAND_priv_bytes"
            ),
        },
    )
    assert digest(D / "expectations.json") == guard.read(D / "expectation-seal.json")["sha256"]
    assert len(guard.read(D / "execution-plan.json")["cases"]) == 35
    source = (N / "overlay/src/bn254.cpp").read_text()
    assert [s for s in source.splitlines() if s.startswith("#include")] == [
        "#include <zkp/finite_field_gmp.hpp>"
    ]
    assert all(
        (N / "prefix/usr/include" / f).is_file()
        for f in ("openssl/rand.h", "openssl/evp.h", "boost/random/uniform_int_distribution.hpp")
    )
    guard.write(
        D / "preflight.json",
        {
            "passed": True,
            "storage": guard.storage(),
            "build_slots": "0/2 package, historical 10/13",
            "case_slots": "0/39 package; historical seven reserved slots untouched",
            "CPU_include_link_closure": (
                "source/header closure inspected; native compilation remains untested"
            ),
            "stage_callers": [
                "webgpu_prover.cpp: private_encoding_seed/stage1_seed/stage2_seed",
                "webgpu_verifier.cpp: stage1_seed/stage2_seed",
                "nonbatch_context_base::init_witness_random: init_challenge_engines",
            ],
            "full_backend_execution": "UNRUN",
        },
    )


if __name__ == "__main__":
    {"static": static, "preflight": preflight}[sys.argv[1]]()
