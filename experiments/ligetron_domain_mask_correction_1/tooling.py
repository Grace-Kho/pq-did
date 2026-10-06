"""Scoped static checks, source guards and overlay seal; no native probes."""

import difflib
import hashlib
import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_domain_mask_correction_1 import run as g  # noqa: E402

D, N = g.D, g.N
OLD = P / "experiments/ligetron_correction_admission_1"


def h(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def static():
    files = [str(p) for p in N.glob("*.py")]
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
    old = P / "docs/data/ligetron_correction_admission_1"
    opening = g.read(D / "opening.json")
    assert h(old / "manifest.json") == opening["prior_manifest_sha256"]
    assert h(old / "validation-closure.json") == opening["prior_closure_sha256"]
    for path, expected in g.read(old / "build-input-seal.json")["sha256"].items():
        assert h(P / path) == expected, path
    for path, expected in g.read(old / "header-closure.json")["headers"].items():
        assert h(P / path) == expected, path
    for path, expected in g.read(old / "link-admission.json")["retained_GMP_sha256"].items():
        assert h(P / path) == expected, path
    assert g.read(D / "source-closure.json")["passed"]
    assert h(D / "expectations.json") == g.read(D / "expectation-seal.json")["sha256"]
    assert len(g.read(D / "execution-plan.json")["cases"]) == 32
    contract = g.read(D / "component-contract.json")
    assert contract["status"].startswith("component algebra admitted")
    # Static call-path checks do not count as GPU execution.
    ctx = (N / "overlay/include/zkp/nonbatch_context.hpp").read_text()
    assert "pad_encoding_random(batch_randomness_, params::sample_size)" not in ctx
    assert "params::sample_size * Field::num_u64_limbs" not in ctx
    engine = (N / "overlay/src/webgpu/engine.cpp").read_text()
    assert engine.count("SetPipeline(pass, ntt_coset_forward_)") == 2
    assert engine.count("SetPipeline(pass, ntt_coset_inverse_)") == 2
    for role in ("prover", "verifier"):
        text = (N / f"overlay/src/webgpu_{role}.cpp").read_text()
        assert "dm1::fixed_profile(k, l, n, params::sample_size)" in text
        assert "pqdid_exp1::stage2_seed(stage1_seed," in " ".join(text.split()).replace("( ", "(")
    allowed = {
        "include/params.hpp",
        "include/wgpu.hpp",
        "include/zkp/backend/witness_manager.hpp",
        "include/zkp/nonbatch_context.hpp",
        "include/zkp/pqdid_rng_exp1.hpp",
        "include/zkp/pqdid_domain_mask_exp1.hpp",
        "src/webgpu/engine.cpp",
        "src/webgpu_prover.cpp",
        "src/webgpu_verifier.cpp",
        "shader/kernels.wgsl.in",
        "pack/shader/bignum.wgsl",
    }
    patch = []
    seals = {}
    for file in sorted((N / "overlay").rglob("*")):
        if not file.is_file():
            continue
        rel = file.relative_to(N / "overlay").as_posix()
        assert rel in allowed
        base = OLD / "overlay" / rel
        if not base.exists():
            base = N / "sources" / rel
        patch.extend(
            difflib.unified_diff(
                base.read_text().splitlines(keepends=True) if base.exists() else [],
                file.read_text().splitlines(keepends=True),
                fromfile="a/" + rel,
                tofile="b/" + rel,
            )
        )
        seals[str(file.relative_to(P))] = h(file)
    (D / "reviewed-overlay.patch").write_text("".join(patch))
    for f in [N / "native.cpp", N / "expectations.py", N / "build.py", N / "cases.py"]:
        seals[str(f.relative_to(P))] = h(f)
    g.write(
        D / "build-input-seal.json",
        {
            "sha256": seals,
            "patch_sha256": h(D / "reviewed-overlay.patch"),
            "base_overlay_sha256": g.read(old / "build-input-seal.json")["patch_sha256"],
        },
    )
    g.write(
        D / "preflight.json",
        {
            "passed": True,
            "storage": g.storage(),
            "source_checks": True,
            "CPU_include_link_closure": "complete; compatibility awaits counted build",
            "GPU_correspondence": "source-only; uncompiled/unrun",
            "cases": 32,
            "builds_remaining": 2,
        },
    )


if __name__ == "__main__":
    {"static": static, "preflight": preflight}[sys.argv[1]]()
