"""Bounded pinned include closure and exact inspected reference artefacts."""

import hashlib
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_domain_mask_correction_1 import run as g  # noqa: E402

D, N = g.D, g.N
OLD = P / "experiments/ligetron_correction_admission_1"
PIN = "4b1cdef1bfdf4497fb3e38170db4541fba3f6c12"


def main():
    tree = {
        e["path"]: e
        for e in g.read(P / "docs/data/ligetron_correction_admission_1/upstream-tree.json")["tree"]
    }
    records = []
    archive = P / "PQ_DID_Ligetron_Domain_Mask_Followup.zip"
    assert (
        hashlib.sha256(archive.read_bytes()).hexdigest()
        == g.read(D / "opening.json")["input_sha256"]
    )
    with zipfile.ZipFile(archive) as z:
        for line in z.read("SHA256SUMS").decode().splitlines():
            expected, path = line.split(None, 1)
            assert hashlib.sha256(z.read(path)).hexdigest() == expected
        sm = json.loads(z.read("source-map.json"))
        for row in sm["source_files"]:
            data = z.read("pinned_source/" + row["path"])
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            assert blob == row["git_blob"] == tree[row["path"]]["sha"]
        for path in (
            "include/wgpu.hpp",
            "src/webgpu/engine.cpp",
            "shader/kernels.wgsl.in",
            "pack/shader/bignum.wgsl",
        ):
            target = N / "sources" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read("pinned_source/" + path))
        g.write(
            D / "archive-admission.json",
            {
                "passed": True,
                "sources": sm,
                "algebra_results_reused_not_executed": json.loads(
                    z.read("finite-model-results.json")
                ),
            },
        )
    queue = [
        "include/util/mpz_vector.hpp",
        "include/util/recycle_pool.hpp",
        "include/zkp/backend/lazy_witness.hpp",
        "include/util/mpz_assign.hpp",
        "shader/bigint.wgsl.in",
        "shader/bn254fr.wgsl.in",
    ]
    seen = set()
    payload = 0
    while queue:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        existing = OLD / "overlay" / path
        if existing.exists():
            data = existing.read_bytes()
        else:
            entry = tree[path]
            assert entry["type"] == "blob" and entry["size"] <= 1048576
            url = "https://raw.githubusercontent.com/ligeroinc/ligero-prover/" + PIN + "/" + path
            with urllib.request.urlopen(url, timeout=8) as response:
                data = response.read(entry["size"] + 1)
            assert len(data) == entry["size"]
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            assert blob == entry["sha"], path
            payload += len(data)
            assert payload <= 262144
            dest = N / "sources" / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            records.append(
                {
                    "path": path,
                    "bytes": len(data),
                    "git_blob": blob,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            g.write(
                D / "source-acquisition.json",
                {"commit": PIN, "payload_bytes": payload, "records": records},
            )
        for header in re.findall(r"#include\s*[<\"]([^>\"]+)[>\"]", data.decode()):
            candidate = "include/" + header
            if candidate in tree:
                queue.append(candidate)
    refs = []
    registry = g.read(D / "artifact-outputs.json")
    for paper in ("2022-1608", "2024-2010"):
        dest = N / "references" / (paper + ".pdf")
        dest.parent.mkdir(exist_ok=True)
        registry["paths"][str(dest.relative_to(P))] = "reference-pdf"
        g.write(D / "artifact-outputs.json", registry)
        url = "https://eprint.iacr.org/" + paper.replace("-", "/") + ".pdf"
        with urllib.request.urlopen(url, timeout=8) as response:
            data = response.read(4194305)
            headers = dict(response.headers)
        assert len(data) <= 4194304 and data.startswith(b"%PDF")
        dest.write_bytes(data)
        refs.append(
            {
                "url": url,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "HTTP_headers": headers,
                "inspected_date": "2026-10-03",
            }
        )
    g.write(
        D / "references.json",
        {
            "versions": refs,
            "claim": (
                "These exact bytes identify the inspected versions; no release-signature claim."
            ),
        },
    )
    g.write(
        D / "source-closure.json",
        {
            "passed": True,
            "CPU_local_include_closure": sorted(seen),
            "new_payload_bytes": payload,
            "dependencies_reused": "Prior sealed GMP/OpenSSL/Boost closure; no install",
            "GPU_build_closure": "not acquired/not admitted",
        },
    )


if __name__ == "__main__":
    main()
