"""Bounded, pinned acquisition. Never execute downloaded scripts or package hooks."""

import hashlib
import json
import stat
import sys
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_correction_admission_1 import run as guard  # noqa: E402

D, N = guard.D, guard.N
PIN = "4b1cdef1bfdf4497fb3e38170db4541fba3f6c12"
API = "https://api.github.com/repos/ligeroinc/ligero-prover/git/"
META_CAP = 1048576
charged = 0
records = []


def sha(b):
    return hashlib.sha256(b).hexdigest()


def blob(b):
    return hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()


def fetch(url, cap):
    global charged
    start = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "PQDID-pinned-admission/1"})
    with urllib.request.urlopen(req, timeout=15) as response:
        data = response.read(cap + 1)
    if len(data) > cap:
        raise RuntimeError("acquisition response cap")
    charged += len(data)
    records.append(
        {"url": url, "bytes": len(data), "sha256": sha(data), "seconds": time.monotonic() - start}
    )
    if charged > META_CAP:
        raise RuntimeError("additional source/metadata cap")
    return data


def safe(name):
    path = PurePosixPath(name)
    return not (path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name)


def main():
    archive = P / "PQ_DID_Ligetron_Correction_Handover.zip"
    assert (
        sha(archive.read_bytes())
        == "e116904d8f39c017b1a0807b4b1d891afc79bb50a98eff2279e6e45a48747fb8"
    )
    with zipfile.ZipFile(archive) as z:
        seen = set()
        for item in z.infolist():
            assert safe(item.filename) and item.filename not in seen
            assert not stat.S_ISLNK(item.external_attr >> 16) and not item.flag_bits & 1
            assert item.file_size <= 1048576
            seen.add(item.filename)
        assert sum(i.file_size for i in z.infolist()) == 362334
        for line in z.read("SHA256SUMS").decode().splitlines():
            digest, name = line.split(maxsplit=1)
            assert sha(z.read(name)) == digest, name
        manifest = json.loads(z.read("source-manifest.json"))
        for row in manifest["source_files"]:
            data = z.read("source_snapshot/" + row["path"])
            assert len(data) == row["bytes"] and sha(data) == row["sha256"]
            assert blob(data) == row["computed_git_blob_sha1"]
        guard.write(
            D / "archive-admission.json",
            {
                "passed": True,
                "sha256": sha(archive.read_bytes()),
                "members": sorted(seen),
                "source_files": 19,
                "patch_executed": False,
            },
        )

        commit_raw = fetch(API + "commits/" + PIN, META_CAP - charged)
        commit = json.loads(commit_raw)
        assert commit["sha"] == PIN
        tree_id = commit["tree"]["sha"]
        assert tree_id != PIN
        (D / "upstream-commit.json").write_bytes(commit_raw)
        tree_raw = fetch(API + "trees/" + tree_id + "?recursive=1", META_CAP - charged)
        tree = json.loads(tree_raw)
        assert tree["sha"] == tree_id and tree.get("truncated") is False
        entries = {r["path"]: r for r in tree["tree"]}
        assert len(entries) == len(tree["tree"])
        (D / "upstream-tree.json").write_bytes(tree_raw)
        for row in manifest["source_files"]:
            upstream = entries[row["path"]]
            assert upstream["type"] == "blob" and upstream["mode"] == "100644"
            assert (
                upstream["sha"] == row["computed_git_blob_sha1"]
                and upstream["size"] == row["bytes"]
            ), row["path"]
        for item in z.infolist():
            destination = (
                (N / "base" / item.filename[len("source_snapshot/") :])
                if item.filename.startswith("source_snapshot/")
                else (D / "handover" / item.filename)
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as out:
                out.write(z.read(item))
        guard.write(
            D / "source-provenance.json",
            {
                "passed": True,
                "public_commit": PIN,
                "root_tree": tree_id,
                "source_membership": manifest["source_files"],
                "verification": (
                    "Independent HTTPS GitHub commit/tree API object identities; not "
                    "an upstream signature verification"
                ),
                "metadata_bytes": charged,
            },
        )

        row = entries["src/bn254.cpp"]
        assert row["type"] == "blob" and row["mode"] == "100644"
        data = fetch(
            "https://raw.githubusercontent.com/ligeroinc/ligero-prover/" + PIN + "/src/bn254.cpp",
            min(row["size"], META_CAP - charged),
        )
        assert len(data) == row["size"] and blob(data) == row["sha"]
        (N / "base/src/bn254.cpp").write_bytes(data)
        guard.write(
            D / "additional-source.json",
            {
                "path": "src/bn254.cpp",
                "bytes": len(data),
                "git_blob": row["sha"],
                "sha256": sha(data),
                "commit": PIN,
            },
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        guard.write(
            D / "acquisition-failure.json",
            {
                "type": type(exc).__name__,
                "error": str(exc),
                "records": records,
                "charged_metadata_bytes": charged,
                "retry": False,
            },
        )
        raise
    finally:
        guard.write(
            D / "source-acquisition.json",
            {"records": records, "charged_metadata_bytes": charged, "cap_bytes": META_CAP},
        )
