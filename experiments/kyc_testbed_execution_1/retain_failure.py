"""Lossless retention then cleanup of this run's exact disposable failed fixture.

Never touches a historical store. The archive and per-file inventory retain all
failed bytes, including synthetic private keys, under the same evidence accounting.
"""

import hashlib
import json
import os
import stat
import sys
import tarfile
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_testbed_execution_1 import run as guard  # noqa: E402


def main():
    root = guard.D / "tmp/R-1-4"
    archive = guard.D / "failed-R-1-4.tar.xz"
    assert root.is_dir() and not archive.exists()
    files = sorted(p for p in root.rglob("*") if p.is_file())
    inventory = {}
    for path in files:
        st = path.lstat()
        assert stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
        assert not path.is_symlink() and st.st_size <= 524288
        inventory[path.relative_to(root).as_posix()] = dict(
            bytes=st.st_size,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            mode=stat.S_IMODE(st.st_mode),
        )
    assert set(inventory) == {
        "manager/authority.sqlite3",
        "issuer/issuer.sqlite3",
        "verifier-A/authority.sqlite3",
        "verifier-B/authority.sqlite3",
        "holder/holder.key",
        "holder/wallet.bin",
        "holder-other-0/holder.key",
        "holder-other-0/wallet.bin",
        "holder-other-1/holder.key",
        "holder-other-1/wallet.bin",
        "holder-other-2/holder.key",
        "holder-other-2/wallet.bin",
    }
    with tarfile.open(archive, "x:xz", preset=1) as output:
        for path in files:
            output.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
    with tarfile.open(archive, "r:xz") as source:
        members = source.getmembers()
        assert len(members) == len(inventory) and {m.name for m in members} == set(inventory)
        for member in members:
            expected = inventory[member.name]
            assert (
                member.isfile()
                and member.size == expected["bytes"]
                and member.mode == expected["mode"]
            )
            with source.extractfile(member) as stream:
                digest = hashlib.sha256()
                while data := stream.read(65536):
                    digest.update(data)
            assert digest.hexdigest() == expected["sha256"]
    guard.write(
        guard.D / "failed-R-1-4-inventory.json",
        dict(
            files=inventory,
            raw_bytes=sum(v["bytes"] for v in inventory.values()),
            archive_bytes=archive.stat().st_size,
            archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            readback_complete=True,
            action=(
                "Exact new disposable fixture archived losslessly before cleanup; "
                "no historical evidence moved/deleted"
            ),
            classification="evidence including synthetic private material; no reclassification",
        ),
    )
    for path in files:
        path.unlink()
    for path in sorted(root.rglob("*"), reverse=True):
        path.rmdir()
    root.rmdir()
    print(json.dumps(dict(retained_files=len(files), archive_bytes=archive.stat().st_size)))


if __name__ == "__main__":
    main()
