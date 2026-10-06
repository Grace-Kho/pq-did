"""Losslessly retain only this fresh failed fixture before bounded cleanup."""

import hashlib
import shutil
import sys
import tarfile
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.kyc_manager_incremental_storage_1 import run as g  # noqa: E402

root = g.D / "tmp/H"
case = "H-15" if len(sys.argv) == 1 else sys.argv[1]
assert case in {"H-15", "H-17"}
archive = g.D / ("failed-" + case + ".tar.xz")
assert not archive.exists()
files = {}
for path in sorted(root.rglob("*")):
    assert not path.is_symlink()
    if path.is_file():
        assert path.stat().st_size <= 524288
        files[str(path.relative_to(root))] = {
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": path.stat().st_mode & 0o777,
        }
with tarfile.open(archive, "x:xz", preset=1) as out:
    for name in files:
        out.add(root / name, arcname=name, recursive=False)
with tarfile.open(archive, "r:xz") as retained:
    assert set(retained.getnames()) == set(files)
    for item in retained:
        assert item.isfile() and item.size == files[item.name]["bytes"]
        data = retained.extractfile(item).read(item.size + 1)
        assert hashlib.sha256(data).hexdigest() == files[item.name]["sha256"]
g.write(
    g.D / ("failed-" + case + "-inventory.json"),
    {
        "files": files,
        "raw_bytes": sum(v["bytes"] for v in files.values()),
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "readback_complete": True,
        "historical_artifacts_changed": False,
        "scope": "Only this package's newly created failed H fixture; synthetic keys included",
    },
)
assert archive.stat().st_size <= g.POLICY["ordinary_file_bytes"]
g.storage()
shutil.rmtree(root)
print("Fresh failed fixture retained losslessly; original failure remains failed")
