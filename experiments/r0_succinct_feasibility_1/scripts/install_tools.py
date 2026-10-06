"""Install only pinned assets under tooling; verify upstream SHA-256 first."""

import hashlib
import json
import os
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tooling/downloads"
OUT.mkdir(exist_ok=True)
record = []


def fetch(url, path, size, expected=None):
    req = urllib.request.Request(url, headers={"User-Agent": "PQ-DID-isolated-toolchain"})
    h = hashlib.sha256()
    n = 0
    start = time.monotonic()
    with urllib.request.urlopen(req, timeout=30) as r, path.open("wb") as f:
        while chunk := r.read(1024**2):
            n += len(chunk)
            if n > size:
                raise ValueError("asset size cap")
            f.write(chunk)
            h.update(chunk)
    if expected and h.hexdigest() != expected:
        raise ValueError("upstream digest mismatch")
    record.append(
        {
            "url": url,
            "path": str(path.relative_to(ROOT)),
            "bytes": n,
            "sha256": h.hexdigest(),
            "upstream_digest_matched": bool(expected),
            "seconds": time.monotonic() - start,
        }
    )
    (ROOT / "evidence/install_assets.json").write_text(json.dumps(record, indent=2) + "\n")
    print(path.name, n, h.hexdigest(), flush=True)


def asset(meta, name, dest):
    a = next(
        x for x in json.loads((ROOT / "sources" / meta).read_text())["assets"] if x["name"] == name
    )
    file = OUT / name
    fetch(a["browser_download_url"], file, a["size"], a["digest"].split(":")[1])
    with tarfile.open(file) as t:
        total = sum(m.size for m in t.getmembers())
        if total > 3 * 1024**3:
            raise ValueError("expanded asset cap")
        print(
            "archive members",
            name,
            [m.name for m in t.getmembers()[:15]],
            "expanded",
            total,
            flush=True,
        )
        t.extractall(ROOT / "tooling" / dest, filter="data")


asset("sdk_release.json", "cargo-risczero-x86_64-unknown-linux-gnu.tgz", "sdk-3.0.6")
asset("rust_release.json", "rust-toolchain-x86_64-unknown-linux-gnu.tar.gz", "guest-r0.1.97.0")
url = "https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init"
with urllib.request.urlopen(url + ".sha256", timeout=30) as r:
    expected = r.read(256).decode().split()[0]
file = OUT / "rustup-init"
fetch(url, file, 32 * 1024**2, expected)
file.chmod(0o700)
install_env = os.environ.copy()
# Independently enforce isolation here, even when invoked without run_limited.py.
# HOME is deliberately unchanged; rustup/cargo destinations are explicit.
for key, relative in [("CARGO_HOME", "tooling/cargo"), ("RUSTUP_HOME", "tooling/rustup")]:
    destination = ROOT / relative
    destination.mkdir(parents=True, exist_ok=True)
    if not destination.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("installation path escapes experimental workspace")
    install_env[key] = str(destination.resolve())
print(
    "Isolated rustup destinations",
    {k: install_env[k] for k in ["CARGO_HOME", "RUSTUP_HOME"]},
    flush=True,
)
subprocess.run(
    [str(file), "-y", "--no-modify-path", "--default-toolchain", "none"],
    env=install_env,
    check=True,
)
print(
    "Asset installation complete; toolchain registration is a separate inspected step", flush=True
)
