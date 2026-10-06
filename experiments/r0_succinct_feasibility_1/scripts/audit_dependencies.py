"""Record exact locked versions, crate digests and primary RustSec advisory matches.
No compilation or execution of downloaded dependencies occurs here.
"""

import hashlib
import io
import json
import re
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def get(url, maxbytes=16 * 1024**2):
    with urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "PQ-DID-locked-dependency-review"}),
        timeout=30,
    ) as r:
        data = r.read(maxbytes + 1)
    if len(data) > maxbytes:
        raise ValueError("source cap")
    return data


if "--offline" in sys.argv:
    commit = json.loads((ROOT / "evidence/dependency_audit.json").read_text())["rustsec_commit"]
    archive = (ROOT / "sources/rustsec.tar.gz").read_bytes()
else:
    meta = json.loads(get("https://api.github.com/repos/RustSec/advisory-db/commits/main"))
    commit = meta["sha"]
    archive = get("https://codeload.github.com/RustSec/advisory-db/tar.gz/" + commit)
(ROOT / "sources/rustsec.tar.gz").write_bytes(archive)
locks = {
    name: tomllib.loads((ROOT / name).read_text())["package"]
    for name in ["Cargo.lock", "methods/guest/Cargo.lock", "sources/sdk_Cargo.lock"]
}
versions = {x["name"]: set() for ps in locks.values() for x in ps}
for ps in locks.values():
    for x in ps:
        versions[x["name"]].add(x["version"])
matches = []
with tarfile.open(fileobj=io.BytesIO(archive)) as tf:
    for item in tf.getmembers():
        if item.name.endswith(".md") and "/crates/" in item.name and item.size < 200000:
            text = tf.extractfile(item).read().decode()
            m = re.search(r"```toml\s*\n(.*?)\n```", text, re.S)
            if not m:
                continue
            data = tomllib.loads(m[1])
            a = data.get("advisory", {})
            name = a.get("package")
            if name in versions:
                matches.append(
                    {
                        "id": a.get("id"),
                        "package": name,
                        "locked_versions": sorted(versions[name]),
                        "title": a.get("title"),
                        "url": a.get("url"),
                        "informational": a.get("informational"),
                        "withdrawn": str(a.get("withdrawn", "")),
                        "versions": data.get("versions"),
                        "source_path": item.name,
                        "advisory_text": text,
                    }
                )
cache = ROOT / "tooling/cargo/registry/cache"
verified = []
for ps in locks.values():
    for p in ps:
        if "checksum" not in p:
            continue
        hits = list(cache.glob("*/" + p["name"] + "-" + p["version"] + ".crate"))
        if hits:
            digest = hashlib.sha256(hits[0].read_bytes()).hexdigest()
            assert digest == p["checksum"]
            verified.append((p["name"], p["version"]))
result = {
    "rustsec_commit": commit,
    "rustsec_url": "https://github.com/RustSec/advisory-db/tree/" + commit,
    "archive_SHA256": hashlib.sha256(archive).hexdigest(),
    "lock_SHA256": {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in locks},
    "locked_packages": {
        n: [
            {
                "name": p["name"],
                "version": p["version"],
                "source": p.get("source"),
                "checksum": p.get("checksum"),
            }
            for p in ps
        ]
        for n, ps in locks.items()
    },
    "cached_crate_checksums_verified": len(set(verified)),
    "package_name_advisory_matches": matches,
    "review_note": (
        "Name matches are not automatically applicable vulnerabilities; inspe"
        "ct affected ranges and exact enabled features. No claim of absence o"
        "f undisclosed vulnerabilities."
    ),
}
(ROOT / "evidence/dependency_audit.json").write_text(
    json.dumps(result, indent=2, default=str) + "\n"
)
print(
    json.dumps(
        {
            "rustsec_commit": commit,
            "cached_crates_verified": len(set(verified)),
            "matches": [
                {
                    k: m[k]
                    for k in [
                        "id",
                        "package",
                        "locked_versions",
                        "title",
                        "versions",
                        "informational",
                        "withdrawn",
                    ]
                }
                for m in matches
            ],
        },
        indent=2,
    )
)
