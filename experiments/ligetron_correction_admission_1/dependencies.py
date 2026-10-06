"""Extract bounded development-header closure; no installation or hooks."""

import hashlib
import re
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_correction_admission_1 import run as guard  # noqa: E402

D, N = guard.D, guard.N
PACKAGES = [
    (
        "libssl-dev_3.5.5-1ubuntu3.6_amd64.deb",
        "main/o/openssl",
        2935982,
        "dd956039c62a404aebfdde72a07d3ae633827da3910a67f67f7f6b912c9e1d7a",
        "3.5.5-1ubuntu3.6",
    ),
    (
        "libboost1.90-dev_1.90.0-6ubuntu1_amd64.deb",
        "main/b/boost1.90",
        11452296,
        "7b89698c907fd5d33ccd439674fa53803139923822181c87b910579827aca379",
        "1.90.0-6ubuntu1",
    ),
]


def sha(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        while b := f.read(262144):
            h.update(b)
    return h.hexdigest()


def members(archive, consume):
    proc = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(archive)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for item in tar:
                name = item.name.removeprefix("./")
                assert (
                    not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
                )
                consume(tar, item, name)
    finally:
        proc.stdout.close()
    if proc.wait(timeout=3):
        raise RuntimeError("package content stream failure")


def main():
    registry = guard.read(D / "artifact-outputs.json")
    for name, _, _, _, _ in PACKAGES:
        registry["paths"][str((N / "downloads" / name).relative_to(P))] = "package-archive"
    guard.write(D / "artifact-outputs.json", registry)
    packages = []
    for name, subdir, length, digest, version in PACKAGES:
        dest = N / "downloads" / name
        url = "https://archive.ubuntu.com/ubuntu/pool/" + subdir + "/" + name
        with urllib.request.urlopen(url, timeout=15) as response, dest.open("xb") as out:
            total = 0
            while data := response.read(min(262144, length + 1 - total)):
                out.write(data)
                total += len(data)
                if total > length:
                    raise RuntimeError("download length limit")
        assert total == length and sha(dest) == digest
        fields = subprocess.check_output(
            ["dpkg-deb", "-f", str(dest), "Version", "Architecture"], text=True, timeout=3
        )
        assert "Version: " + version in fields and "Architecture: amd64" in fields
        packages.append(
            {
                "path": str(dest.relative_to(P)),
                "url": url,
                "bytes": length,
                "sha256": digest,
                "control": fields,
                "maintainer_scripts_executed": False,
            }
        )
    guard.write(D / "download-verification.json", {"passed": True, "packages": packages})

    selected = {}

    def ssl(tar, item, name):
        if name.startswith(("usr/include/openssl/", "usr/include/x86_64-linux-gnu/openssl/")):
            if item.isdir():
                return
            assert item.isfile() and item.size <= 1048576
            selected[name] = tar.extractfile(item).read()

    members(N / "downloads" / PACKAGES[0][0], ssl)

    # Include all branches of the literal include closure, plus the macro-selected
    # Boost configuration headers. No compile/preprocess probe is used here.
    wanted = {
        "usr/include/boost/random/uniform_int_distribution.hpp",
        "usr/include/boost/version.hpp",
    }
    catalog = set()
    unresolved = set()

    def boost(tar, item, name):
        if not name.startswith("usr/include/boost/") or not item.isfile():
            return
        catalog.add(name)
        if name in wanted or name.startswith("usr/include/boost/config/"):
            assert item.size <= 1048576
            selected[name] = tar.extractfile(item).read()

    for _ in range(16):
        members(N / "downloads" / PACKAGES[1][0], boost)
        more = set()
        for name, data in list(selected.items()):
            if "/boost/" not in name:
                continue
            for inc in re.findall(rb'^\s*#\s*include\s*[<"]([^>"]+)[>"]', data, re.M):
                inc = inc.decode()
                target = (
                    "usr/include/" + inc
                    if inc.startswith("boost/")
                    else str(PurePosixPath(name).parent / inc)
                )
                if target in catalog:
                    more.add(target)
                elif inc.startswith("boost/"):
                    unresolved.add(inc)
        if more <= wanted:
            break
        wanted |= more
    else:
        raise RuntimeError("bounded Boost closure iteration limit")
    assert not unresolved, unresolved
    assert wanted <= selected.keys(), wanted - selected.keys()
    assert sum(map(len, selected.values())) <= 16 * 1048576
    for name in selected:
        registry["paths"][str((N / "prefix" / name).relative_to(P))] = "development-header"
    guard.write(D / "artifact-outputs.json", registry)
    hashes = {}
    for name, data in sorted(selected.items()):
        dst = N / "prefix" / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        with dst.open("xb") as out:
            out.write(data)
        hashes[str(dst.relative_to(P))] = hashlib.sha256(data).hexdigest()
    guard.write(
        D / "header-closure.json",
        {
            "passed": True,
            "literal_include_closure": True,
            "macro_configuration_directory_included": True,
            "headers": hashes,
            "bytes": sum(map(len, selected.values())),
            "build_compatibility": "UNTESTED",
        },
    )


def link_checks():
    gmp = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/prefix"
    old = guard.read(
        P / "docs/data/s3_aurora_native_transcript_pilot_1/reconciliation-1/libgmp-dev-members.json"
    )
    retained = {}
    for name in (
        "usr/include/gmpxx.h",
        "usr/include/x86_64-linux-gnu/gmp.h",
        "usr/lib/x86_64-linux-gnu/libgmp.a",
        "usr/lib/x86_64-linux-gnu/libgmpxx.a",
    ):
        archive = gmp.parent / "packages/libgmp-dev_6.3.0+dfsg-5ubuntu2_amd64.deb"
        assert sha(archive) == old["archive_sha256"]
        expected = {}

        def read_member(tar, item, path, name=name, expected=expected):
            if path == name:
                assert item.isfile()
                expected["hash"] = hashlib.sha256(tar.extractfile(item).read()).hexdigest()

        members(archive, read_member)
        actual = sha(gmp / name)
        assert actual == expected["hash"], name
        retained[str((gmp / name).relative_to(P))] = actual
    lib = Path("/usr/lib/x86_64-linux-gnu/libcrypto.so.3").resolve(strict=True)
    elf = subprocess.check_output(["readelf", "-h", str(lib)], text=True, timeout=3)
    assert "Advanced Micro Devices X86-64" in elf
    symbols = subprocess.check_output(
        ["readelf", "--wide", "--dyn-syms", str(lib)], text=True, timeout=3
    )
    for symbol in (
        "RAND_priv_bytes",
        "EVP_EncryptInit_ex",
        "EVP_EncryptUpdate",
        "EVP_DigestFinal_ex",
    ):
        assert symbol in symbols, symbol
    versions = subprocess.check_output(
        [
            "dpkg-query",
            "-W",
            "-f=${Package} ${Version} ${Architecture}\n",
            "libssl3t64",
            "g++-15",
            "libstdc++-15-dev",
        ],
        text=True,
        timeout=3,
    )
    assert "libssl3t64 3.5.5-1ubuntu3.6 amd64" in versions
    header = (N / "prefix/usr/include/openssl/opensslv.h").read_text()
    assert '"3.5.5"' in header
    guard.write(
        D / "link-admission.json",
        {
            "passed": True,
            "libcrypto": str(lib),
            "libcrypto_sha256": sha(lib),
            "elf_header": elf,
            "versions": versions,
            "retained_GMP_sha256": retained,
            "link_compatibility": "requires counted build; no probe run",
            "known_missing_full_backend_dependencies": [
                "Dawn",
                "WABT",
                "Protobuf",
                "full VM include closure",
            ],
        },
    )


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["finish"]:
            link_checks()
        else:
            main()
            link_checks()
    except Exception as exc:
        guard.write(
            D / ("dependency-finish-failure.json" if sys.argv[1:] else "dependency-failure.json"),
            {"type": type(exc).__name__, "error": str(exc), "retry": False},
        )
        raise
