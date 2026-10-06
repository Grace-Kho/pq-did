"""Pinned project-local acquisition and static verification; no downloaded scripts."""

import gzip
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tarfile
import time
from pathlib import Path, PurePosixPath

R = Path(__file__).resolve().parent
N = R.parent
P = N.parents[2]
LOCKDIR = P / "docs/data/s3_aurora_native_dependency_lock_1"
ROOT = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
commands = []
state = {"status": "started", "source_repositories": [], "packages": [], "native_admitted": False}


def write(name, value):
    data = json.dumps(value, indent=2) + "\n"
    assert len(data.encode()) < 1048576
    (R / name).write_text(data)


def read(path):
    return json.loads(path.read_text())


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args, timeout=10, limit=61440):
    start = time.monotonic()
    row = {"argv": list(map(str, args)), "status": "started"}
    commands.append(row)
    write("commands.json", commands)
    env = os.environ.copy()
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    result = subprocess.run(args, cwd=P, env=env, capture_output=True, timeout=timeout)
    assert len(result.stdout) + len(result.stderr) <= limit, "bounded command output"
    row.update(
        exit_code=result.returncode,
        seconds=time.monotonic() - start,
        stdout=result.stdout.decode(errors="replace"),
        stderr=result.stderr.decode(errors="replace"),
        status="pass" if result.returncode == 0 else "failed",
    )
    write("commands.json", commands)
    assert result.returncode == 0, "command failed: " + " ".join(map(str, args))
    return result.stdout


def verify_sources(node):
    name, pin = node["id"], node["commit"]
    dest = ROOT / "src" / name
    command(["git", "-c", "init.templateDir=", "init", str(dest)])
    command(["git", "-C", str(dest), "remote", "add", "origin", node["origin"]])
    command(
        [
            "git",
            "-C",
            str(dest),
            "-c",
            "core.hooksPath=/dev/null",
            "fetch",
            "--no-tags",
            "--depth=1",
            "origin",
            pin,
        ],
        timeout=12,
    )
    command(["git", "-C", str(dest), "-c", "core.hooksPath=/dev/null", "checkout", "--detach", pin])
    assert command(["git", "-C", str(dest), "rev-parse", "HEAD"]).decode().strip() == pin
    command(["git", "-C", str(dest), "fsck", "--full"])
    assert (
        command(["git", "-C", str(dest), "rev-parse", "HEAD^{tree}"]).decode().strip()
        == node["tree_git_sha1"]
    )
    tree = json.loads(gzip.decompress((LOCKDIR / "metadata" / (name + "-tree.gz")).read_bytes()))
    assert not tree["truncated"]
    expected = {x["path"]: x for x in tree["tree"] if x["type"] != "tree"}
    listing = command(["git", "-C", str(dest), "ls-tree", "-r", "-z", "HEAD"], limit=131072)
    rows = {}
    for raw in listing.rstrip(b"\0").split(b"\0"):
        metadata, path = raw.split(b"\t", 1)
        mode, kind, sha = metadata.decode().split()
        path = path.decode()
        assert path not in rows
        rows[path] = (mode, kind, sha)
    assert set(rows) == set(expected)
    total = 0
    for path, (mode, kind, sha) in rows.items():
        exp = expected[path]
        assert (mode, kind, sha) == (exp["mode"], exp["type"], exp["sha"])
        file = dest / path
        if kind == "commit":
            assert file.is_dir() and not any(file.iterdir()), (
                "optional gitlink unexpectedly populated"
            )
            continue
        assert kind == "blob" and mode in {"100644", "100755"}, "unexpected source mode"
        assert file.is_file() and not file.is_symlink()
        data = file.read_bytes()
        assert len(data) == exp["size"] <= 1048576
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert blob == sha, path
        assert bool(file.stat().st_mode & 0o111) == (mode == "100755")
        total += len(data)
    assert not command(["git", "-C", str(dest), "status", "--porcelain", "--untracked-files=all"])
    result = {
        "repository": name,
        "commit": pin,
        "tree": node["tree_git_sha1"],
        "entries": len(rows),
        "blob_bytes": total,
        "gitlinks": {path: sha for path, (_, kind, sha) in rows.items() if kind == "commit"},
        "full_tree_and_worktree_verified": True,
        "submodules_initialised": False,
    }
    state["source_repositories"].append(result)
    write("provision-result.json", state)


def archive_members(path):
    process = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(path)], stdout=subprocess.PIPE)
    rows = []
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as stream:
            for member in stream:
                name = PurePosixPath(member.name)
                assert not name.is_absolute() and ".." not in name.parts
                assert member.isfile() or member.isdir() or member.issym() or member.islnk()
                assert len(rows) < 4096 and member.size <= 33554432
                if member.isfile():
                    assert not member.mode & 0o111, "unexpected executable package member"
                if member.issym() or member.islnk():
                    assert not PurePosixPath(member.linkname).is_absolute()
                    target = (ROOT / "prefix" / name.parent / member.linkname).resolve()
                    assert target.is_relative_to(ROOT / "prefix"), "escaping archive link"
                rows.append(
                    {
                        "path": str(name),
                        "size": member.size,
                        "type": member.type.decode(),
                        "mode": member.mode,
                        "link": member.linkname,
                    }
                )
    finally:
        process.stdout.close()
        code = process.wait(timeout=2)
    assert code == 0
    names = [row["path"] for row in rows]
    assert len(names) == len(set(names)), "duplicate archive member"
    return rows


def verify_static_archive(path):
    machines = []
    with path.open("rb") as stream:
        assert stream.read(8) == b"!<arch>\n"
        while header := stream.read(60):
            assert len(header) == 60 and header[58:] == b"`\n"
            size = int(header[48:58])
            name = header[:16].decode().strip()
            data = stream.read(size)
            assert len(data) == size
            if name not in {"/", "//", "/SYM64/"}:
                assert data[:7] == b"\x7fELF\x02\x01\x01", "non-amd64/little ELF object"
                kind, machine = struct.unpack_from("<HH", data, 16)
                assert kind == 1 and machine == 62, "non-relocatable/x86-64 object"
                machines.append(name)
            if size % 2:
                assert stream.read(1) == b"\n"
    assert machines
    return {
        "path": str(path.relative_to(P)),
        "members": len(machines),
        "ELFCLASS64": True,
        "little_endian": True,
        "machine": "EM_X86_64",
        "sha256": digest(path),
    }


def run(_name):
    try:
        seal = LOCKDIR / "continuation-1/manifest.json"
        assert digest(seal) == "e83682e08a9bdd8ca0b2fc542621ee87e4e8eca492ce0e2801111a2b6055ec36"
        for name, value in read(seal)["sha256"].items():
            assert digest(P / name) == value, name
        lockpath = LOCKDIR / "dependency-lock.json"
        assert (
            digest(lockpath) == "9f95bcb9f82d4cb5f8caaf2ca41e9e22b17ea39e8146474ca055e1d67eae617f"
        )
        lock = read(lockpath)
        assert lock["unresolved_required_revision_pins"] == []
        for tool in ("git", "curl", "dpkg-deb", "ar", "readelf", "cmake", "ninja", "c++"):
            assert shutil.which(tool), "missing approved tool: " + tool
        assert not ROOT.exists()
        write(
            "admission.json",
            {
                "proposal_seal_verified": digest(seal),
                "lock_verified": digest(lockpath),
                "current_cumulative_evidence_bytes": 10689507,
                "cumulative_cap": 12386485,
                "work_reservation_bytes": 1048576,
                "completion_reservation_bytes": 524288,
                "artifact_cap": 134217728,
                "acquisition_reservation": 33554432,
                "binary_per_file": 33554432,
                "ordinary_per_file": 1048576,
                "provisioning_deadline": 55,
                "provisioning_subcap_with_bookkeeping": 60,
                "native_opening_seconds": 291.7509900990408,
                "implementation_opening_seconds": 296.30836975807324,
                "analysis_unchanged": 179.79552399821114,
                "conditional_native_build": True,
                "host_mutations": False,
                "installed_tools_present": True,
            },
        )
        for name in ("src", "packages", "prefix", "evidence"):
            (ROOT / name).mkdir(parents=True)
        for node in lock["nodes"]:
            verify_sources(node)
        bridge = P / "docs/data/s3_aurora_transcript_bridge_1"
        count = 0
        for filename in ("sources.json", "sources-supplement.json"):
            for row in read(bridge / filename)["rows"]:
                path = ROOT / "src/libiop" / row["path"]
                assert path.stat().st_size == row["bytes"] and digest(path) == row["sha256"]
                count += 1
        assert count == 21
        for row in read(N / "source-copy.json")["copied"]:
            assert (
                digest(ROOT / "src/libiop" / row["upstream_path"])
                == digest(P / row["path"])
                == row["sha256"]
            )
        state["retained_files_matched"] = {"snapshot": 21, "historical_copies": 8}
        write("provision-result.json", state)
        for pkg in lock["packages"]:
            archive = ROOT / "packages" / pkg["url"].split("/")[-1]
            command(
                [
                    "curl",
                    "--fail",
                    "--location",
                    "--max-time",
                    "10",
                    "--max-filesize",
                    str(pkg["bytes"]),
                    pkg["url"],
                    "-o",
                    str(archive),
                ],
                timeout=11,
            )
            assert archive.stat().st_size == pkg["bytes"] and digest(archive) == pkg["sha256"], (
                "archive identity"
            )
            fields = command(
                [
                    "dpkg-deb",
                    "--field",
                    str(archive),
                    "Package",
                    "Version",
                    "Architecture",
                    "Depends",
                ]
            ).decode()
            for key, val in (
                ("Package", pkg["id"]),
                ("Version", pkg["version"]),
                ("Architecture", "amd64"),
            ):
                assert key + ": " + val in fields.splitlines()
            members = archive_members(archive)
            regular = {row["path"] for row in members if row["type"] == "0"}
            assert set(pkg["expected_headers"] + pkg["expected_libraries"]) <= regular
            write(
                pkg["id"] + "-members.json", {"archive_sha256": pkg["sha256"], "members": members}
            )
            command(["dpkg-deb", "--extract", str(archive), str(ROOT / "prefix")])
            libs = [
                verify_static_archive(ROOT / "prefix" / name) for name in pkg["expected_libraries"]
            ]
            for name in pkg["expected_headers"]:
                assert (ROOT / "prefix" / name).is_file()
            state["packages"].append(
                {
                    "package": pkg["id"],
                    "version": pkg["version"],
                    "sha256": pkg["sha256"],
                    "member_count": len(members),
                    "libraries": libs,
                }
            )
            write("provision-result.json", state)
        version = (ROOT / "prefix/usr/include/sodium/version.h").read_text()
        assert '#define SODIUM_VERSION_STRING "1.0.18"' in version
        version = (ROOT / "prefix/usr/include/x86_64-linux-gnu/gmp.h").read_text()
        assert "#define __GNU_MP_VERSION            6" in version
        assert "#define __GNU_MP_VERSION_MINOR      3" in version
        assert "#define __GNU_MP_VERSION_PATCHLEVEL 0" in version
        state.update(
            status="provisioned-static-prerequisites-pass",
            native_admitted=True,
            compilation_compatibility_verified=False,
            maintainer_scripts_executed=False,
        )
        write("provision-result.json", state)
    except Exception as error:
        state.update(
            status="blocked",
            error_type=type(error).__name__,
            error=str(error)[:2000],
            native_admitted=False,
        )
        write("provision-result.json", state)
        raise
