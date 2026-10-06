"""Verify commit/tree object identities, then continue pinned provisioning once."""

import copy
import gzip
import hashlib
import json
import os
import textwrap
import types
from pathlib import Path

R = Path(__file__).resolve().parent
N = R.parent
P = N.parents[2]
PREVIOUS = N / "provisioning-1"
LOCKDIR = P / "docs/data/s3_aurora_native_dependency_lock_1"
ROOT = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
old = types.ModuleType("retained_provisioner")
old.__file__ = str(PREVIOUS / "provision.py")
source = Path(old.__file__).read_text()
exec(compile(source, old.__file__, "exec"), old.__dict__)
old.R = R
read, write, digest = old.read, old.write, old.digest
original_command = old.command
os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
os.environ["GIT_OPTIONAL_LOCKS"] = "0"


def command(args, **kwargs):
    if args[0] == "git":
        args = [args[0], "--no-replace-objects", *args[1:]]
    return original_command(args, **kwargs)


old.command = command
old.state = {"status": "reconciling", "source_repositories": [], "packages": [],
             "native_admitted": False}


def git(dest, *args):
    return command(["git", "-C", str(dest), *args])


def association(node):
    dest, pin = ROOT / "src" / node["id"], node["commit"]
    if node["id"] == "libiop":
        assert dest.is_dir()
    else:
        assert not dest.exists(), "remaining pin must not have been fetched already"
        command(["git", "-c", "init.templateDir=", "init", str(dest)])
        git(dest, "remote", "add", "origin", node["origin"])
        git(dest, "-c", "core.hooksPath=/dev/null", "fetch", "--no-tags", "--depth=1", "origin", pin)
    assert git(dest, "remote", "get-url", "origin").decode().strip() == node["origin"]
    assert git(dest, "cat-file", "-t", pin) == b"commit\n"
    raw = git(dest, "cat-file", "commit", pin)
    assert hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == pin
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    trees = [line.split()[1].decode() for line in headers if line.startswith(b"tree ")]
    assert len(trees) == 1
    tree = trees[0]
    assert git(dest, "rev-parse", pin + "^{tree}").decode().strip() == tree
    assert git(dest, "cat-file", "-t", tree) == b"tree\n"
    if node["id"] == "libiop":
        assert tree == "2e2588ccb085242dd2237875c3b9adf1a0fc958c"
        assert git(dest, "rev-parse", "HEAD").decode().strip() == pin
    else:
        git(dest, "fsck", "--full")
    return {"repository": node["id"], "origin": node["origin"], "commit": pin,
            "commit_type": "commit", "raw_commit_sha1_verified": pin,
            "stored_tree_header": tree, "resolved_tree": tree, "tree_type": "tree",
            "replacement_objects_disabled": True, "optional_git_writes_disabled": True,
            "before": node["tree_git_sha1"], "after": tree,
            "existing_fsck_reused": node["id"] == "libiop"}


def verify_tree(node):
    name, pin = node["id"], node["commit"]
    dest = ROOT / "src" / name
    if name != "libiop":
        git(dest, "-c", "core.hooksPath=/dev/null", "checkout", "--detach", pin)
    metadata = json.loads(gzip.decompress((LOCKDIR / "metadata" / (name + "-tree.gz")).read_bytes()))
    assert not metadata["truncated"]
    expected = {x["path"]: x for x in metadata["tree"] if x["type"] != "tree"}
    listing = command(["git", "-C", str(dest), "ls-tree", "-r", "-z", pin], limit=131072)
    rows = {}
    for entry in listing.rstrip(b"\0").split(b"\0"):
        meta, path = entry.split(b"\t", 1)
        path = path.decode()
        assert path not in rows
        rows[path] = meta.decode().split()
    assert set(rows) == set(expected), "tree path inventory mismatch"
    total = 0
    for path, (mode, kind, sha) in rows.items():
        exp = expected[path]
        assert (mode, kind, sha) == (exp["mode"], exp["type"], exp["sha"]), path
        file = dest / path
        if kind == "commit":
            assert mode == "160000" and file.is_dir() and not any(file.iterdir())
            continue
        assert kind == "blob" and mode in {"100644", "100755"}
        assert file.is_file() and not file.is_symlink()
        data = file.read_bytes()
        assert len(data) == exp["size"] <= 1048576
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == sha
        assert bool(file.stat().st_mode & 0o111) == (mode == "100755")
        total += len(data)
    assert not git(dest, "status", "--porcelain", "--untracked-files=all")
    old.state["source_repositories"].append({"repository": name, "commit": pin,
        "tree": node["tree_git_sha1"], "tree_entries": len(rows), "blob_bytes": total,
        "full_tree_and_worktree_verified": True, "gitlink_commits_preserved": True})
    write("provision-result.json", old.state)


def run(_name):
    try:
        seal = PREVIOUS / "manifest.json"
        assert digest(seal) == "71edab13cfc0ab322d5668e466bf65668d8e7ab94f9884d32f9b77ad9f9d48f8"
        for name, expected in read(seal)["sha256"].items():
            assert digest(P / name) == expected, name
        with gzip.open(PREVIOUS / "artifact-inventory.json.gz", "rt") as stream:
            retained = json.load(stream)
        for row in retained["files"]:
            assert digest(P / row["path"]) == row["sha256"], row["path"]
        lockpath = LOCKDIR / "dependency-lock.json"
        assert digest(lockpath) == "9f95bcb9f82d4cb5f8caaf2ca41e9e22b17ea39e8146474ca055e1d67eae617f"
        lock = read(lockpath)
        # Inspect all selected fields and gitlink semantics before further acquisition.
        assert all(n["tree_git_sha1"] == n["commit"] for n in lock["nodes"])
        assert all("tree_git_sha1" not in row and len(row["commit"]) == 40
                   for row in lock["recorded_gitlinks"])
        proofs = []
        for node in lock["nodes"]:
            proofs.append(association(node))
            write("object-associations.json", {"proofs": proofs, "corrections_applied": False})
        corrected = copy.deepcopy(lock)
        for node, proof in zip(corrected["nodes"], proofs, strict=True):
            assert node["commit"] == proof["commit"]
            node["tree_git_sha1"] = proof["after"]
        reverted = copy.deepcopy(corrected)
        for node, proof in zip(reverted["nodes"], proofs, strict=True):
            node["tree_git_sha1"] = proof["before"]
        assert reverted == lock, "only tree identity fields may change"
        write("dependency-lock-v2.json", corrected)
        write("lock-correction.json", {"before_path": str(lockpath.relative_to(P)),
            "before_sha256": digest(lockpath), "after_path": str((R / "dependency-lock-v2.json").relative_to(P)),
            "after_sha256": digest(R / "dependency-lock-v2.json"), "changes": proofs,
            "only_changed_fields": ["nodes[0].tree_git_sha1", "nodes[1].tree_git_sha1", "nodes[2].tree_git_sha1"],
            "revisions_origins_archive_hashes_gitlinks_unchanged": True})
        for node in corrected["nodes"]:
            verify_tree(node)
        # Reuse the reviewed archive/ABI checks exactly; no changes to artifact pins.
        body = source[source.index('        bridge = P / "docs/data/s3_aurora_transcript_bridge_1"'):source.index('    except Exception as error:')]
        exec(compile("def finish(lock):\n" + textwrap.indent(textwrap.dedent(body), "    "),
                     str(PREVIOUS / "provision.py"), "exec"), old.__dict__)
        old.finish(corrected)
    except Exception as error:
        old.state.update(status="blocked", native_admitted=False,
                         error_type=type(error).__name__, error=str(error)[:2000])
        write("provision-result.json", old.state)
        raise
