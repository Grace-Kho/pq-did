"""Read-only allowlisted deployment metadata; never read stores or credentials."""

import _sqlite3
import datetime
import grp
import hashlib
import json
import os
import platform
import pwd
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
P = BASE.parents[2]
ROLES = ("m", "i", "va", "vb")
ACCOUNTS = [f"pqiso-{kind}-{role}" for kind in ("o", "w") for role in ROLES]
ACCOUNTS += ["pqiso-admin", "pqiso-observer", "pqiso-rec-a", "pqiso-rec-b", "pqiso-denied"]


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
    assert len(result.stdout) + len(result.stderr) <= 32768
    return {
        "command": args,
        "exit_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def metadata(path):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"path": str(path), "exists": False}
    return {
        "path": str(path),
        "exists": True,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": oct(stat.S_IMODE(info.st_mode)),
        "symlink": path.is_symlink(),
        "link_target": os.readlink(path) if path.is_symlink() else None,
        "size": info.st_size,
        "links": info.st_nlink,
    }


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def main():
    paths = [
        "/",
        "/home",
        "/home/grace",
        "/home/grace/projects",
        P,
        P / "src",
        P / ".venv",
        P / ".venv/bin",
        P / ".venv/bin/python",
        "/usr",
        "/usr/bin",
        "/usr/bin/python3.14",
        Path(_sqlite3.__file__),
        P / "native/.deps/install/lib",
        P / "native/.deps/install/lib/liboqs.so",
        P / ".tools/uv",
        "/opt",
        "/etc",
        "/var/lib",
        "/run",
        "/opt/pqiso",
        "/etc/pqiso",
        "/var/lib/pqiso",
        "/run/pqiso",
        "/sys/fs/cgroup/cgroup.controllers",
    ]
    site = P / ".venv/lib/python3.14/site-packages"
    packaging = {}
    for name in ("_pqdid.pth", "_virtualenv.pth", "pqdid-0.0.1.dist-info/direct_url.json"):
        path = site / name
        assert path.stat().st_size <= 4096
        packaging[name] = {"metadata": metadata(path), "text": path.read_text()}
    existing_accounts = {}
    for name in ACCOUNTS:
        try:
            entry = pwd.getpwnam(name)
            existing_accounts[name] = {"uid": entry.pw_uid, "gid": entry.pw_gid}
        except KeyError:
            existing_accounts[name] = None
    groups = []
    for gid in os.getgroups():
        groups.append({"gid": gid, "name": grp.getgrgid(gid).gr_name})
    library = P / "native/.deps/install/lib/liboqs.so"
    fs = os.statvfs(P)
    uv_help = command([str(P / ".tools/uv"), "sync", "--help"])
    flags = (
        "--offline",
        "--frozen",
        "--link-mode",
        "--no-dev",
        "--python",
        "--no-python-downloads",
        "--project",
    )
    facts = {
        "package": "S2-AUTHORITY-ISOLATION-PLAN-1",
        "observed_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "view": "User-service guard with remapped IDs; consult host-metadata.json",
        "guard_mount_note": "Project bind mount is read-only in this inspection service",
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": groups,
        "process_status": [
            line
            for line in Path("/proc/self/status").read_text().splitlines()
            if line.split(":")[0] in {"Uid", "Gid", "Groups", "NoNewPrivs"}
        ],
        "pid1_metadata": [
            line
            for line in Path("/proc/1/status").read_text().splitlines()
            if line.split(":")[0] in {"Name", "Uid", "Gid"}
        ],
        "uid_map": Path("/proc/self/uid_map").read_text().strip(),
        "kernel": platform.release(),
        "python": sys.version,
        "executable": sys.executable,
        "base_prefix": sys.base_prefix,
        "prefix": sys.prefix,
        "sys_path": sys.path,
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_extension": _sqlite3.__file__,
        "paths": [metadata(path) for path in paths],
        "editable_and_environment_paths": packaging,
        "liboqs_python_metadata_dependencies": [
            line
            for line in (site / "liboqs_python-0.16.0.dist-info/METADATA").read_text().splitlines()
            if line.startswith(("Name:", "Version:", "Requires-Dist:"))
        ],
        "proposed_account_collisions": existing_accounts,
        "system_manager": command(
            ["systemctl", "show", "--no-pager", "--property=Version,Virtualization,ControlGroup"]
        ),
        "user_manager": command(
            ["systemctl", "--user", "show", "--no-pager", "--property=Version,ControlGroup"]
        ),
        "systemd_build": command(["systemctl", "--version"]),
        "filesystem": command(
            ["findmnt", "-T", str(P), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "--json"]
        ),
        "filesystem_available_bytes": fs.f_bavail * fs.f_frsize,
        "cgroup_controllers": Path("/sys/fs/cgroup/cgroup.controllers").read_text().strip(),
        "interpreter_linkage": command(["ldd", "/usr/bin/python3.14"]),
        "sqlite_linkage": command(["ldd", _sqlite3.__file__]),
        "native_linkage": command(["ldd", str(library)]),
        "uv_version": command([str(P / ".tools/uv"), "--version"]),
        "uv_sync_flags_locally_documented": {flag: flag in uv_help["stdout"] for flag in flags},
        "approved_public_file_sha256": {
            str(path.relative_to(P)): digest(path)
            for path in (
                P / "docs/manuscript/PQ_DID__Implementation.pdf",
                P / ".tools/uv",
                library,
                P / "uv.lock",
                P / "pyproject.toml",
            )
        },
        "existing_pilot_endpoints": "Temporary fixture role-ipc/s or t; prior cleanup complete",
        "existing_owner_tmp_empty": not any(
            (P / "docs/data/s2_authority_owner_boundary_1/tmp").iterdir()
        ),
        "private_store_or_credential_contents_read": False,
        "accounts_services_permissions_changed": False,
        "persistent_databases_opened": 0,
        "functional_tests_run": 0,
        "proofs": 0,
        "zkvm_executions": 0,
        "tool_sandbox_contrast": {
            "uid_gid": [1000, 1000],
            "supplementary_groups_remapped": "65534 repeated",
            "root_path_owner_mapped": "nobody:nogroup",
            "not_used_for_host_DAC_design": True,
        },
    }
    assert all(facts["uv_sync_flags_locally_documented"].values())
    assert facts["approved_public_file_sha256"]["docs/manuscript/PQ_DID__Implementation.pdf"] == (
        "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    )
    encoded = json.dumps(facts, indent=2) + "\n"
    assert len(encoded.encode()) < 65536
    (BASE / "environment-facts.json").write_text(encoded)
    print(
        json.dumps(
            {
                "uid": facts["uid"],
                "gid": facts["gid"],
                "python": platform.python_version(),
                "metadata_only": True,
                "host_changes": False,
            }
        )
    )


if __name__ == "__main__":
    main()
