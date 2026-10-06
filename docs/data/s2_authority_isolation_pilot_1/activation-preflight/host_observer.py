"""Read public host metadata, retaining absent prerequisites as observations.

No subprocess launch, signals, service mutation, root requirement or pilot action.
This small operator observation is outside the separately measured review worker.
"""

import importlib
import json
import os
import stat
import sys
import time
from pathlib import Path

P = Path("/home/grace/projects/pq-did")
D = Path(__file__).resolve().parent
sys.path.insert(0, str(P / "scripts/isolation_pilot"))
layout = importlib.import_module("layout")


def metadata(name):
    try:
        info = Path(name).lstat()
    except OSError as error:
        return {"error_type": type(error).__name__, "errno": error.errno}
    return {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": oct(stat.S_IMODE(info.st_mode)),
        "symlink": stat.S_ISLNK(info.st_mode),
    }


def main():
    start = time.monotonic()
    paths = [
        "/etc",
        "/opt",
        "/var/lib",
        "/run",
        "/etc/systemd/system",
        "/etc/sysusers.d",
        "/etc/tmpfiles.d",
        str(P),
        str(P / "src"),
        str(P / "docs"),
        str(P / ".venv"),
    ]
    result = {
        "kind": "read-only-host-metadata-not-an-actual-identity-case",
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": os.getgroups(),
        "uid_map": Path("/proc/self/uid_map").read_text(),
        "collisions": layout.collision_report(),
        "accounts": {name: None for name in layout.ACCOUNTS},
        "proposed_groups": {name: None for name in (*layout.ACCOUNTS, *layout.IPC_GROUPS)},
        "metadata": {name: metadata(name) for name in paths},
        "host_file_sha256": {name: layout.digest(name) for name in ("/etc/passwd", "/etc/group")},
        "required_executables": {
            name: os.access("/usr/bin/" + name, os.X_OK)
            for name in (
                "python3.14",
                "systemctl",
                "systemd-run",
                "systemd-sysusers",
                "systemd-tmpfiles",
                "systemd-analyze",
                "env",
            )
        },
        "cgroup_controllers": Path("/sys/fs/cgroup/cgroup.controllers").read_text().strip(),
        "system_slice_cgroup_kill_exists": Path("/sys/fs/cgroup/system.slice/cgroup.kill").exists(),
        "privileged_mutations": [],
        "activation_preflight_passed": False,
        "observation_wall_seconds": time.monotonic() - start,
    }
    with (D / "host-observations.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
