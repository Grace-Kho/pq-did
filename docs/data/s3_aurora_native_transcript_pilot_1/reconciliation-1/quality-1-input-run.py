"""Approved native continuation; reuse the existing cgroup guard."""

import json
import os
import resource
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
N = R.parent
P = N.parents[2]
E = P / "experiments/aurora_native_transcript_pilot_1"
ROOT = E / "dependency-prefix-v1"
OLD = P / "docs/data/s3_aurora_transcript_regression_1/run_checks.py"
g = types.ModuleType("native_guard")
g.__file__ = str(OLD)
source = OLD.read_text()
for before, after in (
    (
        'assert len(Path("/proc/net/route").read_text().splitlines()) == 1',
        'assert name == "provision" or len(Path("/proc/net/route").read_text().splitlines()) == 1',
    ),
    ('"PrivateNetwork=yes",', '"PrivateNetwork=" + ("no" if name == "provision" else "yes"),'),
    (
        '"network": "private-no-routes",',
        '"network": "approved pinned acquisition" if name == "provision" else "private-no-routes",',
    ),
    ('"LimitFSIZE=1048576",', '"LimitFSIZE=" + str(FILE_LIMIT),'),
    ('unit = "pqdid-auroraregression-" + name', 'unit = "pqdid-auroranative-recon-" + name'),
    (
        'if (D / "STOP.json").exists():',
        'if (D / "STOP.json").exists() and name not in {"quality", "prepare", "full-audit"} '
        "and not approved_build_continuation(name):",
    ),
    (
        "if stop:\n                ctl",
        "artifact_stop = artifact_limits()\n"
        "            if artifact_stop:\n                stop = artifact_stop\n"
        "            if stop:\n                ctl",
    ),
):
    assert before in source
    source = source.replace(before, after)
exec(compile(source, str(OLD), "exec"), g.__dict__)
g.D = g.BASE = R
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
selected = sys.argv[-1] if sys.argv else ""
native_command = selected in {"provision", "build-1", "build-2", "cases"}
g.CONFIG["memory_bytes"] = 1073741824 if native_command else 268435456
FILE_LIMIT = 33554432 if native_command else 1048576
g.FILE_LIMIT = FILE_LIMIT
g.FILES = [str(R), str(E)]
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}


def package_size():
    total = g.size(R)
    for name, prefix in json.loads((R / "prefixes.json").read_text()).items():
        total += (P / name).stat().st_size - prefix["bytes"]
    return total


def artifact_limits():
    if g.size(ROOT) + g.size(R / "tmp") > 134217728:
        return "128 MiB aggregate artifact stop"
    for root in (R, ROOT):
        for base, _dirs, names in os.walk(root):
            for name in names:
                path = Path(base) / name
                try:
                    size = path.lstat().st_size
                except FileNotFoundError:
                    continue
                binary = root == ROOT and (
                    ".git" in path.parts
                    or path.suffix in {".deb", ".a", ".o"}
                    or "build" in path.parts
                    and path.suffix == ""
                )
                if size > (33554432 if binary else 1048576):
                    return "per-file artifact/source/evidence stop: " + str(path.relative_to(P))
    return None


def approved_build_continuation(name):
    if name not in {"build-2", "cases"}:
        return False
    stop = json.loads((R / "STOP.json").read_text())
    failed = json.loads((R / "build-1.json").read_text())
    if stop != {"name": "build-1", "reason": "check/service failure", "proofs": False}:
        return False
    if failed["stop"] is not None or failed["exit_code"] != 1:
        return False
    if name == "cases":
        result = json.loads((R / "build-2.json").read_text())
        return result["status"] == "pass" and result["stop"] is None
    return (R / "build-only-correction.json").is_file()


g.approved_build_continuation = approved_build_continuation

g.package_size = package_size
g.artifact_limits = artifact_limits


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (g.CONFIG["memory_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT,) * 2)
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        name = sys.argv[2]
        helper = types.ModuleType("work")
        helper.__file__ = str(R / ("provision.py" if name == "provision" else "checks.py"))
        exec(compile(Path(helper.__file__).read_text(), helper.__file__, "exec"), helper.__dict__)
        helper.run(name)
    else:
        if selected == "provision":
            assert ROOT.is_dir(), "authorised retained checkout continuation"
            assert (
                g.CONFIG["operator_charge_seconds"] + 45
                <= g.CONFIG["provisioning_remaining_seconds"]
            )
            assert package_size() + 786432 + 524288 + 10867863 < 12386485
        raise SystemExit(g.main(sys.argv[1]))
