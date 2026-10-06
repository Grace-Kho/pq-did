"""Approved native continuation; reuse the existing cgroup guard."""

import json
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
    ('unit = "pqdid-auroraregression-" + name', 'unit = "pqdid-auroranative-admission4-" + name'),
    (
        'if (D / "STOP.json").exists():',
        'if (D / "STOP.json").exists() and name not in '
        '{"quality", "quality-2", "quality-3", "quality-4", "quality-5", "prepare", "full-audit"} '
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
native_command = False  # This continuation admits tooling/audit only.
g.CONFIG["memory_bytes"] = 1073741824 if native_command else 268435456
FILE_LIMIT = 33554432 if native_command else 1048576
g.FILE_LIMIT = FILE_LIMIT
if selected in {"quality", "prepare", "full-audit"}:
    g.CONFIG["cleanup_and_evidence_reserve_seconds"] = 0
g.FILES = [str(R)]  # Native artifacts are read-only in this correction package.
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
    try:
        policy.enforce_live(R, ROOT, 0)
        if 1502465 + package_size() > 2097152:
            return "native cumulative evidence limit"
    except (ValueError, OSError) as error:
        return str(error)
    return None


def compiler_environment():
    # Prospective compiler launch wiring only. COMMANDS contains no native build.
    return policy.compiler_environment(ROOT / "guarded-build-v1")


def approved_build_continuation(name):
    return False


g.approved_build_continuation = approved_build_continuation

policy = types.ModuleType("resource_policy")
policy.__file__ = str(R.parent / "resource-guard-repair-1/policy.py")
exec(compile(Path(policy.__file__).read_text(), policy.__file__, "exec"), policy.__dict__)
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
        helper.__file__ = str(R / "checks.py")
        exec(compile(Path(helper.__file__).read_text(), helper.__file__, "exec"), helper.__dict__)
        helper.run(name)
    else:
        raise SystemExit(g.main(sys.argv[1]))
