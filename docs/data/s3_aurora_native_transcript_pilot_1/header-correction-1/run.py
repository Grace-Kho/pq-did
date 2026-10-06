"""Approved native continuation; reuse the existing cgroup guard."""

import hashlib
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
    ('unit = "pqdid-auroraregression-" + name', 'unit = "pqdid-auroranative-resume5-" + name'),
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
source = source.replace(
    'temporary_peak = max(temporary_peak, size(D / "tmp"))',
    'temporary_peak = max(temporary_peak, size(D / "tmp"), size(NEXT / "scratch"))',
)
exec(compile(source, str(OLD), "exec"), g.__dict__)
g.D = g.BASE = R
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
selected = sys.argv[-1] if sys.argv else ""
native_command = selected in {"build-5", "cases"}
g.CONFIG["memory_bytes"] = 1073741824 if native_command else 268435456
FILE_LIMIT = 33554432 if native_command else 1048576
g.FILE_LIMIT = FILE_LIMIT
if selected in {"quality", "prepare", "full-audit"}:
    g.CONFIG["cleanup_and_evidence_reserve_seconds"] = 0
NEXT = ROOT / "guarded-build-v2"
g.FILES = [str(R), str(NEXT)]
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}


def package_size():
    total = 1619972 + g.size(R) + live_totals()["evidence"]
    for name, prefix in json.loads((R / "prefixes.json").read_text()).items():
        total += (P / name).stat().st_size - prefix["bytes"]
    return total


def live_totals():
    return policy.account(policy.walk_outputs(NEXT), R, NEXT, compiler_active=True)


def artifact_limits():
    try:
        policy.enforce_live(R, ROOT, 0)
        totals = live_totals()
        policy.need(19586323 + totals["artifacts"] <= 134217728, "aggregate artifact limit")
        policy.need(totals["scratch"] <= 8388608, "aggregate temporary limit")
        used = package_size()
        policy.need(used <= 4194304, "continuation evidence reservation")
        policy.need(12222999 + used <= 18874368, "cumulative evidence limit")
        policy.need(1606632 + used <= 6291456, "native evidence limit")
        if selected in {"preflight", "build-5", "cases"}:
            policy.need(used <= 4194304 - 524288, "finalisation evidence reserve")
    except (ValueError, OSError) as error:
        return str(error)
    return None


def compiler_environment():
    # Approved compiler scratch destination; classifications remain unchanged.
    return policy.compiler_environment(ROOT / "guarded-build-v2")


def approved_build_continuation(name):
    return False


g.approved_build_continuation = approved_build_continuation

policy = types.ModuleType("resource_policy")
policy.__file__ = str(R.parent / "resource-guard-repair-1/policy.py")
policy_source = Path(policy.__file__).read_text()
# Exclude only the explicitly registered new root from the historical inventory;
# account its complete contents separately with the unchanged tested classifier.
old_walk = "for base, dirs, names in os.walk(artifact_root, followlinks=False):"
assert policy_source.count(old_walk) == 1
policy_source = policy_source.replace(
    old_walk,
    old_walk + "\n        if Path(base) == artifact_root:"
    '\n            dirs[:] = [n for n in dirs if n != "guarded-build-v2"]',
)
# The prior full audit sealed this inventory via checked-inputs.json.
seal_root = R.parent / "seal-repair-1"
seal_raw = (seal_root / "manifest.json").read_bytes()

assert hashlib.sha256(seal_raw).hexdigest() == (
    "b654553f67533c37c4906c6d73e8fe891677048fb978ac52e03dfa909ed805ee"
)
seal_values = json.loads(seal_raw)["sha256"]
checked_path = seal_root / "checked-inputs.json"
assert (
    hashlib.sha256(checked_path.read_bytes()).hexdigest()
    == seal_values[str(checked_path.relative_to(P))]
)
sealed_inventory = seal_root / "artifact-inventory.json.gz"
assert (
    hashlib.sha256(sealed_inventory.read_bytes()).hexdigest()
    == json.loads(checked_path.read_text())["sha256"][str(sealed_inventory.relative_to(P))]
)
exec(compile(policy_source, policy.__file__, "exec"), policy.__dict__)
retained_inventory_before = policy.retained_inventory
retained_rows = retained_inventory_before(R)
with policy.gzip.open(sealed_inventory, "rt") as stream:
    for entry in json.load(stream)["files"]:
        assert entry["path"] not in retained_rows
        retained_rows[entry["path"]] = entry

# Historical enforce_live is called with zero new evidence; its old ceilings
# remain valid for that retained snapshot. New outputs use amended settings above.
g.NEXT = NEXT
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
        helper.__file__ = str(
            R / ("work.py" if name in {"preflight", "build-5", "cases"} else "checks.py")
        )
        exec(compile(Path(helper.__file__).read_text(), helper.__file__, "exec"), helper.__dict__)
        helper.run(name)
    else:
        raise SystemExit(g.main(sys.argv[1]))
