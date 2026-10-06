"""Reuse the retained guard with exact output registration and fatal completion."""

import json
import resource
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
H = R.parent / "header-correction-1"


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    return module


retained = load(H / "run.py")
g, policy, NEXT = retained.g, retained.policy, retained.NEXT
g.D = g.BASE = R
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
selected = sys.argv[-1]
g.CONFIG["memory_bytes"] = 1073741824 if selected == "cases" else 268435456
g.FILE_LIMIT = 1048576  # No new native artifacts or compilation are permitted.
if selected in {"quality", "prepare", "full-audit"}:
    g.CONFIG["cleanup_and_evidence_reserve_seconds"] = 0
g.FILES = [str(R)]  # Retained build, sources and dependencies are read-only.
g.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", name]
    for name in g.CONFIG["command_reservations_seconds"]
}
previous_slots = policy.output_slots
EXACT = frozenset(
    NEXT / "build" / name
    for name in (
        "CMakeFiles/exp2_native.dir/exp2_native.cpp.o",
        "CMakeFiles/exp2_semantics.dir/semantic_cases.cpp.o",
    )
)


def output_slots(root):
    slots = previous_slots(root)
    return slots | EXACT if Path(root) == NEXT else slots


policy.output_slots = output_slots


def package_size():
    # All old fallback evidence charges remain paid, including the two objects.
    total = 3622250 + g.size(R)
    for name, prefix in json.loads((R / "prefixes.json").read_text()).items():
        total += (P / name).stat().st_size - prefix["bytes"]
    return total


def artifact_limits():
    try:
        policy.enforce_live(R, retained.ROOT, 0)
        totals = policy.account(policy.walk_outputs(NEXT), R, NEXT, compiler_active=True)
        policy.need(19586323 + totals["artifacts"] <= 134217728, "aggregate artifact limit")
        policy.need(totals["scratch"] <= 8388608, "temporary limit")
        used = package_size()
        policy.need(used <= 6291456, "continuation evidence reservation")
        policy.need(12222999 + used <= 18874368, "cumulative evidence limit")
        policy.need(1606632 + used <= 8388608, "native evidence limit")
        if selected not in {"quality", "prepare", "full-audit"}:
            policy.need(used <= 6291456 - 524288, "completion evidence reserve")
    except (ValueError, OSError) as error:
        return str(error)
    return None


g.package_size = package_size
g.artifact_limits = artifact_limits
safety = load(R / "monitor_safety.py")
# Guard identity only; all cgroup/resource directives and accounting remain inherited.
old_ctl = g.ctl


def checked_ctl(*args):
    result = old_ctl(*args)
    if args and args[0] == "show" and result.returncode != 0:
        raise RuntimeError("systemd query failed: " + result.stderr[:1000])
    return result


g.ctl = checked_ctl
original_main = g.main


def authorised_static_continuation(name):
    if name not in {"tooling-corrected", "prepare-pre", "pre-audit", "cases"}:
        return False
    stop = json.loads((R / "STOP.json").read_text())
    if stop.get("name") != "tooling" or list(R.glob("STOP-*.json")):
        return False
    rows = json.loads((R / "run-ledger.json").read_text())
    if any(row["status"] != "pass" for row in rows if row["name"] != "tooling"):
        return False
    failed = json.loads((R / "tooling.json").read_text())
    if failed["stop"] is not None or not (R / "static-correction.json").exists():
        return False
    return name == "tooling-corrected" or (
        json.loads((R / "tooling-corrected.json").read_text())["status"] == "pass"
    )


g.approved_build_continuation = authorised_static_continuation


def completed_main(name):
    code = original_main(name)
    if name == "pre-audit" and code == 0:
        # The retained guard writes its full-audit final record only for that literal name.
        checks = load(R / "checks.py")
        checks.finish_pre_audit()
    return code


def main(name):
    return safety.protect(completed_main, g, name)


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (g.CONFIG["memory_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576,) * 2)
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        load(R / "work.py").run(sys.argv[2])
    else:
        raise SystemExit(main(sys.argv[1]))
