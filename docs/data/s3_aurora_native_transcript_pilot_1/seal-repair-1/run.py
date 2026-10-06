"""Completion entry point using the retained launcher without changing its source."""

import json
import resource
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
P = R.parents[3]
OLD = R.parent / "build-4-resumption-1/run.py"
retained = types.ModuleType("retained_launcher")
retained.__file__ = str(OLD)
exec(compile(OLD.read_text(), str(OLD), "exec"), retained.__dict__)
retained.R = R
g = retained.g
g.D = g.BASE = R
g.__file__ = str(R / "run.py")
g.CONFIG = json.loads((R / "config.json").read_text())
selected = sys.argv[-1]
native_phase = selected in {"build-4", "cases"}
g.CONFIG["memory_bytes"] = 1073741824 if native_phase else 268435456
if selected in {"quality", "prepare", "full-audit"}:
    g.CONFIG["cleanup_and_evidence_reserve_seconds"] = 0
g.FILES = [str(R), str(retained.NEXT)]
g.COMMANDS = {
    n: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", n]
    for n in g.CONFIG["command_reservations_seconds"]
}
previous_size = retained.package_size


def package_size():
    # 784736 historic metadata is already included by the retained function.
    # Earlier continuations additionally retained 242260 evidence bytes.
    return 242260 + previous_size()


retained.package_size = g.package_size = package_size
artifact_limits = retained.artifact_limits
compiler_environment = retained.compiler_environment


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (g.CONFIG["memory_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, ((33554432 if native_phase else 1048576),) * 2)
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        helper = types.ModuleType("completion")
        helper.__file__ = str(
            R / ("work.py" if sys.argv[2] in {"preflight", "build-4", "cases"} else "checks.py")
        )
        exec(compile(Path(helper.__file__).read_text(), helper.__file__, "exec"), helper.__dict__)
        helper.run(sys.argv[2])
    else:
        raise SystemExit(g.main(sys.argv[1]))
