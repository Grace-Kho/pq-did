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
g.CONFIG["cleanup_and_evidence_reserve_seconds"] = 0  # Completion work only.
g.FILES = [str(R)]
g.COMMANDS = {
    n: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "run.py"), "work", n]
    for n in g.CONFIG["command_reservations_seconds"]
}
previous_size = retained.package_size


def package_size():
    # 784736 historic metadata is already included by the retained function.
    # The previous continuation additionally retained 147016 evidence bytes.
    return 147016 + previous_size()


retained.package_size = g.package_size = package_size
artifact_limits = retained.artifact_limits


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (268435456,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576,) * 2)
    if sys.argv[1] == "--worker":
        raise SystemExit(g.worker(sys.argv[2]))
    if sys.argv[1] == "work":
        helper = types.ModuleType("completion")
        helper.__file__ = str(R / "checks.py")
        exec(compile(Path(helper.__file__).read_text(), helper.__file__, "exec"), helper.__dict__)
        helper.run(sys.argv[2])
    else:
        raise SystemExit(g.main(sys.argv[1]))
