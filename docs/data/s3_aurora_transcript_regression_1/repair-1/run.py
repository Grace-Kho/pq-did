"""Reuse the sealed guard, keeping repair evidence separate from the failed run."""

import json
import sys
import types
from pathlib import Path

R = Path(__file__).resolve().parent
B = R.parent
P = B.parents[2]
guard = types.ModuleType("sealed_guard")
guard.__file__ = str(B / "run_checks.py")
source = (B / "run_checks.py").read_text()
old = 'unit = "pqdid-auroraregression-" + name'
assert source.count(old) == 1
exec(
    compile(source.replace(old, 'unit = "pqdid-aurorarepair-" + name'), guard.__file__, "exec"),
    guard.__dict__,
)
guard.__file__ = str(Path(__file__).resolve())
guard.D = guard.BASE = R
guard.CONFIG = json.loads((R / "config.json").read_text())
guard.FILES = [str(p) for p in sorted(R.glob("*.py"))]
guard.COMMANDS = {
    name: [str(P / ".venv/bin/python"), "-I", "-B", str(R / "repair.py"), name]
    for name in ("checks", "prepare", "full-audit")
}
guard.package_size = lambda: guard.size(B) + guard.size(guard.E) + guard.REPORT.stat().st_size


def write(name, value):
    # Lossless references avoid retaining the same service snapshot three times.
    if name == "run-ledger.json":
        value = [
            {
                **{k: v for k, v in row.items() if k != "service"},
                "service_record": row["name"] + ".service.json",
            }
            for row in value
        ]
    elif name in ("checks.json", "prepare.json", "full-audit.json"):
        value = {
            **{k: v for k, v in value.items() if k not in ("service", "command")},
            "command_record": "run-ledger.json",
            "service_record": name[:-5] + ".service.json",
        }
    (R / name).write_text(json.dumps(value, separators=(",", ":")) + "\n")


guard.write = write
if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        raise SystemExit(guard.worker(sys.argv[2]))
    raise SystemExit(guard.main(sys.argv[1]))
