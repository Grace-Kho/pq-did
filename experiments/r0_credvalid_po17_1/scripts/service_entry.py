"""Check controls before spawning a target; retain exact cgroup peaks before exit."""

import json
import resource
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
name, limit = sys.argv[1], int(sys.argv[2])
command = sys.argv[3:]
assert command
relative = next(
    line[3:]
    for line in Path("/proc/self/cgroup").read_text().splitlines()
    if line.startswith("0::")
)
cgroup = Path("/sys/fs/cgroup") / relative.lstrip("/")


def snapshot():
    return {
        key: (cgroup / key).read_text().strip()
        for key in [
            "memory.max",
            "memory.swap.max",
            "memory.peak",
            "memory.current",
            "memory.events",
            "cpu.max",
            "pids.max",
        ]
    }


before = snapshot()
assert before["memory.max"] == str(limit) and before["memory.swap.max"] == "0"
assert before["cpu.max"] == "200000 100000" and before["pids.max"] == "128"
available = next(
    int(line.split()[1]) * 1024
    for line in Path("/proc/meminfo").read_text().splitlines()
    if line.startswith("MemAvailable:")
)
assert available >= limit + 2 * 1024**3
routes = Path("/proc/net/route").read_text().splitlines()
assert len(routes) == 1, "private network must have no external routes"
record = {
    "before": before,
    "available_before_target": available,
    "external_routes": 0,
    "target_started": False,
    "command": command,
}
path = root / "evidence" / f"{name}.service.json"
path.write_text(json.dumps(record, indent=2) + "\n")
if command == ["control-probe"]:
    code = 0
else:
    record["target_started"] = True
    path.write_text(json.dumps(record, indent=2) + "\n")
    code = subprocess.run(command, check=False).returncode
try:
    list((root / "tmp").iterdir())
    temporary_bytes = sum(p.stat().st_size for p in (root / "tmp").rglob("*") if p.is_file())
except PermissionError:
    temporary_bytes = None  # The independent verifier cannot access execution traces.
record.update(
    {
        "after": snapshot(),
        "exit_code": code,
        "largest_child_ru_maxrss_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        * 1024,
        "ru_maxrss_note": "largest child high-water RSS, not aggregate tree RSS",
        "temporary_bytes_at_exit": temporary_bytes,
    }
)
path.write_text(json.dumps(record, indent=2) + "\n")
sys.exit(code)
