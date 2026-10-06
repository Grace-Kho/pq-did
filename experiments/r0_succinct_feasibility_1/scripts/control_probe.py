"""Small aggregate-memory test: kernel must kill the whole 64 MiB group."""

import json
import os
import time
from pathlib import Path

cg = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().split("::")[1].lstrip(
    "/"
)
print(
    json.dumps(
        {
            k: (cg / k).read_text().strip()
            for k in ["memory.max", "memory.swap.max", "pids.max", "cpu.max"]
        }
    ),
    flush=True,
)
for _ in range(2):
    if os.fork() == 0:
        block = bytearray(40 * 1024**2)
        time.sleep(10)
        os._exit(0)
time.sleep(10)
raise SystemExit("ERROR: memory control did not terminate aggregate allocations")
