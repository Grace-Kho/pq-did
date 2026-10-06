"""Read five remaining pinned source dependencies; no reviewed code execution."""

import concurrent.futures
import importlib.util
import json
import os
import resource
import signal
import time
from pathlib import Path

D = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("source_reader", D / "source_read.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
FILES = [
    "libiop/protocols/encoded/lincheck/basic_lincheck.tcc",
    "libiop/protocols/encoded/sumcheck/sumcheck.tcc",
    "libiop/bcs/common_bcs_parameters.tcc",
    "libiop/bcs/hashing/blake2b.cpp",
    "libiop/protocols/ldt/fri/fri_aux.tcc",
]


def main():
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    signal.alarm(2)
    os.sched_setaffinity(0, set(sorted(os.sched_getaffinity(0))[:2]))
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(reader.fetch, FILES))
    result = {
        "kind": "Additional source text only; never compiled/imported/executed",
        "rows": rows,
        "wall_seconds": time.monotonic() - started,
        "peak_self_RSS_KiB": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "limits": "256MiB AS,2s CPU/alarm,two threads,100000B/read,1MiB/file",
        "accounting": "Included in five-second analysis bookkeeping charge",
    }
    (D / "sources-supplement.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
