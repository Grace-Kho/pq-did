"""Stop-only external monitor; independent of the installed runtime and normal guard.

Runs from the trusted reviewed source. Never launches a workload, removes a socket,
deletes configuration/data, admits a case or clears the persistent inhibition file.
"""

import json
import math
import os
import resource
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import check, object_pairs, protected, read_bytes, root_required  # noqa: E402
from termination import ALL_UNITS, STOP, gate, inhibit, terminate  # noqa: E402

HEADER = b"Pilot launch inhibited; retain until separately authorised review.\n"


def recorded_seconds():
    if not STOP.exists() and not STOP.is_symlink():
        return 0
    protected(STOP, gid=0, mode=0o600)
    data = read_bytes(STOP, 1048576)
    check(data.startswith(HEADER) and data.endswith(b"\n"), "stop-record-framing")
    lines = data[len(HEADER) :].splitlines()
    check(len(lines) <= 64, "stop-record-count")
    seconds = 0
    for line in lines:
        row = json.loads(line, object_pairs_hook=object_pairs)
        check(type(row) is dict and type(row.get("complete")) is bool, "stop-record-shape")
        value = row.get("seconds")
        check(
            type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 10,
            "stop-record-time",
        )
        seconds += value
    return seconds


def stop(deadline=None):
    root_required()
    deadline = time.monotonic() + 5 if deadline is None else deadline
    inhibit()  # Persist before attempting the launch gate or contacting systemd.
    with gate(deadline=deadline):
        return terminate(emergency=True, units=ALL_UNITS, deadline=deadline)


def stop_recorded(deadline=None):
    started = time.monotonic()
    result = {"complete": False, "kind": "stop-only-external-monitor", "workloads_launched": 0}
    try:
        result.update(stop(deadline))
    except Exception as error:
        result["failure_type"] = type(error).__name__
        result["failure"] = (
            str(error) if type(error).__name__ == "PilotError" else "shutdown-unknown"
        )
    result["seconds"] = time.monotonic() - started
    try:
        recorded_seconds()
        data = (json.dumps(result) + "\n").encode()
        check(len(data) < 61440 and STOP.stat().st_size + len(data) <= 1048576, "stop-record-size")
        fd = os.open(STOP, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception as error:
        result["complete"] = False
        result["report_failure"] = type(error).__name__
    return result


def main():
    root_required()
    # Additional bounds on the small external monitor, not a replacement for the
    # unchanged cgroup-v2 256 MiB/zero-swap workload ceiling. No project imports.
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    signal.alarm(10)
    result = stop_recorded(time.monotonic() + 5)
    data = (json.dumps(result) + "\n").encode()
    check(len(data) < 61440, "emergency-report-size")
    # Root operator captures this fixed-size public report in the runbook command.
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
