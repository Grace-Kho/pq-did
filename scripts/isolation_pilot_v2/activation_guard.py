"""Version 2 bounded activation; immutable history, no retry and checked teardown."""

import fcntl
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import (
    EVIDENCE,
    PROJECT,
    RELEASE,
    STATE,
    check,
    json_bytes,
    read_json,
    root_required,
    write_new,
)
from ledger import capacity, elapsed
from termination import CASE_IDS, gate, inhibited, query

OUT = EVIDENCE / "activation"
SOURCE = PROJECT / "scripts/isolation_pilot_v2"
MAINTENANCE = {"shutdown", "rollback"}


def size(path):
    return (
        sum(p.lstat().st_size for p in path.rglob("*") if p.is_file() or p.is_symlink())
        if path.exists()
        else 0
    )


def snapshot(cg):
    return {
        name: (cg / name).read_text().strip()
        for name in (
            "memory.max",
            "memory.peak",
            "memory.events",
            "memory.swap.max",
            "memory.swap.peak",
            "cpu.max",
            "pids.max",
        )
    }


def available():
    return next(
        int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemAvailable:")
    )


def worker(action, name):
    location = next(
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    unit = Path("/sys/fs/cgroup") / location.lstrip("/")
    cg = unit if action in {"provision", *MAINTENANCE} else unit.parent
    before = snapshot(cg)
    check(
        before["memory.max"] == "268435456" and before["memory.swap.max"] == "0",
        "aggregate-memory-controls",
    )
    check(
        before["cpu.max"] == "200000 100000" and len(os.sched_getaffinity(0)) <= 2, "cpu-controls"
    )
    check(available() >= 268435456 + 2147483648, "WSL-headroom")
    script = (SOURCE if action in {"provision", *MAINTENANCE} else RELEASE) / "pilotctl.py"
    command = ["/usr/bin/python3.14", "-I", "-B", str(script), action, *([name] if name else [])]
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PQISO_GUARDED_ACTION": action,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(OUT / "tmp"),
    }
    started = time.monotonic()
    failure = None
    try:
        code = subprocess.run(command, timeout=55, env=env, close_fds=True).returncode
    except subprocess.TimeoutExpired:
        code, failure = 124, "child-timeout"
    record = {
        "command": command,
        "before": before,
        "after": snapshot(cg),
        "seconds": time.monotonic() - started,
        "exit_code": code,
        "failure": failure,
        "cgroup": str(cg),
    }
    events = dict(line.split() for line in record["after"]["memory.events"].splitlines())
    passed = code == 0 and all(int(events[k]) == 0 for k in ("max", "oom", "oom_kill"))
    record["resource_guard_passed"] = passed
    write_new(OUT / ((name or action) + ".worker.json"), json_bytes(record))
    return 0 if passed else 125


def prior_runs():
    starts = sorted(OUT.glob("*.started.json")) if OUT.exists() else []
    check(len(starts) <= 32, "activation-record-count")
    rows = []
    for start in starts:
        record = read_json(start)
        check(
            set(record) == {"key", "reserved_seconds", "version"}
            and record["version"] == 2
            and record["reserved_seconds"] == 60
            and start.name == record["key"] + ".started.json",
            "activation-start-record",
        )
        path = OUT / (record["key"] + ".guard.json")
        if not path.exists():
            rows.append(
                {"key": record["key"], "passed": False, "wall_seconds": 60, "incomplete": True}
            )
            continue
        value = read_json(path)
        seconds = value.get("wall_seconds")
        check(
            type(seconds) in {int, float} and math.isfinite(seconds) and 0 <= seconds <= 60,
            "activation-record-time",
        )
        check(type(value.get("passed")) is bool, "activation-record-outcome")
        rows.append({"key": record["key"], **value})
    check(
        {p.stem.removesuffix(".guard") for p in OUT.glob("*.guard.json")}
        <= {r["key"] for r in rows},
        "unpaired-activation-record",
    )
    return rows


def admission(action, name):
    check(action in {"provision", "case", "verify", *MAINTENANCE}, "activation-action")
    check(
        (action == "case" and name in CASE_IDS) or (action != "case" and name is None),
        "activation-case",
    )
    rows = prior_runs()
    check(action in MAINTENANCE or not any(not r["passed"] for r in rows), "previous-failure-stop")
    key = name or action
    check(key not in {r["key"] for r in rows}, "no-automatic-retry")
    capacity()
    from provision import verify_authorisation

    verify_authorisation()
    from emergency_stop import recorded_seconds

    seconds = elapsed() + sum(r["wall_seconds"] for r in rows) + recorded_seconds()
    check(seconds + 60 + 10 <= 300, "aggregate-deadline-with-emergency-reserve")
    check(action in MAINTENANCE or not inhibited(), "launch-inhibited")
    if action == "provision":
        from termination import LOCK

        check(not LOCK.exists() and not LOCK.is_symlink(), "launch-lock-collision")
    if action == "case":
        completed = [r["case"] for r in rows if r.get("action") == "case"]
        check(
            set(CASE_IDS[: len(completed)]) == set(completed) and name == CASE_IDS[len(completed)],
            "case-order",
        )
        check(
            {"provision", "verify"} <= {r["key"] for r in rows if r["passed"]}, "case-prerequisites"
        )
    check(available() >= 268435456 + 2147483648, "WSL-headroom")
    check(size(PROJECT / "experiments") + size(RELEASE) + size(STATE) < 9663676416, "disk-stop")
    check(size(EVIDENCE) < 10485760, "output-stop")
    return key, seconds


def launch_command(action, name, key):
    props = [
        "MemoryMax=268435456",
        "MemorySwapMax=0",
        "CPUQuota=200%",
        "CPUAffinity=0 1",
        "TasksMax=128",
        "RuntimeMaxSec=60",
        "TimeoutStopSec=1",
        "KillMode=control-group",
        "OOMPolicy=kill",
        "PrivateNetwork=yes",
        "UMask=0077",
        "LimitCORE=0",
        "LimitFSIZE=1048576",
        "Restart=no",
    ]
    if action not in {"provision", *MAINTENANCE}:
        props += ["Slice=pqiso.slice"]
    args = ["/usr/bin/systemd-run", "--wait", "--pipe", "--unit=pqiso-guard-" + key.lower()]
    for prop in props:
        args += ["-p", prop]
    return args + [
        "/usr/bin/python3.14",
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--worker",
        action,
        *([name] if name else []),
    ]


def rss(cg):
    total = 0
    for listing in cg.rglob("cgroup.procs"):
        try:
            pids = listing.read_text().split()
        except FileNotFoundError:
            continue
        for pid in pids:
            try:
                total += next(
                    (
                        int(line.split()[1]) * 1024
                        for line in Path("/proc", pid, "status").read_text().splitlines()
                        if line.startswith("VmRSS:")
                    ),
                    0,
                )
            except FileNotFoundError, ProcessLookupError:
                pass
    return total


def main(action, name=None):
    root_required()
    # No privileged directory/lock mutation before complete local ledger admission.
    key, consumed = admission(action, name)
    if not OUT.exists():
        OUT.mkdir(mode=0o700)
        (OUT / "tmp").mkdir(mode=0o700)
    from layout import protected

    protected(OUT, directory=True, mode=0o700, ancestors=False)
    fd = os.open(OUT / "run.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "a"):
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Repeat admission under the exclusive run lock, before any workload.
        key, consumed = admission(action, name)
        write_new(
            OUT / (key + ".started.json"),
            json_bytes({"key": key, "version": 2, "reserved_seconds": 60}),
        )
        return monitored(action, name, key, consumed)


def monitored(action, name, key, consumed):
    from emergency_stop import stop_recorded

    started = time.monotonic()
    command = launch_command(action, name, key)
    unit_name = "pqiso-guard-" + key.lower() + ".service"
    record = {
        "action": action,
        "case": name,
        "passed": False,
        "exit_code": None,
        "command": command,
        "stop": None,
        "worker": {},
        "prior_accounted_seconds": consumed,
        "version": 2,
        "cgroup_memory_peak_bytes": 0,
        "sampled_tree_RSS_peak_bytes": 0,
        "temporary_peak_bytes": 0,
        "memory_metric": (
            "cgroup-v2 charged worker subtree or common slice, including descendants/cache/kernel; "
            "small external monitor excluded"
        ),
        "new_proofs": 0,
        "new_zkvm_executions": 0,
    }
    process = None
    stopped = False
    try:
        if action in MAINTENANCE:
            # Teardown first; no extra memory-limited worker overlaps a surviving workload.
            record["premaintenance_shutdown"] = stop_recorded(deadline=started + 5)
            check(record["premaintenance_shutdown"]["complete"], "premaintenance-shutdown-unknown")
        with (OUT / (key + ".log")).open("xb") as log:
            with gate(launching=action not in MAINTENANCE, deadline=started + 8):
                process = subprocess.Popen(
                    command, stdout=log, stderr=subprocess.STDOUT, close_fds=True
                )
                # Hold admission until the manager has observed the queued unit.
                while process.poll() is None:
                    row = query((unit_name,), min(started + 8, time.monotonic() + 2))[unit_name]
                    if row["LoadState"] == "loaded" and row["ActiveState"] in {
                        "active",
                        "activating",
                        "deactivating",
                        "failed",
                    }:
                        break
                    check(time.monotonic() < started + 8, "coordinator-admission-timeout")
                    time.sleep(0.01)
            cg = None
            while process.poll() is None:
                row = query((unit_name,), min(started + 55, time.monotonic() + 2))[unit_name]
                if row["ControlGroup"]:
                    cg = Path("/sys/fs/cgroup") / row["ControlGroup"].lstrip("/")
                    if action not in {"provision", *MAINTENANCE}:
                        cg = cg.parent
                if cg is not None and cg.exists():
                    snap = snapshot(cg)
                    record["cgroup_memory_peak_bytes"] = max(
                        record["cgroup_memory_peak_bytes"], int(snap["memory.peak"])
                    )
                    record["sampled_tree_RSS_peak_bytes"] = max(
                        record["sampled_tree_RSS_peak_bytes"], rss(cg)
                    )
                    events = dict(line.split() for line in snap["memory.events"].splitlines())
                    check(
                        not any(int(events[k]) for k in ("max", "oom", "oom_kill")),
                        "aggregate-memory-event",
                    )
                    check(
                        record["sampled_tree_RSS_peak_bytes"] <= 268435456, "sampled-tree-RSS-limit"
                    )
                record["temporary_peak_bytes"] = max(
                    record["temporary_peak_bytes"], size(OUT / "tmp")
                )
                check(record["temporary_peak_bytes"] <= 8388608, "temporary-limit")
                check(
                    log.tell() < 61440 and size(EVIDENCE) + size(STATE / "evidence") < 10485760,
                    "output-limit",
                )
                check(
                    size(PROJECT / "experiments") + size(RELEASE) + size(STATE) < 9663676416,
                    "disk-stop",
                )
                check(time.monotonic() - started < 55, "wall-stop-with-teardown-reserve")
                check(action in MAINTENANCE or not inhibited(), "externally-inhibited")
                time.sleep(0.05)
            record["exit_code"] = process.wait(timeout=max(0.001, started + 55 - time.monotonic()))
        detail = read_json(OUT / (key + ".worker.json"))
        record["worker"] = detail
        record["cgroup_memory_peak_bytes"] = max(
            record["cgroup_memory_peak_bytes"], int(detail["after"]["memory.peak"])
        )
        check(
            record["exit_code"] == 0 and detail["resource_guard_passed"] is True, "worker-failure"
        )
        if action == "case":
            check(
                read_json(STATE / "evidence" / (key + ".json"))["status"]
                == "comparisons-complete-outer-guard-pending",
                "case-incomplete",
            )
        record["passed"] = True
    except Exception as error:
        record["stop"] = (
            str(error) if type(error).__name__ == "PilotError" else type(error).__name__
        )
        record["shutdown"] = stop_recorded(deadline=min(started + 60, time.monotonic() + 5))
        stopped = True
    finally:
        if process is not None and process.poll() is None:
            if not stopped:
                record["shutdown"] = stop_recorded(deadline=min(started + 60, time.monotonic() + 5))
            # This is only the known systemd-run frontend; descendant termination
            # is established separately, never inferred from killing this process.
            process.kill()
            process.wait(timeout=1)
            record["passed"] = False
        record["wall_seconds"] = time.monotonic() - started
        record["passed"] &= record["wall_seconds"] <= 60
        write_new(OUT / (key + ".guard.json"), json_bytes(record))
    print(
        json.dumps(
            {
                k: record[k]
                for k in ("action", "case", "passed", "exit_code", "stop", "wall_seconds")
            }
        )
    )
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    try:
        if sys.argv[1] == "--worker":
            raise SystemExit(worker(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None))
        raise SystemExit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
    except Exception as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "failure_type": type(error).__name__,
                    "reason": str(error)
                    if type(error).__name__ == "PilotError"
                    else "guard-failure",
                }
            )
        )
        raise SystemExit(1) from None
