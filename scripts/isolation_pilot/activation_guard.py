"""Future explicitly approved root activation guard. No automatic retries or limit changes."""

import fcntl
import json
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

OUT = EVIDENCE / "activation"


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


def ctl(*args):
    return subprocess.run(["/usr/bin/systemctl", *args], capture_output=True, timeout=5)


def worker(action, name):
    location = next(
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    unit = Path("/sys/fs/cgroup") / location.lstrip("/")
    cg = unit.parent if action != "provision" else unit
    before = snapshot(cg)
    check(
        before["memory.max"] == "268435456" and before["memory.swap.max"] == "0",
        "aggregate-memory-controls",
    )
    check(
        before["cpu.max"] == "200000 100000" and len(os.sched_getaffinity(0)) <= 2, "cpu-controls"
    )
    check(available() >= 268435456 + 2147483648, "WSL-headroom")
    script = (
        Path(__file__).with_name("pilotctl.py")
        if action == "provision"
        else RELEASE / "pilotctl.py"
    )
    command = ["/usr/bin/python3.14", "-I", "-B", str(script), action, *([name] if name else [])]
    started = time.monotonic()
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PQISO_GUARDED_ACTION": action,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(OUT / "tmp"),
    }
    result = subprocess.run(command, timeout=55, env=env, close_fds=True)
    record = {
        "command": command,
        "before": before,
        "after": snapshot(cg),
        "seconds": time.monotonic() - started,
        "exit_code": result.returncode,
        "cgroup": str(cg),
    }
    events = dict(line.split() for line in record["after"]["memory.events"].splitlines())
    passed = result.returncode == 0 and all(int(events[k]) == 0 for k in ("max", "oom", "oom_kill"))
    record["resource_guard_passed"] = passed
    write_new(OUT / ((name or action) + ".worker.json"), json_bytes(record))
    return 0 if passed else 125


def main(action, name=None):
    root_required()
    check(action in {"provision", "case", "verify", "shutdown", "rollback"}, "activation-action")
    if action == "case":
        plan = read_json(PROJECT / "docs/proposals/s2_authority_isolation_plan_1/acceptance.json")
        check(name in {r["id"] for r in plan["cases"]}, "case-scope")
    else:
        check(name is None, "unexpected-argument")
    if not OUT.exists():
        OUT.mkdir(mode=0o700)
        (OUT / "tmp").mkdir(mode=0o700)
    check(OUT.lstat().st_uid == 0 and OUT.stat().st_mode & 0o777 == 0o700, "guard-evidence-owner")
    lock = (OUT / "run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    prior = [read_json(p) for p in OUT.glob("*.guard.json")]
    # Shutdown/quarantine stay available after a failed case; they cannot launch clients.
    check(
        action in {"shutdown", "rollback"} or not any(not r["passed"] for r in prior),
        "previous-failure-stop",
    )
    key = name or action
    check(not (OUT / (key + ".guard.json")).exists(), "no-automatic-retry")
    elapsed = sum(r.get("wall_seconds", 60) for r in prior)
    elapsed += sum(r.get("seconds", 60) for r in read_json(EVIDENCE / "run-ledger.json"))
    check(elapsed + 60 <= 300, "aggregate-deadline-admission")
    check(available() >= 268435456 + 2147483648, "WSL-headroom")
    check(size(PROJECT / "experiments") + size(RELEASE) + size(STATE) < 9663676416, "disk-stop")
    check(size(EVIDENCE) < 10485760, "output-stop")
    unit_name = "pqiso-guard-" + key.lower()
    command = [
        "/usr/bin/systemd-run",
        "--wait",
        "--pipe",
        "--unit=" + unit_name,
        "-p",
        "MemoryMax=268435456",
        "-p",
        "MemorySwapMax=0",
        "-p",
        "CPUQuota=200%",
        "-p",
        "CPUAffinity=0 1",
        "-p",
        "TasksMax=128",
        "-p",
        "RuntimeMaxSec=60",
        "-p",
        "TimeoutStopSec=1",
        "-p",
        "KillMode=control-group",
        "-p",
        "OOMPolicy=kill",
        "-p",
        "PrivateNetwork=yes",
        "-p",
        "UMask=0077",
        "-p",
        "LimitCORE=0",
        "-p",
        "LimitFSIZE=1048576",
        "-p",
        "Restart=no",
    ]
    if action != "provision":
        command += ["-p", "Slice=pqiso.slice"]
    command += [
        "/usr/bin/python3.14",
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--worker",
        action,
        *([name] if name else []),
    ]
    started = time.monotonic()
    memory_peak, rss_peak, tmp_peak, stop = 0, 0, 0, None
    with (OUT / (key + ".log")).open("xb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, close_fds=True)
        cg = None
        while process.poll() is None:
            if cg is None:
                location = (
                    ctl("show", unit_name, "-p", "ControlGroup", "--value").stdout.decode().strip()
                )
                if location:
                    cg = Path("/sys/fs/cgroup") / location.lstrip("/")
                    if action != "provision":
                        cg = cg.parent
            if cg is not None and cg.exists():
                memory_peak = max(memory_peak, int((cg / "memory.peak").read_text()))
                rss = 0
                for listing in cg.rglob("cgroup.procs"):
                    try:
                        pids = listing.read_text().split()
                    except FileNotFoundError:
                        continue
                    for pid in pids:
                        try:
                            rss += next(
                                (
                                    int(line.split()[1]) * 1024
                                    for line in Path("/proc", pid, "status")
                                    .read_text()
                                    .splitlines()
                                    if line.startswith("VmRSS:")
                                ),
                                0,
                            )
                        except FileNotFoundError, ProcessLookupError:
                            pass
                rss_peak = max(rss_peak, rss)
                if rss > 268435456:
                    stop = "sampled-tree-RSS-limit"
                events = dict(
                    line.split() for line in (cg / "memory.events").read_text().splitlines()
                )
                if any(int(events[k]) for k in ("max", "oom", "oom_kill")):
                    stop = "aggregate-memory-event"
            tmp_peak = max(tmp_peak, size(OUT / "tmp"))
            if tmp_peak > 8388608:
                stop = "temporary-limit"
            if log.tell() >= 61440 or size(EVIDENCE) + size(STATE / "evidence") >= 10485760:
                stop = "output-limit"
            if size(PROJECT / "experiments") + size(RELEASE) + size(STATE) >= 9663676416:
                stop = "disk-stop"
            if time.monotonic() - started >= 60:
                stop = "wall-limit"
            if stop:
                ctl("kill", "--signal=KILL", unit_name)
                if action != "provision":
                    ctl("kill", "--signal=KILL", "pqiso.slice")
            time.sleep(0.05)
        code = process.wait()
    worker_path = OUT / (key + ".worker.json")
    detail = read_json(worker_path) if worker_path.exists() else {}
    passed = code == 0 and stop is None and detail.get("resource_guard_passed") is True
    if action == "case":
        outcome = (
            read_json(STATE / "evidence" / (key + ".json"))
            if (STATE / "evidence" / (key + ".json")).exists()
            else {}
        )
        passed &= outcome.get("status") == "comparisons-complete-outer-guard-pending"
    result = {
        "action": action,
        "case": name,
        "passed": passed,
        "exit_code": code,
        "command": command,
        "wall_seconds": time.monotonic() - started,
        "stop": stop,
        "cgroup_memory_peak_bytes": max(
            memory_peak, int(detail.get("after", {}).get("memory.peak", 0))
        ),
        "sampled_tree_RSS_peak_bytes": rss_peak,
        "temporary_peak_bytes": tmp_peak,
        "memory_metric": (
            "cgroup-v2 memory.peak; complete common slice including coordinator, "
            "owners, clients, charged cache/kernel; small monitor outside"
        ),
        "worker": detail,
        "new_proofs": 0,
        "new_zkvm_executions": 0,
    }
    write_new(OUT / (key + ".guard.json"), json_bytes(result))
    print(
        json.dumps(
            {
                k: result[k]
                for k in ("action", "case", "passed", "exit_code", "stop", "wall_seconds")
            }
        )
    )
    return 0 if passed else 1


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
