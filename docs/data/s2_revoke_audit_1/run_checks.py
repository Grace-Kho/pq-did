"""Local check runner adapted from the existing R0 cgroup guard; no backend calls."""

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
P = BASE.parents[2]
D = BASE / "final_checks" if "--final-checks" in sys.argv else BASE
CONFIG = json.loads((BASE / "config.json").read_text())
FILES = [
    "scripts/preservation_audit.py",
    "tests/unit/test_preservation_audit.py",
    str(BASE / "diagnose.py"),
    str(BASE / "full_audit.py"),
    str(BASE / "run_checks.py"),
]
COMMANDS = {
    "diagnostic": [".venv/bin/python", str(BASE / "diagnose.py")],
    "focused": [
        ".venv/bin/python",
        "-m",
        "pytest",
        "-q",
        "-x",
        "-p",
        "no:cacheprovider",
        "tests/unit/test_preservation_audit.py",
        "--junitxml=" + str(D / "focused.xml"),
    ],
    "quality": [".venv/bin/ruff", "check", "--no-cache", *FILES],
    "format": [".venv/bin/ruff", "format", "--check", "--no-cache", *FILES],
    "full-audit": [".venv/bin/python", str(BASE / "full_audit.py")],
}


def write(name, value):
    (D / name).write_text(json.dumps(value, indent=2) + "\n")


def size(root):
    total = 0
    for base, _dirs, names in os.walk(root):
        for name in names:
            try:
                total += (Path(base) / name).lstat().st_size
            except FileNotFoundError:
                pass
    return total


def available():
    return next(
        int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemAvailable:")
    )


def ctl(*args):
    return subprocess.run(
        ["systemctl", "--user", *args], capture_output=True, text=True, timeout=10
    )


def worker(name):
    cg = Path("/sys/fs/cgroup") / next(
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    ).lstrip("/")

    def snapshot():
        return {
            key: (cg / key).read_text().strip()
            for key in [
                "memory.max",
                "memory.swap.max",
                "memory.peak",
                "memory.current",
                "memory.stat",
                "memory.swap.peak",
                "memory.events",
                "cpu.max",
                "pids.max",
            ]
        }

    before = snapshot()
    assert before["memory.max"] == str(CONFIG["memory_bytes"])
    assert before["memory.swap.max"] == "0" and before["cpu.max"] == "200000 100000"
    assert len(os.sched_getaffinity(0)) <= 2
    assert available() >= CONFIG["memory_bytes"] + CONFIG["headroom_reserve_bytes"]
    assert len(Path("/proc/net/route").read_text().splitlines()) == 1
    info = {
        "command": COMMANDS[name],
        "before": before,
        "available": available(),
        "allowed_cpus": sorted(os.sched_getaffinity(0)),
        "network": "private-no-routes",
    }
    write(name + ".service.json", info)
    started = time.monotonic()
    process = subprocess.Popen(COMMANDS[name], cwd=P, start_new_session=True)
    while process.poll() is None:
        if time.monotonic() - started >= 55:
            os.killpg(process.pid, signal.SIGKILL)
            break
        time.sleep(0.02)
    code = process.wait()
    info.update(after=snapshot(), seconds=time.monotonic() - started, exit_code=code)
    events = dict(line.split() for line in info["after"]["memory.events"].splitlines())
    if int(events.get("max", 0)) or int(events.get("oom", 0)):
        code = 125
    info["resource_guard_exit_code"] = code
    info["resource_guard_passed"] = code == 0
    write(name + ".service.json", info)
    return code


def main(name):
    if name not in COMMANDS:
        raise SystemExit("unknown check")
    lock = (BASE / "run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    ledger_path = D / "run-ledger.json"
    ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else []
    if (D / "STOP.json").exists() or any(run["name"] == name for run in ledger):
        raise SystemExit("stop or prior run name: no automatic retry")
    prior = json.loads((BASE / "run-ledger.json").read_text()) if D != BASE else []
    if D != BASE:
        failure = json.loads((BASE / "quality.json").read_text())
        events = dict(
            line.split() for line in failure["service"]["after"]["memory.events"].splitlines()
        )
        if (
            name not in {"quality", "format", "full-audit"}
            or failure["exit_code"] != 1
            or failure["stop"] is not None
            or any(int(events[key]) for key in ["max", "oom", "oom_kill"])
            or any(run["name"] == "full-audit" for run in prior)
            or json.loads((BASE / "STOP.json").read_text())["name"] != "quality"
        ):
            raise SystemExit("final namespace is only for the documented non-resource lint fix")
    if sum(run.get("seconds", 60) for run in [*prior, *ledger]) + 60 > 300:
        raise SystemExit("aggregate deadline admission failed")
    mem = available()
    disk = size(P / "experiments")
    if (
        mem < CONFIG["memory_bytes"] + CONFIG["headroom_reserve_bytes"]
        or disk >= CONFIG["disk_stop_bytes"]
    ):
        raise SystemExit("headroom/disk admission failed")
    if size(BASE) >= CONFIG["output_bytes"]:
        raise SystemExit("package output admission failed")
    unit = "pqdid-s2revokeaudit-" + ("final-" if D != BASE else "") + name
    cpus = sorted(os.sched_getaffinity(0))[:2]
    props = [
        "MemoryMax=" + str(CONFIG["memory_bytes"]),
        "MemorySwapMax=0",
        "CPUQuota=200%",
        "CPUAffinity=" + " ".join(map(str, cpus)),
        "TasksMax=128",
        "RuntimeMaxSec=60",
        "TimeoutStopSec=1",
        "KillMode=control-group",
        "OOMPolicy=kill",
        "NoNewPrivileges=yes",
        "PrivateDevices=yes",
        "PrivateNetwork=yes",
        "UMask=0077",
        "LimitCORE=0",
        "LimitFSIZE=1048576",
        "ReadOnlyPaths=" + str(P),
        "ReadWritePaths=" + str(D),
    ]
    launch = [
        "systemd-run",
        "--user",
        "--wait",
        "--pipe",
        "--unit=" + unit,
        "--working-directory=" + str(P),
    ]
    for prop in props:
        launch += ["-p", prop]
    for value in [
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        "OMP_NUM_THREADS=2",
        "RAYON_NUM_THREADS=2",
        "RISC0_DEV_MODE=0",
        "TMPDIR=" + str(D / "tmp"),
        "PATH=/usr/bin:/bin",
    ]:
        launch += ["--setenv=" + value]
    launch += [str(P / ".venv/bin/python"), str(Path(__file__).resolve()), "--worker", name]
    if D != BASE:
        launch += ["--final-checks"]
    info = {
        "name": name,
        "admitted_memory_available": mem,
        "disk_before": disk,
        "command": launch,
        "limit_seconds": 60,
        "status": "launched",
    }
    ledger.append(info)
    write("run-ledger.json", ledger)
    (D / "tmp").mkdir(exist_ok=True)
    started = time.monotonic()
    log = D / (name + ".log")
    peak_rss = 0
    stop = None
    with log.open("w") as output:
        process = subprocess.Popen(launch, stdout=output, stderr=subprocess.STDOUT)
        cg = None
        while process.poll() is None:
            if cg is None:
                location = ctl("show", unit, "--property=ControlGroup", "--value").stdout.strip()
                if location:
                    cg = Path("/sys/fs/cgroup") / location.lstrip("/")
            if cg is not None:
                rss = 0
                for procs in cg.rglob("cgroup.procs"):
                    try:
                        pids = procs.read_text().split()
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
                peak_rss = max(peak_rss, rss)
                if rss > CONFIG["memory_bytes"]:
                    stop = "sampled process-tree RSS limit"
            if log.stat().st_size >= 60 * 1024 or size(BASE) >= CONFIG["output_bytes"]:
                stop = "diagnostic/package output stop"
            if time.monotonic() - started >= 60:
                stop = "wall deadline"
            if stop:
                ctl("kill", "--signal=KILL", unit)
            time.sleep(0.02)
        code = process.wait()
    info.update(
        seconds=time.monotonic() - started,
        exit_code=code,
        sampled_tree_RSS_peak=peak_rss,
        stop=stop,
        status="pass" if code == 0 and stop is None else "failed",
    )
    service = D / (name + ".service.json")
    if service.exists():
        info["service"] = json.loads(service.read_text())
    info["systemd_result"] = ctl("show", unit, "--property=Result,MemoryPeak,MemorySwapPeak").stdout
    write(name + ".json", info)
    write("run-ledger.json", ledger)
    if name == "full-audit":
        # Small post-service bookkeeping only; never repeat/move content comparisons.
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(P))
        from scripts.preservation_audit import guarded_pass

        try:
            content = json.loads((D / "validation.json").read_text())
            phases = json.loads((D / "phases.json").read_text())["phases"]
        except OSError, ValueError, KeyError:
            content, phases = {}, []
        complete = bool(phases and phases[-1]["phase"] == "report-written-and-readback-complete")
        passed = complete and guarded_pass(
            content,
            info,
            memory_bytes=CONFIG["memory_bytes"],
            command_seconds=CONFIG["command_seconds"],
        )
        write(
            "result.json",
            {
                "package": CONFIG["package"],
                "passed": passed,
                "status": "complete" if passed else "incomplete",
                "full_audit_attempts": 1,
                "content_comparison_passed": content.get("passed", False),
                "report_generation_completed": complete,
                "resource_guard_passed": passed,
                "guard_record": "full-audit.json",
                "content_record": "validation.json",
                "phase_record": "phases.json",
                "guard_exit_code": code,
                "wall_seconds": info["seconds"],
                "memory_metric": (
                    "cgroup-v2 memory.peak; entire worker cgroup and descendants, including "
                    "charged anonymous/file-cache/kernel memory; monitor outside cgroup"
                ),
                "cgroup_memory_peak_bytes": info.get("service", {})
                .get("after", {})
                .get("memory.peak"),
                "sampled_tree_RSS_peak_bytes": peak_rss,
                "package_bytes_at_guard_completion": size(BASE),
                "temporary_storage_bytes_at_guard_completion": size(D / "tmp"),
                "post_guard_work": "Result recording only; no repeated content scan",
                "new_proofs": 0,
                "new_zkvm_executions": 0,
                "proof_attempts_used": 2,
                "proof_attempts_unused": 1,
                "CPU_proving_paused": True,
            },
        )
        if not passed:
            info["status"] = "failed"
    if info["status"] != "pass":
        write(
            "STOP.json", {"name": name, "reason": stop or "check/service failure", "proofs": False}
        )
    ctl("reset-failed", unit)
    print(
        json.dumps(
            {
                key: info[key]
                for key in [
                    "name",
                    "status",
                    "seconds",
                    "exit_code",
                    "stop",
                    "sampled_tree_RSS_peak",
                ]
            },
            indent=2,
        )
    )
    return 0 if info["status"] == "pass" else 1


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        raise SystemExit(worker(sys.argv[2]))
    raise SystemExit(main(sys.argv[1]))
