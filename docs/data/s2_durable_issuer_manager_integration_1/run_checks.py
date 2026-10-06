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
D = BASE
CONFIG = json.loads((BASE / "config.json").read_text())
FILES = [str(p) for p in sorted(D.glob("*.py"))] + [
    str(P / "src/pqdid/durable_issuance.py"),
    str(P / "tests/integration/test_durable_issuance.py"),
    str(P / "tests/integration/durable_issuance_cases.py"),
    str(P / "tests/integration/durable_issuance_worker.py"),
]


def pytest_command(name, *nodes):
    return [
        str(P / ".venv/bin/python"),
        "-m",
        "pytest",
        "-q",
        "-x",
        "-p",
        "no:cacheprovider",
        *nodes,
        "--junitxml=" + str(D / (name + ".xml")),
    ]


COMMANDS = {
    "imports": [str(P / ".venv/bin/ruff"), "check", "--select", "I", "--fix", "--no-cache", *FILES],
    "preflight": [str(P / ".venv/bin/python"), "-I", "-B", str(D / "preflight.py")],
    "focused": pytest_command(
        "focused", "tests/integration/test_durable_issuance.py", "-k", "not test_real_process_crash"
    ),
    "crashes": pytest_command(
        "crashes", "tests/integration/test_durable_issuance.py", "-k", "test_real_process_crash"
    ),
    "prepare": [str(P / ".venv/bin/python"), "-I", "-B", str(D / "prepare.py")],
    "final-source-format": [str(P / ".venv/bin/ruff"), "format", "--no-cache", *FILES],
    "source-format": [str(P / ".venv/bin/ruff"), "format", "--no-cache", *FILES],
    "quality": [str(P / ".venv/bin/ruff"), "check", "--no-cache", *FILES],
    "format": [str(P / ".venv/bin/ruff"), "format", "--check", "--no-cache", *FILES],
    "full-audit": [str(P / ".venv/bin/python"), "-I", "-B", str(D / "audit.py")],
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
    if (D / "STOP.json").exists():
        raise SystemExit("stopped: source review required; no automatic retry")
    if any(run["name"] == name for run in ledger):
        raise SystemExit("stop or prior run name: no automatic retry")
    prior = [
        {
            "seconds": CONFIG["prior_implementation_charged_seconds"]
            + CONFIG["operator_charge_seconds"]
        }
    ]
    if (
        sum(run.get("seconds", 60) for run in [*prior, *ledger])
        + 60
        + CONFIG["cleanup_and_evidence_reserve_seconds"]
        > 300
    ):
        raise SystemExit("aggregate deadline admission failed")
    planned_tests = CONFIG["test_invocations"]
    used_tests = CONFIG["prior_test_invocations"] + sum(
        planned_tests.get(row["name"], 0) for row in ledger
    )
    if used_tests + planned_tests.get(name, 0) > CONFIG["synthetic_case_limit"]:
        raise SystemExit("test invocation admission failed")
    mem = available()
    disk = size(P / "experiments")
    if (
        mem < CONFIG["memory_bytes"] + CONFIG["headroom_reserve_bytes"]
        or disk >= CONFIG["disk_stop_bytes"]
    ):
        raise SystemExit("headroom/disk admission failed")
    if CONFIG["prior_output_bytes"] + size(BASE) >= CONFIG["output_bytes"]:
        raise SystemExit("package output admission failed")
    unit = "pqdid-s2issuemanager-" + name
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
        "ReadWritePaths=" + " ".join([str(D), *FILES]),
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
        "PQDID_PILOT_RUN=" + name,
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        "PYTHONPATH=" + str(D),
        "OMP_NUM_THREADS=2",
        "RAYON_NUM_THREADS=2",
        "RISC0_DEV_MODE=0",
        "TMPDIR=" + str(D / "tmp"),
        "PATH=/usr/bin:/bin",
    ]:
        launch += ["--setenv=" + value]
    launch += [
        str(P / ".venv/bin/python"),
        str(Path(__file__).resolve()),
        "--worker",
        name,
    ]
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
    temporary_peak = 0
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
            temporary_peak = max(temporary_peak, size(D / "tmp"))
            if temporary_peak > CONFIG["temporary_bytes"]:
                stop = "aggregate temporary storage cap"
            if (
                log.stat().st_size >= 60 * 1024
                or CONFIG["prior_output_bytes"] + size(BASE) >= CONFIG["output_bytes"]
            ):
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
        temporary_storage_observed_peak=temporary_peak,
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
            ("STOP-" + name + ".json") if (D / "STOP.json").exists() else "STOP.json",
            {"name": name, "reason": stop or "check/service failure", "proofs": False},
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
