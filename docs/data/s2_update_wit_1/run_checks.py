"""Local check runner adapted from the existing R0 cgroup guard; no backend calls."""

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
CONFIG = json.loads((D / "config.json").read_text())
FILES = [
    "src/pqdid/witness_updates.py",
    "tests/unit/witness_update_cases.py",
    "tests/unit/test_witness_updates.py",
]
REGRESSION = [
    "tests/unit/test_expiry.py::test_before_at_after_expiry",
    "tests/unit/test_expiry.py::test_timestamp_range_boundaries",
    "tests/unit/test_verifier_state.py::test_old_valid_witness_and_proof_result_rejected_after_state_superseded",
    "tests/unit/test_verifier_state.py::test_current_root_revoked_and_surviving_same_witness",
    "tests/unit/test_verifier_state.py::test_deterministic_state_and_expiry_interleavings",
    "tests/unit/test_verifier_state.py::test_simultaneous_submissions_accept_at_most_once",
    "tests/unit/test_verifier_state.py::test_atomic_complete_record_recheck_and_session",
    "tests/unit/test_verifier_state.py::test_default_and_explicit_absent_backend_fail_closed",
    "tests/unit/test_relations.py::test_nonuniform_path_substitution_reaches_path_check",
    "tests/unit/test_relations.py::test_equal_paths_in_uniform_subtrees_are_legitimate",
    "tests/unit/test_relations.py::test_revocation_reuses_surviving_credential_and_rejects_revoked_zero_leaf",
    "tests/unit/test_relations.py::test_public_apis_do_not_receive_witness_and_full_relation_has_no_skip_mode",
    "tests/unit/test_relation_encodings.py::test_independent_state_and_signed_body",
    "tests/unit/test_relation_encodings.py::test_repeated_metadata_parameters_mask_and_state_must_match",
]
COMMANDS = {
    "final-audit": [".venv/bin/python", str(D / "audit.py")],
    "audit-correction": [".venv/bin/python", str(D / "audit.py"), "--correct-audit-lint"],
    "focused": [
        ".venv/bin/python",
        "-m",
        "pytest",
        "-q",
        "-x",
        "-p",
        "no:cacheprovider",
        "tests/unit/test_witness_updates.py",
        "--junitxml=" + str(D / "focused.xml"),
    ],
    "regression": [
        ".venv/bin/python",
        "-m",
        "pytest",
        "-q",
        "-x",
        "-p",
        "no:cacheprovider",
        *REGRESSION,
        "--junitxml=" + str(D / "regression.xml"),
    ],
    "quality": [".venv/bin/ruff", "check", "--no-cache", *FILES, str(D / "run_checks.py")],
    "format": [
        ".venv/bin/ruff",
        "format",
        "--check",
        "--no-cache",
        *FILES,
        str(D / "run_checks.py"),
    ],
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
    write(name + ".service.json", info)
    return code


def main(name):
    if name not in COMMANDS:
        raise SystemExit("unknown check")
    lock = (D / "run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    ledger_path = D / "run-ledger.json"
    ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else []
    stopped = (D / "STOP.json").exists()
    if stopped and name == "audit-correction":
        # Explicit audit-script repair, never a test/backend retry.
        prior = ledger[-1]
        assert prior["name"] == "final-audit" and prior["exit_code"] == 1
        assert prior["stop"] is None and prior["seconds"] < 60
        events = dict(
            line.split() for line in prior["service"]["after"]["memory.events"].splitlines()
        )
        assert all(int(events[key]) == 0 for key in ["max", "oom", "oom_kill"])
        assert (D / "audit-correction-plan.json").is_file()
        stopped = False  # Original STOP and failed evidence remain intact.
    if stopped or any(run["name"] == name for run in ledger):
        raise SystemExit("stop or prior run name: no automatic retry")
    if sum(run.get("seconds", 60) for run in ledger) + 60 > 300:
        raise SystemExit("aggregate deadline admission failed")
    mem = available()
    disk = size(P / "experiments")
    if (
        mem < CONFIG["memory_bytes"] + CONFIG["headroom_reserve_bytes"]
        or disk >= CONFIG["disk_stop_bytes"]
    ):
        raise SystemExit("headroom/disk admission failed")
    if size(D) >= CONFIG["output_bytes"]:
        raise SystemExit("package output admission failed")
    unit = "pqdid-s2update-" + name
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
            if log.stat().st_size >= 60 * 1024 or size(D) >= CONFIG["output_bytes"]:
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
    if info["status"] != "pass" and not (D / "STOP.json").exists():
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
