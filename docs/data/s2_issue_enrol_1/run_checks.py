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
D = (
    BASE / "release_checks"
    if "--release-checks" in sys.argv
    else (BASE / "final_checks" if "--final-checks" in sys.argv else BASE)
)
CONFIG = json.loads((BASE / "config.json").read_text())
FILES = [
    "src/pqdid/issuance.py",
    "src/pqdid/revocation_state.py",
    "tests/unit/issuance_cases.py",
    "tests/unit/test_issuance.py",
    "docs/data/s2_issue_enrol_1/run_checks.py",
    "docs/data/s2_issue_enrol_1/audit.py",
]
REGRESSION = [
    "tests/unit/test_revocation_state.py::test_exact_authorised_transition_and_independent_messages",
    "tests/unit/test_revocation_state.py::test_identifier_boundaries",
    "tests/unit/test_revocation_state.py::test_allocated_aborted_issuance_can_revoke_without_a_credential",
    "tests/unit/test_revocation_state.py::test_duplicate_revocation_replay_and_stale_reference_do_not_commit",
    "tests/unit/test_revocation_state.py::test_storage_limit_preserves_state_nonce_and_history",
    "tests/unit/test_revocation_state.py::test_actual_bounded_verification_exhaustion_no_fallback",
    "tests/unit/test_revocation_state.py::test_concurrent_preparations_commit_one_consistent_successor",
    "tests/unit/test_revocation_state.py::test_read_current_signature_and_overlap_linearisation",
    "tests/unit/test_revocation_state.py::test_busy_admission_has_no_wait_signing_or_state_mutation",
    "tests/unit/test_revocation_state.py::test_full_history_retrieval_in_holder_sized_batches_and_storage_stop",
    "tests/unit/test_revocation_state.py::test_composition_holder_update_full_relation_and_verifier",
    "tests/unit/test_relations.py::test_enrolment_and_stateless_public_checks",
    "tests/unit/test_relations.py::test_enrolment_approved_vector_is_checked_at_both_required_boundaries",
    "tests/unit/test_relations.py::test_enrolment_state_authenticity_is_a_separate_public_check",
    "tests/unit/test_witness_updates.py::test_multiple_updates_and_explicit_validated_chunk_resume",
    "tests/unit/test_verifier_state.py::test_default_and_explicit_absent_backend_fail_closed",
]
COMMANDS = {
    "focused": [
        ".venv/bin/python",
        "-m",
        "pytest",
        "-q",
        "-x",
        "-p",
        "no:cacheprovider",
        "tests/unit/test_issuance.py",
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
    "quality": [".venv/bin/ruff", "check", "--no-cache", *FILES],
    "format": [".venv/bin/ruff", "format", "--check", "--no-cache", *FILES],
    "full-audit": [".venv/bin/python", str(BASE / "audit.py")],
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
        failure = json.loads((BASE / "focused.json").read_text())
        events = dict(
            line.split() for line in failure["service"]["after"]["memory.events"].splitlines()
        )
        if (
            failure["exit_code"] != 1
            or failure["stop"] is not None
            or any(int(events[key]) for key in ["max", "oom", "oom_kill"])
            or any(run["name"] == "full-audit" for run in prior)
            or json.loads((BASE / "STOP.json").read_text())["name"] != "focused"
        ):
            raise SystemExit("fresh final namespace only for the documented fixture correction")
    if D.name == "release_checks":
        earlier = json.loads((BASE / "final_checks/run-ledger.json").read_text())
        failure = json.loads((BASE / "final_checks/quality.json").read_text())
        events = dict(
            line.split() for line in failure["service"]["after"]["memory.events"].splitlines()
        )
        if (
            name not in {"quality", "format", "full-audit"}
            or failure["exit_code"] != 1
            or failure["stop"] is not None
            or any(int(events[key]) for key in ["max", "oom", "oom_kill"])
            or any(run["name"] == "full-audit" for run in earlier)
            or json.loads((BASE / "final_checks/STOP.json").read_text())["name"] != "quality"
        ):
            raise SystemExit("release namespace only for the recorded non-resource lint fix")
        prior += earlier
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
    unit = "pqdid-s2issueenrol-" + (D.name + "-" if D != BASE else "") + name
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
        launch += ["--release-checks" if D.name == "release_checks" else "--final-checks"]
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
