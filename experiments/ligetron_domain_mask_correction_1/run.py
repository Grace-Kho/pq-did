"""Milestone coordinator: serial cgroup jobs, prospective admission and shared ledger.

Adapted from the retained preservation/native guards. No cryptographic backend is
selected here. Case reservation is separate from job admission and happens before
each individual case, including failed cases and measured warm-up trials.
"""

import argparse
import fcntl
import json
import os
import resource
import signal
import subprocess
import time
from pathlib import Path

P = Path(__file__).resolve().parents[2]
D = P / "docs/data/ligetron_domain_mask_correction_1"
POLICY = json.loads((D / "policy.json").read_text())
N = P / "experiments/ligetron_domain_mask_correction_1"
ROOTS = (D, N)
SLICE = "pqdid-ligetron-domain-mask-1.slice"


def write(path, value):
    data = json.dumps(value, indent=2) + "\n"
    if len(data.encode()) > POLICY["ordinary_file_bytes"]:
        raise RuntimeError("ordinary JSON file cap")
    tmp = path.with_suffix(path.suffix + ".new")
    tmp.write_text(data)
    tmp.replace(path)


def read(path):
    if path.stat().st_size > POLICY["ordinary_file_bytes"]:
        raise RuntimeError("bounded JSON admission")
    return json.loads(path.read_text())


def change_ledger(operation):
    with (D / "ledger.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        value = read(D / "ledger.json")
        result = operation(value)
        write(D / "ledger.json", value)
        return result


def consumed(value):
    return (
        POLICY["historical_seconds"]
        + sum(x["seconds"] for x in value["bookkeeping"])
        + sum(x.get("seconds", x["limit_seconds"]) for x in value["jobs"])
    )


def reserve_case(case_id, work_reservation=100_000_000):
    def reserve(value):
        if len(value["invocations"]) >= POLICY["milestone_invocations"]:
            raise RuntimeError("milestone invocation allowance exhausted")
        if type(work_reservation) is not int or work_reservation < 0:
            raise ValueError("work reservation")
        if (
            value["work_events"] + value.get("work_events_reserved", 0) + work_reservation
            > POLICY["work_event_ceiling"]
        ):
            raise RuntimeError("aggregate work reservation")
        value["work_events_reserved"] = value.get("work_events_reserved", 0) + work_reservation
        ordinal = len(value["invocations"]) + 1
        row = {
            "invocation_id": f"LDMC1-{ordinal:04d}",
            "case_id": case_id,
            "work_event_reservation": work_reservation,
            "ordinal": ordinal,
            "cumulative_invocations": POLICY["historical_invocations"] + ordinal,
            "status": "admitted",
        }
        value["invocations"].append(row)
        return row

    return change_ledger(reserve)


def finish_case(receipt, outcome):
    def finish(value):
        row = value["invocations"][receipt["ordinal"] - 1]
        assert row["invocation_id"] == receipt["invocation_id"]
        row.update(status=outcome)

    change_ledger(finish)


def available():
    return next(
        int(x.split()[1]) * 1024
        for x in Path("/proc/meminfo").read_text().splitlines()
        if x.startswith("MemAvailable:")
    )


def size(root):
    return sum(p.lstat().st_size for p in root.rglob("*") if not p.is_dir()) if root.exists() else 0


def output_role(path):
    """Roles depend on approved destinations, with metadata always evidence."""
    rel = path.relative_to(P).as_posix()
    if path.is_symlink():
        raise RuntimeError("unexpected new symlink: " + rel)
    registered = read(D / "artifact-outputs.json")["paths"]
    if rel in registered:
        role = registered[rel]
        if role == "reference-pdf":
            return role, 4 * 1024 * 1024
        return role, POLICY["artifact_file_bytes"] if role in {
            "package-archive",
            "build-artifact",
        } else POLICY["ordinary_file_bytes"]
    if path.is_relative_to(N / "scratch"):
        if path.suffix in {".s", ".o"} and path.name.startswith("cc"):
            return "compiler-artifact", POLICY[
                "artifact_file_bytes"
            ] if path.suffix == ".o" else POLICY["ordinary_file_bytes"]

    return "evidence", POLICY["ordinary_file_bytes"]


def storage():
    evidence, artifacts, temporary = (
        (P / "PQ_DID_Ligetron_Domain_Mask_Followup.zip").stat().st_size,
        0,
        0,
    )
    for root in ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            try:
                count = path.lstat().st_size
            except FileNotFoundError:
                continue
            role, limit = output_role(path)
            if count > limit:
                raise RuntimeError(f"per-file {role} cap: {path.relative_to(P)}")
            if role == "evidence":
                evidence += count
            else:
                artifacts += count
            if path.is_relative_to(D / "tmp") or path.is_relative_to(N / "scratch"):
                temporary += count
    for name, prefix in read(D / "prefixes.json").items():
        evidence += max(0, (P / name).stat().st_size - prefix["bytes"])
    for report_name in ("docs/ligetron_domain_mask_correction.md",):
        report = P / report_name
        if report.exists():
            evidence += report.stat().st_size
    result = {
        "new_evidence_bytes": evidence,
        "new_artifact_bytes": artifacts,
        "evidence_bytes": POLICY["historical_evidence_bytes"] + evidence,
        "artifact_bytes": (
            POLICY["historical_artifact_bytes"]
            + artifacts
            + POLICY.get("retained_artifact_classification_charge_bytes", 0)
        ),
        "temporary_bytes": temporary,
    }
    if (
        evidence >= POLICY["new_evidence_cap_bytes"]
        or result["evidence_bytes"] >= POLICY["evidence_ceiling_bytes"]
    ):
        raise RuntimeError("cumulative evidence limit")
    if (
        artifacts >= POLICY["new_artifact_cap_bytes"]
        or result["artifact_bytes"] >= POLICY["artifact_cap_bytes"]
    ):
        raise RuntimeError("aggregate artifact limit")
    if temporary > POLICY["temporary_bytes"]:
        raise RuntimeError("ordinary temporary limit")
    return result


def ctl(*args):
    return subprocess.run(
        ["systemctl", "--user", *args], capture_output=True, text=True, timeout=5, check=True
    ).stdout


def snapshot(cg):
    return {
        key: (cg / key).read_text().strip()
        for key in (
            "memory.max",
            "memory.swap.max",
            "memory.peak",
            "memory.events",
            "cpu.max",
            "pids.max",
        )
    }


def worker(name):
    row = read(D / "jobs" / (name + ".input.json"))
    cg = Path("/sys/fs/cgroup") / next(
        x[3:].lstrip("/")
        for x in Path("/proc/self/cgroup").read_text().splitlines()
        if x.startswith("0::")
    )
    before = snapshot(cg)
    assert before["memory.max"] == str(POLICY["phase_memory"][row["phase"]])
    assert before["memory.swap.max"] == "0" and before["cpu.max"] == "200000 100000"
    assert len(os.sched_getaffinity(0)) <= 2
    if row["phase"] != "acquire":
        assert len(Path("/proc/net/route").read_text().splitlines()) == 1
    start = time.monotonic()
    process = subprocess.Popen(row["argv"], cwd=P, start_new_session=True)
    timeout = False
    while process.poll() is None:
        if time.monotonic() - start >= row["child_seconds"]:
            os.killpg(process.pid, signal.SIGKILL)
            timeout = True
            break
        time.sleep(0.02)
    code = process.wait()
    after = snapshot(cg)
    events = dict(x.split() for x in after["memory.events"].splitlines())
    breach = timeout or any(int(events.get(k, 0)) for k in ("max", "oom", "oom_kill"))
    write(
        D / "jobs" / (name + ".worker.json"),
        {
            "before": before,
            "after": after,
            "child_exit_code": code,
            "child_seconds": time.monotonic() - start,
            "resource_breach": breach,
            "metric": (
                "cgroup-v2 memory.peak including worker and descendants, charged cache/kernel"
            ),
        },
    )
    return 125 if breach else code


def job(name, phase, seconds, argv, *, build=False, completion=False):
    job_started = time.monotonic()
    assert POLICY["milestone_seconds"] <= POLICY["outside_KYC_after_amendment"]
    assert POLICY["shared_headroom_bytes"] - POLICY["new_evidence_cap_bytes"] >= 2097152
    if (
        phase not in POLICY["phase_memory"]
        or not 1 <= seconds <= 300
        or build != (phase == "build")
    ):
        raise RuntimeError("unauthorised phase/deadline")
    with (D / "execution.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (D / "jobs").mkdir(exist_ok=True)
        (D / "tmp").mkdir(exist_ok=True)
        (N / "scratch").mkdir(exist_ok=True)
        if (D / "jobs" / (name + ".input.json")).exists():
            raise RuntimeError("job name already used; preserve failure; choose explicit rerun ID")
        usage = storage()
        reserve = 0 if completion else POLICY["completion_reserve_seconds"]
        if (
            not completion
            and usage["new_evidence_bytes"] + POLICY["evidence_completion_reserve_bytes"]
            >= POLICY["new_evidence_cap_bytes"]
        ):
            raise RuntimeError("package completion evidence reserve")
        if (
            not completion
            and usage["evidence_bytes"] + POLICY["evidence_completion_reserve_bytes"]
            >= POLICY["evidence_ceiling_bytes"]
        ):
            raise RuntimeError("completion evidence reserve admission")
        mem = available()
        if mem < POLICY["phase_memory"][phase] + POLICY["headroom_bytes"]:
            raise RuntimeError("WSL memory headroom")
        if size(P / "experiments") >= POLICY["disk_stop_bytes"]:
            raise RuntimeError("experiment storage stop")
        # Only this explicitly named ephemeral user slice is affected.
        ctl(
            "set-property",
            "--runtime",
            SLICE,
            "MemoryMax=2147483648",
            "MemorySwapMax=0",
            "CPUQuota=200%",
            "TasksMax=128",
        )
        parent = ctl(
            "show", SLICE, "--property=MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax"
        )
        assert "MemoryMax=2147483648" in parent and "MemorySwapMax=0" in parent
        cpus = sorted(os.sched_getaffinity(0))[:2]
        unit = "pqdid-ligetron-domain-mask-1-" + name
        row = {
            "name": name,
            "phase": phase,
            "argv": argv,
            "limit_seconds": seconds,
            "child_seconds": min(295, seconds - 1),
            "status": "launched",
            "unit": unit,
            "memory_limit_bytes": POLICY["phase_memory"][phase],
            "opening_storage": usage,
            "available_memory": mem,
            "parent_limits": parent,
            "build": build,
        }

        def admit(value):
            if consumed(value) + seconds + reserve > POLICY["implementation_ceiling_seconds"]:
                raise RuntimeError("implementation time admission")
            if (
                consumed(value) - POLICY["historical_seconds"] + seconds + reserve
                > POLICY["milestone_seconds"]
            ):
                raise RuntimeError("milestone time admission")
            if value["work_events"] > POLICY["work_event_ceiling"]:
                raise RuntimeError("aggregate work-event ceiling")
            if build and len(value["builds"]) >= POLICY["milestone_builds"]:
                raise RuntimeError("milestone build allowance")
            if build:
                if POLICY["historical_builds"] + len(value["builds"]) >= POLICY["build_ceiling"]:
                    raise RuntimeError("build allowance exhausted")
                value["builds"].append(name)
            value["jobs"].append(row)

        change_ledger(admit)
        write(D / "jobs" / (name + ".input.json"), row)
        writable = " ".join(str(x) for x in ROOTS if x.exists())
        props = [
            f"MemoryMax={row['memory_limit_bytes']}",
            "MemorySwapMax=0",
            "CPUQuota=200%",
            "CPUAffinity=" + " ".join(map(str, cpus)),
            "TasksMax=128",
            f"RuntimeMaxSec={seconds}",
            "TimeoutStopSec=1",
            "KillMode=control-group",
            "OOMPolicy=kill",
            "NoNewPrivileges=yes",
            "PrivateDevices=yes",
            "PrivateNetwork=" + ("no" if phase == "acquire" else "yes"),
            "UMask=0077",
            "LimitCORE=0",
            "LimitFSIZE=" + str(33554432 if phase in {"acquire", "build"} else 1048576),
            "ReadOnlyPaths=" + str(P),
            "ReadWritePaths=" + writable,
        ]
        launch = [
            "systemd-run",
            "--user",
            "--wait",
            "--pipe",
            "--slice=" + SLICE,
            "--unit=" + unit,
            "--working-directory=" + str(P),
        ]
        for prop in props:
            launch += ["-p", prop]
        for setting in (
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            "OMP_NUM_THREADS=2",
            "RAYON_NUM_THREADS=2",
            "PATH=/usr/bin:/bin",
            "TMPDIR=" + str(N / "scratch" if build else D / "tmp"),
        ):
            launch += ["--setenv=" + setting]
        launch += [str(P / ".venv/bin/python"), "-I", "-B", str(Path(__file__)), "worker", name]
        started = time.monotonic()
        stop = None
        peak_rss = 0
        peak_artifact = usage["artifact_bytes"]
        log = D / "jobs" / (name + ".log")
        cg = None
        with log.open("x") as output:
            process = subprocess.Popen(
                launch,
                stdout=output,
                stderr=subprocess.STDOUT,
                preexec_fn=lambda: resource.setrlimit(
                    resource.RLIMIT_AS, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
                ),
            )
            while process.poll() is None:
                if cg is None:
                    try:
                        location = ctl("show", unit, "--property=ControlGroup", "--value").strip()
                        if location:
                            cg = Path("/sys/fs/cgroup") / location.lstrip("/")
                    except subprocess.CalledProcessError:
                        pass  # startup only; completion requires a worker record
                if cg and cg.exists():
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
                                        int(x.split()[1]) * 1024
                                        for x in Path("/proc", pid, "status")
                                        .read_text()
                                        .splitlines()
                                        if x.startswith("VmRSS:")
                                    ),
                                    0,
                                )
                            except FileNotFoundError, ProcessLookupError:
                                pass
                    peak_rss = max(peak_rss, rss)
                try:
                    current = storage()
                    peak_artifact = max(peak_artifact, current["artifact_bytes"])
                except RuntimeError as error:
                    stop = str(error)
                if log.stat().st_size >= POLICY["diagnostic_bytes"]:
                    stop = "diagnostic stop"
                if time.monotonic() - started >= seconds:
                    stop = "wall deadline"
                if stop:
                    ctl("kill", "--signal=KILL", "--kill-whom=all", unit)
                time.sleep(0.04)
            code = process.wait()
        record = D / "jobs" / (name + ".worker.json")
        measured = read(record) if record.exists() else {}
        row.update(
            seconds=time.monotonic() - job_started,
            exit_code=code,
            stop=stop,
            worker=measured,
            sampled_tree_rss_peak=peak_rss,
            artifact_observed_peak_bytes=peak_artifact,
            status="pass" if code == 0 and stop is None and measured else "failed",
        )
        write(D / "jobs" / (name + ".json"), row)

        def close(value):
            value["jobs"][-1] = row
            for item in value["invocations"]:
                if item["status"] == "admitted":
                    bound = item["work_event_reservation"]
                    value["work_events"] += bound
                    value["work_events_reserved"] -= bound
                    item.update(status="incomplete", work_events_charged_upper_bound=bound)

        change_ledger(close)
        print(json.dumps({k: row[k] for k in ("name", "status", "exit_code", "seconds", "stop")}))
        return 0 if row["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    w = sub.add_parser("worker")
    w.add_argument("name")
    j = sub.add_parser("job")
    j.add_argument("name")
    j.add_argument("phase", choices=POLICY["phase_memory"])
    j.add_argument("seconds", type=int)
    j.add_argument("--build", action="store_true")
    j.add_argument("--completion", action="store_true")
    j.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "worker":
        return worker(args.name)
    resource.setrlimit(resource.RLIMIT_AS, (268435456, resource.RLIM_INFINITY))
    command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    return job(
        args.name, args.phase, args.seconds, command, build=args.build, completion=args.completion
    )


if __name__ == "__main__":
    raise SystemExit(main())
