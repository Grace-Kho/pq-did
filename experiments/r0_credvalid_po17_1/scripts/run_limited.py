"""One guarded transient service, persistent phase budgets and proof-attempt ledger.

Run outside the editor sandbox so the existing systemd user manager is reachable.
No global service/default is changed. MemoryMax charges the whole descendant cgroup.
"""

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / "r0_succinct_feasibility_1"
CYCLE = ROOT.parent / "r0_credvalid_cycle_1"
EXEC24 = ROOT.parent / "r0_credvalid_exec24_1"
PRIOR = ROOT.parent / "r0_succinct_proof_1"
ENROL = ROOT.parent / "r0_enrol_po17_1"
GIB = 1024**3


def used_disk():
    total = 0
    for base, _dirs, files in os.walk(ROOT.parent):
        for name in files:
            try:
                total += (Path(base) / name).lstat().st_size
            except FileNotFoundError:
                pass
    return total


def output_disk(diagnostics=False):
    total = 0
    for base, dirs, files in os.walk(ROOT):
        if Path(base) == ROOT:
            dirs[:] = [
                d
                for d in dirs
                if d not in ("tooling", "target", "tmp") + (("receipts",) if diagnostics else ())
            ]
        for name in files:
            try:
                total += (Path(base) / name).stat().st_size
            except FileNotFoundError:
                pass  # Atomic progress-file replacement can occur during sampling.
    return total


def available():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("no MemAvailable")


def systemctl(*args):
    return subprocess.run(
        ["systemctl", "--user", *args], text=True, capture_output=True, timeout=10
    )


def read(p):
    try:
        return p.read_text().strip()
    except FileNotFoundError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "phase", choices=["setup", "build", "execute", "prove", "verify", "adversarial", "check"]
    )
    ap.add_argument("name")
    ap.add_argument("--slot", type=int)
    ap.add_argument("--seconds", type=int, required=True)
    ap.add_argument("--memory", type=int, default=2 * GIB)
    ap.set_defaults(network=False)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    if a.phase in ("setup", "build", "execute", "prove") and (ROOT / "evidence/STOP.json").exists():
        raise SystemExit(
            "package resource stop recorded; no further build/execution/proving "
            "authorised by this package"
        )
    cmd = a.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("missing command")
    if "/" in cmd[0] and not Path(cmd[0]).is_absolute():
        cmd[0] = str(ROOT / cmd[0])
    if not 1 <= a.seconds <= 1200 or not 1 <= a.memory <= 2 * GIB:
        ap.error("unsafe limit")
    lock = open(ROOT / "evidence/run.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    ledgerpath = ROOT / "evidence/run_ledger.json"
    ledger = (
        json.loads(ledgerpath.read_text())
        if ledgerpath.exists()
        else {"proof_attempts": 0, "execution_runs": 0, "runs": []}
    )
    sums = {
        k: sum(
            r.get("wall_seconds", r["limit_seconds"])
            for r in ledger["runs"]
            if r["phase"] in phases
        )
        for k, phases in {
            "setup_build": ["setup", "build"],
            "execute_prove": ["execute", "prove"],
            "execute": ["execute"],
            "check": ["check", "verify", "adversarial"],
        }.items()
    }
    allowed = {
        "setup": 1200 - sums["setup_build"],
        "build": 1200 - sums["setup_build"],
        "prove": min(1800 - sums["execute_prove"], 600),
        "execute": min(1800 - sums["execute_prove"], 300 - sums["execute"], 60),
        "verify": min(300 - sums["check"], 10),
        "adversarial": min(300 - sums["check"], 60),
        "check": min(300 - sums["check"], 60),
    }[a.phase]
    if a.seconds > allowed:
        raise SystemExit(f"phase budget remaining {allowed}; requested {a.seconds}")
    if a.phase == "check" and a.memory > 256 * 1024**2:
        raise SystemExit("check memory allowance exceeded")
    if a.phase in ("verify", "adversarial") and a.memory > GIB:
        raise SystemExit("verifier memory allowance exceeded")
    if a.phase == "execute":
        if ledger["execution_runs"] != 0 or a.slot != 1 or a.name != "execution":
            raise SystemExit("one execution-only check authorised")
        if cmd != [str(ROOT / "target/release/pqdid-r0-host"), "execute"]:
            raise SystemExit("fixed execution command required")
    if a.phase == "prove":
        if a.slot != 3 or ledger["proof_attempts"] != 0 or a.name != "attempt3":
            raise SystemExit("only cumulative proof attempt 3 authorised")
        execution = json.loads((ROOT / "evidence/execution.result.json").read_text())
        admission = json.loads((ROOT / "evidence/admission.result.json").read_text())
        resources = json.loads((ROOT / "evidence/execution.json").read_text())
        if not (
            resources["status"] == "pass"
            and execution["accepted"]
            and execution["journal_matches_expected"]
            and admission["conservative_estimate_seconds"] <= 600
            and admission["memory_admitted"]
            and admission["proof_admitted"]
        ):
            raise SystemExit("execution/segmentation/support admission gate failed")
        if cmd != [
            str(ROOT / "target/release/pqdid-r0-host"),
            "prove",
            "cred-alpha-42",
            "receipts/attempt3.bin",
        ]:
            raise SystemExit("fixed CredValid-only proof command required")
    if a.phase in ("execute", "prove"):
        manifest = json.loads((ROOT / "evidence/manifest-before-launch.json").read_text())
        for relative, expected_hash in manifest["frozen_sha256"].items():
            with (ROOT / relative).open("rb") as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != expected_hash:
                    raise SystemExit("frozen input/config/host changed: " + relative)
        if manifest["config"] != json.loads((ROOT / "config.json").read_text()):
            raise SystemExit("manifest/config mismatch")
    if available() < a.memory + 2 * GIB:
        raise SystemExit("insufficient MemAvailable for worker plus 2 GiB reserve")
    if used_disk() >= 9 * GIB:
        raise SystemExit("conservative disk stop threshold reached")
    if output_disk(True) >= 60 * 1024**2 or output_disk() >= 240 * 1024**2:
        raise SystemExit("conservative output stop threshold reached")
    if (ROOT / "evidence" / f"{a.name}.json").exists():
        raise SystemExit("run name already used; no overwrite/retry")
    unit = "pqdid-r0credpo17-" + a.name
    log = ROOT / "evidence" / f"{a.name}.log"
    output = open(log, "w")
    props = [
        "MemoryMax=" + str(a.memory),
        "ReadOnlyPaths=" + " ".join(map(str, [BASE, CYCLE, EXEC24, PRIOR, ENROL])),
        "MemorySwapMax=0",
        "CPUQuota=200%",
        "TasksMax=128",
        "RuntimeMaxSec=" + str(a.seconds),
        "TimeoutStopSec=2",
        "KillMode=control-group",
        "OOMPolicy=kill",
        "NoNewPrivileges=yes",
        "PrivateDevices=yes",
        "UMask=0077",
        "LimitCORE=0",
        "LimitFSIZE=" + str(2 * GIB),
    ]
    if a.phase in ("verify", "adversarial"):
        props += [
            "InaccessiblePaths="
            + " ".join(
                map(
                    str,
                    [
                        ROOT / "fixtures/private",
                        ROOT / "tmp",
                        PRIOR,
                        ENROL,
                        ROOT.parents[1] / "tests/fixtures",
                        BASE,
                        CYCLE,
                        EXEC24,
                    ],
                )
            )
        ]
    if not a.network:
        props += ["PrivateNetwork=yes"]
    env = {
        "CARGO_HOME": str(ROOT / "tooling/cargo"),
        "RUSTUP_HOME": str(ROOT / "tooling/rustup"),
        "RUSTC": str(BASE / "tooling/guest-r0.1.97.0/bin/rustc"),
        "RZUP_HOME": str(ROOT / "tooling/rzup"),
        "RISC0_HOME": str(ROOT / "tooling/risc0"),
        "XDG_CACHE_HOME": str(ROOT / "tooling/cache"),
        "CARGO_TARGET_DIR": str(ROOT / "target"),
        "TMPDIR": str(ROOT / "tmp"),
        "CARGO_BUILD_JOBS": "1",
        "CMAKE_BUILD_PARALLEL_LEVEL": "1",
        "MAKEFLAGS": "-j1",
        "RAYON_NUM_THREADS": "2",
        "OMP_NUM_THREADS": "2",
        "RISC0_DEV_MODE": "0",
        "RISC0_PROVER": "local",
        "RISC0_EXECUTOR": "local",
        "R0_PROOF_SLOT": str(a.slot or 0),
        "R0_EXECUTION_SLOT": str(a.slot or 0),
        "CUDA_VISIBLE_DEVICES": "",
        "RUST_LOG": (
            "warn,risc0_zkvm::host::server::prove::prover_impl=debug,"
            "risc0_zkvm::host::recursion=debug"
        ),
        "PATH": str(BASE / "tooling/guest-r0.1.97.0/bin") + ":/usr/local/bin:/usr/bin:/bin",
    }
    launch = [
        "systemd-run",
        "--user",
        "--wait",
        "--pipe",
        "--unit=" + unit,
        "--working-directory=" + str(ROOT),
    ]
    for v in props:
        launch += ["-p", v]
    for k, v in env.items():
        launch += ["--setenv=" + k + "=" + v]
    # Explicitly clear remote-prover credentials inherited by the user manager.
    launch += [
        "-p",
        "UnsetEnvironment=BONSAI_API_KEY BONSAI_API_URL RISC0_CUDA "
        "RISC0_DEV_MODE_FORCE RISC0_PPROF_OUT",
    ]
    launch += [
        "/usr/bin/python3",
        str(ROOT / "scripts/service_entry.py"),
        a.name,
        str(a.memory),
        *cmd,
    ]
    entry = {
        "phase": a.phase,
        "slot": a.slot,
        "mem_available_at_admission": available(),
        "name": a.name,
        "command": cmd,
        "limit_seconds": a.seconds,
        "memory_max": a.memory,
        "network": a.network,
        "start_time_UTC": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "launched",
    }
    if a.phase == "execute":
        ledger["execution_runs"] += 1
    if a.phase == "prove":
        ledger["proof_attempts"] += 1
        cumulative_path = ROOT / "evidence/cumulative_attempt_ledger.json"
        cumulative = json.loads(cumulative_path.read_text())
        if cumulative["attempts_used"] != 2 or cumulative["remaining"] != 1:
            raise SystemExit("cumulative proof budget mismatch")
        cumulative.update(attempts_used=3, remaining=0)
        cumulative["attempts"].append(
            {"number": 3, "package": "R0-CREDVALID-PO17-1", "outcome": "launched"}
        )
        cumulative_path.write_text(json.dumps(cumulative, indent=2) + "\n")
    ledger["runs"].append(entry)
    ledgerpath.write_text(json.dumps(ledger, indent=2) + "\n")
    start = time.monotonic()
    entry["systemd_command"] = launch
    ledgerpath.write_text(json.dumps(ledger, indent=2) + "\n")
    proc = subprocess.Popen(launch, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    from capture import capture

    capture_thread = threading.Thread(
        target=capture,
        args=(proc.stdout, output, ROOT / "evidence" / f"{a.name}.sdk-progress.json"),
    )
    capture_thread.start()
    peak_rss = peak_charge = peak_disk = 0
    peak_swap = 0
    peak_tmp = 0
    peak_kernel = 0
    last_memory_events = {}
    next_disk_check = 0.0
    cg = None
    effective = {}
    stop = None
    try:
        while proc.poll() is None:
            if cg is None:
                q = systemctl("show", unit, "--property=ControlGroup", "--value").stdout.strip()
                if q:
                    cg = Path("/sys/fs/cgroup") / q.lstrip("/")
                    effective = {
                        k: read(cg / k)
                        for k in ["memory.max", "memory.swap.max", "cpu.max", "pids.max"]
                    }
                    if (
                        effective["memory.max"] != str(a.memory)
                        or effective["memory.swap.max"] != "0"
                    ):
                        stop = "effective memory/swap controls not confirmed"
            if cg is not None:
                peak_kernel = max(peak_kernel, int(read(cg / "memory.peak") or 0))
                raw_events = read(cg / "memory.events")
                if raw_events:
                    last_memory_events = {
                        k: int(v) for k, v in (line.split() for line in raw_events.splitlines())
                    }
                    if last_memory_events.get("max", 0) or last_memory_events.get("oom", 0):
                        stop = "cgroup memory limit reached"
                charge = int(read(cg / "memory.current") or 0)
                peak_charge = max(peak_charge, charge)
                peak_swap = max(peak_swap, int(read(cg / "memory.swap.current") or 0))
                rss = 0
                for pf in cg.rglob("cgroup.procs"):
                    for pid in (read(pf) or "").split():
                        try:
                            for line in Path("/proc", pid, "status").read_text().splitlines():
                                if line.startswith("VmRSS:"):
                                    rss += int(line.split()[1]) * 1024
                        except ProcessLookupError, FileNotFoundError:
                            pass
                peak_rss = max(peak_rss, rss)
                if rss > a.memory:
                    stop = "summed RSS exceeded ceiling"
                if peak_swap:
                    stop = "worker used swap"
            peak_tmp = max(
                peak_tmp, sum(p.stat().st_size for p in (ROOT / "tmp").rglob("*") if p.is_file())
            )
            if time.monotonic() >= next_disk_check:
                disk = used_disk()
                peak_disk = max(peak_disk, disk)
                if disk >= 9 * GIB:
                    stop = "conservative disk stop threshold"
                if output_disk(True) >= 60 * 1024**2 or output_disk() >= 240 * 1024**2:
                    stop = "conservative output stop threshold"
                next_disk_check = time.monotonic() + 0.5
            if time.monotonic() - start > a.seconds + 5:
                stop = "external wall watchdog"
            if stop:
                systemctl("stop", unit)
            time.sleep(0.02)
        rc = proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            systemctl("stop", unit)
            proc.wait(timeout=10)
        capture_thread.join(timeout=5)
        output.close()
    elapsed = time.monotonic() - start
    state = systemctl(
        "show",
        unit,
        "--property=Result,ExecMainCode,ExecMainStatus,MemoryPeak,MemorySwapPeak,CPUUsageNSec,ControlGroup",
    ).stdout
    entry.update(
        {
            "wall_seconds": elapsed,
            "exit_code": rc,
            "status": "pass" if rc == 0 and stop is None else "failed",
            "stop_reason": stop,
            "effective_cgroup": effective,
            "sampled_process_tree_RSS_peak": peak_rss,
            "sampled_cgroup_charge_peak": peak_charge,
            "sampled_swap_peak": peak_swap,
            "sampled_cgroup_kernel_peak": peak_kernel,
            "last_sampled_memory_events": last_memory_events,
            "sampled_temporary_bytes_peak": peak_tmp,
            "sampled_experiment_disk_peak": peak_disk,
            "systemd_final_properties": state,
            "log": "evidence/" + log.name,
            "resource_note": (
                "Kernel MemoryMax includes descendants and cache; summed RSS sampled "
                "at ~20 ms excluding metadata/disk polling can double-count shared pages "
                "and miss peaks; inspect cgroup memory.peak independently."
            ),
        }
    )
    service_path = ROOT / "evidence" / f"{a.name}.service.json"
    if service_path.exists():
        service = json.loads(service_path.read_text())
        if "after" in service:
            entry["cgroup_memory_peak_bytes"] = int(service["after"]["memory.peak"])
            entry["memory_events"] = service["after"]["memory.events"]
            entry["temporary_bytes_at_exit"] = service["temporary_bytes_at_exit"]
    if entry["status"] != "pass":
        (ROOT / "evidence/STOP.json").write_text(
            json.dumps(
                {
                    "package": "R0-CREDVALID-PO17-1",
                    "reason": stop or state or "command failure",
                    "failed_run": a.name,
                    "proof_attempts": ledger["proof_attempts"],
                    "further_proving_authorised": False,
                },
                indent=2,
            )
            + "\n"
        )
    if a.phase == "prove":
        cumulative = json.loads(cumulative_path.read_text())
        cumulative["attempts"][-1]["outcome"] = entry["status"]
        cumulative["attempts"][-1]["resource_record"] = "evidence/attempt3.json"
        cumulative_path.write_text(json.dumps(cumulative, indent=2) + "\n")
    ledgerpath.write_text(json.dumps(ledger, indent=2) + "\n")
    (ROOT / "evidence" / f"{a.name}.json").write_text(json.dumps(entry, indent=2) + "\n")
    systemctl("reset-failed", unit)
    print(json.dumps(entry, indent=2))
    raise SystemExit(0 if entry["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
