"""One guarded transient service, persistent phase budgets and proof-attempt ledger.

Run outside the editor sandbox so the existing systemd user manager is reachable.
No global service/default is changed. MemoryMax charges the whole descendant cgroup.
"""

import argparse
import fcntl
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / "r0_succinct_feasibility_1"
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


def output_disk():
    return sum(
        p.stat().st_size
        for p in ROOT.rglob("*")
        if p.is_file() and p.relative_to(ROOT).parts[0] not in ("tooling", "target", "tmp")
    )


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
    ap.add_argument("phase", choices=["setup", "build", "execute", "check"])
    ap.add_argument("name")
    ap.add_argument("--slot", type=int)
    ap.add_argument("--seconds", type=int, required=True)
    ap.add_argument("--memory", type=int, default=2 * GIB)
    ap.set_defaults(network=False)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    if a.phase in ("setup", "build", "execute") and (ROOT / "evidence/STOP.json").exists():
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
            "execute_prove": ["execute"],
            "execute": ["execute"],
            "check": ["check"],
        }.items()
    }
    allowed = {
        "setup": 1200 - sums["setup_build"],
        "build": 1200 - sums["setup_build"],
        "execute": min(300 - sums["execute"], 1800 - sums["execute_prove"], 60),
        "check": min(300 - sums["check"], 60),
    }[a.phase]
    if a.seconds > allowed:
        raise SystemExit(f"phase budget remaining {allowed}; requested {a.seconds}")
    if a.phase == "execute":
        if a.slot not in range(1, 7) or ledger["execution_runs"] >= 6:
            raise SystemExit("execution slot/count limit")
        if any(r.get("slot") == a.slot for r in ledger["runs"] if r["phase"] == "execute"):
            raise SystemExit("execution slot already used")
        if len(cmd) < 2 or Path(cmd[0]) != ROOT / "target/release/pqdid-r0-host" or cmd[1] != "run":
            raise SystemExit("execution-only host command required")
    if available() < a.memory + 2 * GIB:
        raise SystemExit("insufficient MemAvailable for worker plus 2 GiB reserve")
    if used_disk() >= 9 * GIB:
        raise SystemExit("conservative disk stop threshold reached")
    if output_disk() >= 60 * 1024**2:
        raise SystemExit("conservative output stop threshold reached")
    if (ROOT / "evidence" / f"{a.name}.json").exists():
        raise SystemExit("run name already used; no overwrite/retry")
    unit = "pqdid-r0cycle-" + a.name
    log = ROOT / "evidence" / f"{a.name}.log"
    output = open(log, "w")
    props = [
        "MemoryMax=" + str(a.memory),
        "ReadOnlyPaths=" + str(BASE),
        "MemorySwapMax=0",
        "CPUQuota=200%",
        "TasksMax=128",
        "RuntimeMaxSec=" + str(a.seconds),
        "TimeoutStopSec=2",
        "KillMode=control-group",
        "OOMPolicy=kill",
        "NoNewPrivileges=yes",
        "UMask=0077",
        "LimitCORE=0",
        "LimitFSIZE=" + str(2 * GIB),
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
        "R0_EXECUTION_SLOT": str(a.slot or 0),
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
        "RISC0_DEV_MODE_FORCE RISC0_PPROF_OUT RUST_LOG",
    ]
    launch += cmd
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
    ledger["runs"].append(entry)
    ledgerpath.write_text(json.dumps(ledger, indent=2) + "\n")
    start = time.monotonic()
    proc = subprocess.Popen(launch, stdout=output, stderr=subprocess.STDOUT)
    peak_rss = peak_charge = peak_disk = 0
    peak_swap = 0
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
            disk = used_disk()
            peak_disk = max(peak_disk, disk)
            if disk >= 9 * GIB:
                stop = "conservative disk stop threshold"
            if output_disk() >= 60 * 1024**2:
                stop = "conservative output stop threshold"
            if time.monotonic() - start > a.seconds + 5:
                stop = "external wall watchdog"
            if stop:
                systemctl("stop", unit)
            time.sleep(0.05)
        rc = proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            systemctl("stop", unit)
            proc.wait(timeout=10)
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
            "sampled_experiment_disk_peak": peak_disk,
            "systemd_final_properties": state,
            "log": "evidence/" + log.name,
            "resource_note": (
                "Kernel MemoryMax includes descendants and cache; summed RSS sampled "
                "at ~50 ms may double-count shared pages and miss peaks; inspect syst"
                "emd MemoryPeak independently."
            ),
        }
    )
    ledgerpath.write_text(json.dumps(ledger, indent=2) + "\n")
    (ROOT / "evidence" / f"{a.name}.json").write_text(json.dumps(entry, indent=2) + "\n")
    systemctl("reset-failed", unit)
    print(json.dumps(entry, indent=2))
    raise SystemExit(0 if entry["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
