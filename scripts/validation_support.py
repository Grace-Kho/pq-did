"""Operational profile and Linux process supervision, separate from circuit identity."""

import json
import os
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def extended_profile():
    return json.loads((ROOT / "configs/validation_profiles.json").read_text())[
        "hash_enrolment_extended_v1"
    ]


def resident_bytes(pid):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except FileNotFoundError:
        pass
    return 0


def supervise(command, *, profile, log, heartbeat=None, env=None):
    """One child at a time; stop its process group on RSS/time/log ceiling.

    RSS samples can miss transient overshoot. RLIMIT_AS is set separately by the
    child; Linux RLIMIT_RSS would not enforce the intended bound.
    """
    peak = 0
    reason = None
    started = last_case = time.monotonic()
    heartbeat_stamp = None
    with Path(log).open("w") as output:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        try:
            while process.poll() is None:
                now = time.monotonic()
                peak = max(peak, resident_bytes(process.pid))
                if heartbeat is not None and Path(heartbeat).exists():
                    stamp = Path(heartbeat).stat().st_mtime_ns
                    if stamp != heartbeat_stamp:
                        heartbeat_stamp, last_case = stamp, now
                if peak > profile["rss_ceiling_bytes"]:
                    reason = "RSS watchdog ceiling"
                elif now - last_case >= profile["case_wall_seconds"]:
                    reason = "case wall-time limit"
                elif Path(log).stat().st_size > profile["case_log_bytes"]:
                    reason = "case log-storage limit"
                if reason:
                    break
                time.sleep(profile["rss_poll_seconds"])
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        returncode = process.wait()
    return {
        "returncode": returncode,
        "reason": reason,
        "sampled_peak_rss_bytes": peak,
        "supervised_seconds": time.monotonic() - started,
        "rss_poll_seconds": profile["rss_poll_seconds"],
        "log_bytes": Path(log).stat().st_size,
    }
