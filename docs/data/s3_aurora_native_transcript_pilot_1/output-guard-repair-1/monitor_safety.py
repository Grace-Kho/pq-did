"""Failure completion for the retained monitor; no native behaviour changes."""

import json
import os
import signal
import subprocess
import time
import traceback


def failure(error, context, persist):
    """Preserve the primary error before containment; secondary failures cannot replace it."""
    started = context.get("started")
    result = {
        "status": "failed",
        "exit_code": 1,
        "original_error": {"type": type(error).__name__, "message": str(error)[:3000]},
        "traceback": "".join(traceback.format_exception(error))[-12000:],
        "secondary_errors": [],
        "seconds": None,
        "conservative_charge_seconds": 60,
        "sampled_tree_RSS_peak": context.get("peak_rss") or None,
        "cgroup_memory_peak": None,
        "contained": False,
        "reaped": False,
        "resource_guard_passed": False,
    }

    def attempt(label, action):
        try:
            return action()
        except BaseException as secondary:
            result["secondary_errors"].append(
                {"phase": label, "type": type(secondary).__name__, "message": str(secondary)[:1000]}
            )
            return None

    attempt("persist-primary-error", lambda: persist(result))
    cg = context.get("cg")
    if cg is not None:
        value = attempt("read-memory-peak", lambda: (cg / "memory.peak").read_text())
        if value is not None:
            result["cgroup_memory_peak"] = attempt("parse-memory-peak", lambda: int(value))
    process = context.get("process")
    unit = context.get("unit")

    def control(*args):
        call = subprocess.run(
            ["systemctl", "--user", *args], capture_output=True, text=True, timeout=1
        )
        if call.returncode:
            raise RuntimeError(f"systemd {args}: exit {call.returncode}: {call.stderr[:500]}")
        return call.stdout

    def state():
        raw = control(
            "show",
            unit,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "ControlGroup",
        )
        pairs = [line.split("=", 1) for line in raw.splitlines()]
        if any(len(row) != 2 for row in pairs):
            raise ValueError("malformed systemd response")
        value = dict(pairs)
        required = {"LoadState", "ActiveState", "SubState", "ControlGroup"}
        if len(pairs) != len(value) or set(value) != required:
            raise ValueError("missing/duplicate systemd properties")
        return value

    if unit:
        before = attempt("query-before-containment", state)
        if before is None or before["ActiveState"] not in {"inactive", "failed"}:
            attempt(
                "kill-exact-cgroup",
                lambda: control("kill", "--kill-whom=all", "--signal=KILL", unit),
            )
            attempt("stop-exact-unit", lambda: control("stop", unit))
        after = attempt("query-after-containment", state)
        result["systemd_after"] = after
        if after is not None:

            def empty():
                if cg is not None and cg.exists():
                    return not any(p.read_text().strip() for p in cg.rglob("cgroup.procs"))
                return not after["ControlGroup"]

            absent = attempt("verify-cgroup-empty", empty)
            result["contained"] = bool(
                after["LoadState"] in {"loaded", "not-found"}
                and after["ActiveState"] in {"inactive", "failed"}
                and after["SubState"] in {"dead", "failed"}
                and absent
            )
    elif process is not None and context.get("owned_process_group"):
        # Used for the worker's own child session and the explicit harmless fixture.
        if attempt("poll-child", process.poll) is None:
            attempt("kill-owned-process-group", lambda: os.killpg(process.pid, signal.SIGKILL))
        result["contained"] = False  # Established by the bounded reap below.
    else:
        result["contained"] = process is None
    if process is not None:
        code = attempt("reap-child", lambda: process.wait(timeout=1))
        if code is None:
            attempt("kill-launcher", process.kill)
            code = attempt("reap-launcher", lambda: process.wait(timeout=1))
        result["reaped"] = code is not None
        result["child_exit_code"] = code
        if not unit and context.get("owned_process_group"):
            result["contained"] = result["reaped"]
    else:
        result["reaped"] = True
    if started is not None:
        result["seconds"] = time.monotonic() - started
        result["conservative_charge_seconds"] = result["seconds"]
    # No zero substitution for an unavailable observation or missing start time.
    attempt("persist-final-failure", lambda: persist(result))
    return result


def protect(function, guard, name):
    began = time.monotonic()
    try:
        return function(name)
    except BaseException as error:
        context = {"started": began}
        tb = error.__traceback__
        while tb is not None:
            if tb.tb_frame.f_globals is guard.__dict__ and tb.tb_frame.f_code.co_name == "main":
                context.update(tb.tb_frame.f_locals)
            tb = tb.tb_next

        def persist(value):
            guard.write(name + ".fatal.json", value)

        result = failure(error, context, persist)
        # Best-effort bookkeeping cannot erase the primary fatal record.
        try:
            path = guard.D / "run-ledger.json"
            rows = json.loads(path.read_text()) if path.exists() else []
            original = next((row for row in rows if row["name"] == name), None)
            result["original_resource_record"] = dict(original) if original else None
            row = original if original is not None else {"name": name}
            if original is None:
                rows.append(row)
            row.update(status="failed", exit_code=1, stop="fatal monitor/admission exception")
            row["limit_seconds"] = guard.CONFIG["command_reservations_seconds"][name]
            if result["seconds"] is not None:
                row["seconds"] = result["seconds"]
            guard.write(name + ".json", {**row, "failure": result})
            guard.write("run-ledger.json", rows)
            stop_name = (
                "STOP-" + name + ".json" if (guard.D / "STOP.json").exists() else "STOP.json"
            )
            guard.write(stop_name, {"phase": name, "original_error": result["original_error"]})
        except BaseException as secondary:
            result["secondary_errors"].append({"phase": "ledger", "message": str(secondary)[:1000]})
        try:
            persist(result)
        except BaseException as secondary:
            print("Failure persistence incomplete:", repr(error), repr(secondary))
        print(
            json.dumps(
                {"phase": name, "status": "failed", "original_error": result["original_error"]}
            )
        )
        return 1
