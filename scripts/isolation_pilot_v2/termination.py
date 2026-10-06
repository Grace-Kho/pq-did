"""Fixed-unit launch exclusion and fail-closed descendant termination checks.

Standard library only. Usable from the reviewed source before runtime installation.
No process-name matching, automatic socket deletion or configuration removal.
"""

import contextlib
import fcntl
import os
import stat
import subprocess
import time
from pathlib import Path

from layout import ACCOUNTS, ROLES, PilotError, check, protected, write_new

CGROOT = Path("/sys/fs/cgroup")
STOP = Path("/run/pqiso-stop")
LOCK = Path("/run/pqiso-launch.lock")
CASE_IDS = (
    "ISO-RUNTIME",
    "ISO-ROLE-m",
    "ISO-ROLE-i",
    "ISO-ROLE-va",
    "ISO-ROLE-vb",
    "ISO-CROSS-va",
    "ISO-CROSS-vb",
    "ISO-RECIPIENT",
    "ISO-DAC-DENIED",
    "ISO-ACL-DENIED",
    "ISO-FENCING",
    "ISO-ROTATION",
    "ISO-HOLDER",
    "ISO-FD",
    "ISO-MISCONFIG-peer-identity",
    "ISO-MISCONFIG-socket-mode",
    "ISO-MISCONFIG-writable-parent",
    "ISO-MISCONFIG-mutable-runtime",
    "ISO-RESTART-m",
    "ISO-RESTART-i",
    "ISO-RESTART-va",
    "ISO-RESTART-vb",
)
ROLE_UNITS = tuple(
    [f"pqiso-owner@{r}.service" for r in ROLES]
    + [f"pqiso-bootstrap@{r}.service" for r in ROLES]
    + [f"pqiso-client@{a}.service" for a in ACCOUNTS]
    + ["pqiso-replacement-m.service"]
)
GUARD_UNITS = tuple(
    f"pqiso-guard-{key.lower()}.service"
    for key in ("provision", "verify", *CASE_IDS, "shutdown", "rollback")
)
ALL_UNITS = (*ROLE_UNITS, *GUARD_UNITS, "pqiso.slice")
PROPERTIES = "Id,LoadState,ActiveState,SubState,ControlGroup,MainPID,ControlPID,Job"


def inhibited():
    return STOP.exists() or STOP.is_symlink()


def inhibit():
    protected(STOP.parent, directory=True)
    try:
        write_new(STOP, b"Pilot launch inhibited; retain until separately authorised review.\n")
    except FileExistsError:
        protected(STOP, gid=0, mode=0o600)


@contextlib.contextmanager
def gate(*, launching=False, deadline=None):
    """Serialise admission with teardown; hold through each manager start request."""
    deadline = time.monotonic() + 5 if deadline is None else deadline
    protected(LOCK.parent, directory=True)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        check(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1,
            "launch-lock",
        )
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                check(time.monotonic() < deadline, "launch-gate-timeout")
                time.sleep(0.01)
        if launching:
            check(not inhibited(), "launch-inhibited")
        yield
    finally:
        os.close(fd)


def command(args, deadline):
    remaining = deadline - time.monotonic()
    check(remaining > 0, "shutdown-deadline")
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "--no-pager", *args],
            capture_output=True,
            timeout=min(2, remaining),
            close_fds=True,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PilotError("shutdown-transport-unknown") from error
    check(len(result.stdout) + len(result.stderr) < 61440, "shutdown-output-limit")
    check(result.returncode == 0 and not result.stderr, "shutdown-query-or-command-failed")
    return result.stdout


def expected_cgroup(name):
    check(name in ALL_UNITS, "termination-unit-scope")
    if name == "pqiso.slice":
        return "/pqiso.slice"
    if name in {
        "pqiso-guard-provision.service",
        "pqiso-guard-shutdown.service",
        "pqiso-guard-rollback.service",
    }:
        return "/system.slice/" + name
    return "/pqiso.slice/" + name


def parse_query(data, units):
    try:
        blocks = data.decode("utf-8", errors="strict").strip().split("\n\n")
    except UnicodeError as error:
        raise PilotError("shutdown-malformed-response") from error
    check(len(blocks) == len(units), "shutdown-missing-unit")
    records = {}
    for block in blocks:
        row = {}
        for line in block.splitlines():
            key, separator, value = line.partition("=")
            check(separator and key not in row, "shutdown-malformed-property")
            row[key] = value
        name = row.get("Id")
        check(name in units and name not in records, "shutdown-unit-identity")
        required = set(PROPERTIES.split(","))
        if name == "pqiso.slice":
            required -= {"MainPID", "ControlPID"}
        check(set(row) == required, "shutdown-required-properties")
        check(row["LoadState"] in {"loaded", "not-found"}, "shutdown-load-unknown")
        check(
            row["ActiveState"] in {"active", "inactive", "failed", "activating", "deactivating"},
            "shutdown-state-unknown",
        )
        check(row["ControlGroup"] in {"", expected_cgroup(name)}, "shutdown-cgroup-scope")
        for key in required & {"MainPID", "ControlPID"}:
            check(row[key].isascii() and row[key].isdecimal(), "shutdown-pid-malformed")
        records[name] = row
    check(set(records) == set(units), "shutdown-incomplete-units")
    return records


def query(units, deadline):
    return parse_query(
        command(["show", "--all", "--property=" + PROPERTIES, *units], deadline), units
    )


def populated(name):
    check((CGROOT / "cgroup.controllers").is_file(), "cgroup-interface-unavailable")
    path = CGROOT / expected_cgroup(name).lstrip("/")
    check(path.resolve() == path, "cgroup-path-alias")
    try:
        fd = os.open(path / "cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        check(not path.exists(), "cgroup-events-missing")
        return False
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(4097)
    check(len(data) <= 4096, "cgroup-events-size")
    return parse_events(data)


def parse_events(data):
    try:
        pairs = [line.split() for line in data.decode("ascii").splitlines()]
        values = dict(pairs)
    except (ValueError, UnicodeError) as error:
        raise PilotError("cgroup-events-malformed") from error
    check(
        len(values) == len(pairs) and values.get("populated") in {"0", "1"},
        "cgroup-populated-missing",
    )
    return values["populated"] == "1"


def complete(records):
    result = True
    for name, row in records.items():
        inactive = row["ActiveState"] in {"inactive", "failed"}
        inactive &= row["SubState"] in {"dead", "failed"} and row["Job"] == ""
        inactive &= all(row.get(key, "0") == "0" for key in ("MainPID", "ControlPID"))
        # Evaluate occupancy even when PID/state looks inactive or not-found.
        occupied = populated(name)
        result &= inactive and not occupied
    return result


def terminate(*, emergency=False, units=ROLE_UNITS, deadline=None):
    """Caller owns the gate. Unknown transport/state prevents a complete result."""
    deadline = time.monotonic() + 5 if deadline is None else deadline
    check(set(units) <= set(ALL_UNITS) and len(set(units)) == len(units), "termination-scope")
    before = query(units, deadline)
    loaded = [name for name, row in before.items() if row["LoadState"] == "loaded"]
    if emergency:
        active = [
            name
            for name in loaded
            if name != "pqiso.slice"
            and (
                before[name]["ActiveState"] in {"active", "activating", "deactivating"}
                or populated(name)
            )
        ]
        if active:
            command(["kill", "--kill-whom=all", "--signal=KILL", *active], deadline)
    if loaded:
        command(["--no-block", "--job-mode=replace-irreversibly", "stop", *loaded], deadline)
    while True:
        rows = query(units, deadline)
        if complete(rows):
            return {"complete": True, "units": rows, "descendant_cgroups_empty": True}
        check(time.monotonic() < deadline, "shutdown-incomplete")
        time.sleep(0.02)
