"""Trusted fixed-unit controller; client actions always execute as configured non-root users."""

import os
import subprocess
import time
from pathlib import Path

from layout import (
    ACCOUNTS,
    CONFIG,
    ROLES,
    RUN,
    STATE,
    check,
    identities,
    json_bytes,
    protected,
    read_bytes,
    read_json,
    root_required,
    write_new,
)

EVENTS = []


def ctl(*args, timeout=5, ok=True):
    result = subprocess.run(
        ["/usr/bin/systemctl", *args],
        capture_output=True,
        timeout=timeout,
        close_fds=True,
        stdin=subprocess.DEVNULL,
    )
    check(len(result.stdout) + len(result.stderr) < 61440, "controller-output")
    check(not ok or result.returncode == 0, "systemd-command")
    return result


def owned_units():
    return (
        [f"pqiso-owner@{r}.service" for r in ROLES]
        + [f"pqiso-bootstrap@{r}.service" for r in ROLES]
        + [f"pqiso-client@{a}.service" for a in ACCOUNTS]
        + ["pqiso-replacement-m.service"]
    )


def verify():
    root_required()
    from runtime import release_check

    release_check()
    ids = identities()
    for name, expected in read_json(CONFIG / "creation.json")["created_files"].items():
        from layout import digest

        protected(Path(name), mode=0o644)
        check(digest(name) == expected, "installed-file-changed")
    protected(CONFIG / "ACTIVATION-AUTHORISED", mode=0o600)
    return ids


def shutdown():
    root_required()
    check((CONFIG / "creation.json").exists(), "unowned-deployment")
    for unit in owned_units():
        ctl("stop", unit, ok=False)
        result = ctl("show", unit, "-p", "MainPID", "--value", ok=False)
        check(result.stdout.strip() in {b"0", b""}, "surviving-process")
    # SIGTERM handler normally removes listeners. No stale automatic unlink fallback.
    check(not any(RUN.glob("*/*.sock")), "stale-endpoint-review-required")


def concurrency_admission():
    result = ctl("show", *owned_units(), "-p", "MainPID", "--value", ok=False)
    running = sum(line.isdigit() and int(line) > 0 for line in result.stdout.splitlines())
    check(running < 4, "controlled-child-limit")


def start(role, *, replacement=False):
    concurrency_admission()
    check(role in ROLES, "role")
    unit = "pqiso-replacement-m.service" if replacement else f"pqiso-owner@{role}.service"
    check(not replacement or role == "m", "replacement-role")
    endpoint = RUN / role / ("replacement.sock" if replacement else "owner.sock")
    check(not endpoint.exists(), "existing-listener")
    ctl("start", unit)
    until = time.monotonic() + 3
    while not endpoint.exists():
        check(time.monotonic() < until, "owner-readiness-timeout")
        time.sleep(0.01)
    info = ctl("show", unit, "-p", "MainPID", "--value").stdout.strip()
    check(info.isdigit() and int(info) > 0, "owner-process")
    # Independent kernel observation, not owner/client-provided claims.
    status = Path("/proc", info.decode(), "status").read_text()
    identity = identities()["pqiso-o-" + role]
    check(
        next(line.split()[1:] for line in status.splitlines() if line.startswith("Uid:"))
        == [str(identity["uid"])] * 4,
        "kernel-owner-uid",
    )
    EVENTS.append(
        {
            "owner": role,
            "pid": int(info),
            "uid": identity["uid"],
            "gid": identity["gid"],
            "groups": identity["groups"],
            "kernel_uid_observed": True,
        }
    )
    return unit


def stop(unit):
    check(unit in owned_units(), "unit-scope")
    ctl("stop", unit)
    check(ctl("show", unit, "-p", "MainPID", "--value").stdout.strip() == b"0", "surviving-process")


def client(account, request, *, asynchronous=False):
    concurrency_admission()
    check(account in ACCOUNTS, "client-account")
    uid = identities()[account]
    unit = f"pqiso-client@{account}.service"
    check(
        ctl("show", unit, "-p", "MainPID", "--value", ok=False).stdout.strip() in {b"0", b""},
        "client-already-running",
    )
    directory = CONFIG / "clients" / account
    for name in ("request.json", "go"):
        path = directory / name
        if path.exists():
            protected(path, gid=uid["gid"], mode=0o640)
            path.unlink()
    for name in ("response.bin", "identity.json", "connected"):
        path = STATE / "clients" / account / name
        if path.exists():
            protected(path, uid=uid["uid"], gid=uid["gid"], mode=0o600, ancestors=False)
            path.unlink()
    write_new(directory / "request.json", json_bytes(request), gid=uid["gid"], mode=0o640)
    ctl("reset-failed", unit, ok=False)
    ctl("start", unit)
    if asynchronous:
        return unit
    return finish_client(account)


def finish_client(account):
    from pqdid.persistence.codec import decode

    unit = f"pqiso-client@{account}.service"
    until = time.monotonic() + 5
    while ctl("show", unit, "-p", "MainPID", "--value").stdout.strip() != b"0":
        check(time.monotonic() < until, "client-deadline")
        time.sleep(0.01)
    check(
        ctl("show", unit, "-p", "Result", "--value").stdout.strip() == b"success",
        "client-harness-failure",
    )
    root = STATE / "clients" / account
    observed = read_json(root / "identity.json")
    expected = identities()[account]
    check(all(observed[k] == expected[k] for k in ("uid", "gid", "groups")), "client-identity")
    check(
        ctl("show", unit, "-p", "User", "--value").stdout.strip().decode() == account,
        "unit-client-user",
    )
    check(
        int(ctl("show", unit, "-p", "ExecMainPID", "--value").stdout.strip()) == observed["pid"],
        "client-unit-pid",
    )
    EVENTS.append({"account": account, **observed, "systemd_pid_user_matched": True})
    result = decode(read_bytes(root / "response.bin"))
    return result, observed


def rpc(role, operation, arguments=(), *, account=None, replacement=False, **options):
    from pqdid.persistence.codec import encode

    account = account or "pqiso-w-" + role
    name = (
        "admin"
        if account == "pqiso-admin"
        else "observer"
        if account == "pqiso-observer"
        else "recipient-a"
        if account == "pqiso-rec-a"
        else "recipient-b"
        if account == "pqiso-rec-b"
        else "writer"
    )
    return client(
        account,
        {
            "mode": "rpc",
            "role": role,
            "token": role + ":" + name,
            "operation": operation,
            "arguments": encode(arguments).hex(),
            "replacement": replacement,
            **options,
        },
    )[0]


def head(role, **options):
    result = rpc(role, "status", account="pqiso-observer", **options)
    check(result[0] == b"STATUS", "status-handshake")
    return result[2]


def admit(role, ticket, *, replacement=False):
    result = rpc(
        role, "replace", (os.urandom(32), ticket), account="pqiso-admin", replacement=replacement
    )
    check(result[0] == b"ADMITTED", "explicit-admission")
    return result[1]


def bootstrap(role):
    concurrency_admission()
    check(role in ROLES, "bootstrap-role")
    unit = f"pqiso-bootstrap@{role}.service"
    ctl("start", unit, timeout=5)
    check(
        ctl("show", unit, "-p", "Result", "--value").stdout.strip() == b"success",
        "bootstrap-failed",
    )
    marker = CONFIG / "owners" / role / "BOOTSTRAP"
    protected(marker, mode=0o644)
    marker.unlink()
