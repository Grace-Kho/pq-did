"""Fixed synthetic-pilot layout and bounded metadata I/O; no mutation on import."""

import errno
import grp
import hashlib
import json
import os
import pwd
import stat
from pathlib import Path

PROJECT = Path("/home/grace/projects/pq-did")
RELEASE = Path("/opt/pqiso/r1")
CONFIG = Path("/etc/pqiso")
STATE = Path("/var/lib/pqiso")
RUN = Path("/run/pqiso")
PROPOSAL = PROJECT / "docs/proposals/s2_authority_isolation_pilot_1"
EVIDENCE = PROJECT / "docs/data/s2_authority_isolation_pilot_1"
ROLES = {"m": "manager", "i": "issuer", "va": "verifier0", "vb": "verifier1"}
ACCOUNTS = tuple(f"pqiso-{kind}-{r}" for r in ROLES for kind in ("o", "w")) + (
    "pqiso-admin",
    "pqiso-observer",
    "pqiso-rec-a",
    "pqiso-rec-b",
    "pqiso-denied",
)
IPC_GROUPS = tuple("pqiso-ipc-" + r for r in ROLES)
UNITS = (
    "pqiso.slice",
    "pqiso-owner@.service",
    "pqiso-client@.service",
    "pqiso-replacement-m.service",
    "pqiso-bootstrap@.service",
)
LIMIT = 65536


class PilotError(Exception):
    """Public fixed failure label; never carries a private input."""


def check(value, label):
    if not value:
        raise PilotError(label)


def object_pairs(rows):
    result = {}
    for name, value in rows:
        check(name not in result, "duplicate-json-key")
        result[name] = value
    return result


def read_bytes(path, limit=LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "private-file-type")
        check(info.st_size <= limit, "input-size")
        value = stream.read(limit + 1)
        check(len(value) <= limit and len(value) == info.st_size, "input-size")
        return value


def read_json(path, limit=LIMIT):
    return json.loads(read_bytes(path, limit), object_pairs_hook=object_pairs)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def write_new(path, value, *, uid=0, gid=0, mode=0o600):
    check(type(value) is bytes and len(value) <= 1048576, "output-size")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        if (uid, gid) != (os.getuid(), os.getgid()):
            os.fchown(stream.fileno(), uid, gid)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def atomic_json(path, value):
    """Only root-owned creation/evidence records inside the fixed new pilot namespace."""
    path = Path(path)
    check(path.is_relative_to(CONFIG) or path.is_relative_to(STATE), "record-path")
    temporary = path.with_suffix(path.suffix + ".new")
    write_new(temporary, json_bytes(value))
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def no_acl(path):
    try:
        values = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        if error.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise
    check(
        not {"system.posix_acl_access", "system.posix_acl_default", "security.capability"}
        & set(values),
        "unsafe-acl",
    )


def protected(path, *, uid=0, gid=None, mode=None, directory=False, ancestors=True):
    path = Path(path)
    check(path.is_absolute() and path.resolve() == path and not path.is_symlink(), "unsafe-path")
    info = path.lstat()
    check((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode), "unsafe-type")
    check(info.st_uid == uid and (gid is None or info.st_gid == gid), "unsafe-owner")
    check(mode is None or stat.S_IMODE(info.st_mode) == mode, "unsafe-mode")
    check(not stat.S_IMODE(info.st_mode) & 0o022, "writable-protected-path")
    check(directory or info.st_nlink == 1, "unsafe-hardlink")
    check(not stat.S_IMODE(info.st_mode) & 0o6000, "set-id-protected-path")
    no_acl(path)
    if ancestors:
        for parent in path.parents:
            parent_info = parent.lstat()
            check(stat.S_ISDIR(parent_info.st_mode) and not parent.is_symlink(), "unsafe-parent")
            check(
                parent_info.st_uid == 0 and not stat.S_IMODE(parent_info.st_mode) & 0o022,
                "writable-ancestor",
            )
            no_acl(parent)
    return info


def expected_groups(account):
    check(account in ACCOUNTS, "unknown-account")
    if account in {"pqiso-admin", "pqiso-observer"}:
        return IPC_GROUPS
    if account in {"pqiso-rec-a", "pqiso-rec-b"}:
        return ("pqiso-ipc-i",)
    if account == "pqiso-denied":
        return ()
    groups = ("pqiso-ipc-" + account.rsplit("-", 1)[1],)
    return (*groups, "pqiso-ipc-m") if account == "pqiso-o-i" else groups


def identities():
    result = {}
    for name in ACCOUNTS:
        entry, group = pwd.getpwnam(name), grp.getgrnam(name)
        check(entry.pw_uid != 0 and entry.pw_gid == group.gr_gid, "identity-mapping")
        check(
            entry.pw_shell == "/usr/sbin/nologin" and entry.pw_dir == "/nonexistent", "login-policy"
        )
        groups = sorted({entry.pw_gid, *(grp.getgrnam(g).gr_gid for g in expected_groups(name))})
        check(sorted(os.getgrouplist(name, entry.pw_gid)) == groups, "group-membership")
        result[name] = {"uid": entry.pw_uid, "gid": entry.pw_gid, "groups": groups}
    check(len({r["uid"] for r in result.values()}) == len(ACCOUNTS), "duplicate-uid")
    check(len({r["gid"] for r in result.values()}) == len(ACCOUNTS), "duplicate-gid")
    return result


def root_required():
    check(os.getuid() == os.geteuid() == 0, "host-administrator-required")
    check(
        Path("/proc/self/uid_map").read_text().split() == ["0", "0", "4294967295"],
        "real-host-root-required",
    )


def collision_report():
    found = []
    for name in ACCOUNTS:
        try:
            pwd.getpwnam(name)
            found.append("account:" + name)
        except KeyError:
            pass
    for name in (*ACCOUNTS, *IPC_GROUPS):
        try:
            grp.getgrnam(name)
            found.append("group:" + name)
        except KeyError:
            pass
    paths = [Path("/opt/pqiso"), CONFIG, STATE, RUN]
    paths += [Path("/etc/systemd/system") / n for n in UNITS]
    paths += [Path("/etc/sysusers.d/pqiso.conf"), Path("/etc/tmpfiles.d/pqiso.conf")]
    found += [str(p) for p in paths if p.exists() or p.is_symlink()]
    return found
