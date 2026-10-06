"""Explicit Linux cross-UID endpoint policy; the legacy private endpoint is unchanged."""

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .codec import require


def no_acl(path):
    """Refuse ACL grants beyond the audited mode bits, including inherited defaults."""
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        if error.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise
    require(not {"system.posix_acl_access", "system.posix_acl_default"} & set(names), "path-acl")


@dataclass(frozen=True)
class EndpointPolicy:
    owner_uid: int
    owner_gid: int
    transport_gid: int

    def __post_init__(self):
        require(
            all(
                type(v) is int and 0 < v < 1 << 32
                for v in (self.owner_uid, self.owner_gid, self.transport_gid)
            ),
            "endpoint-identity",
        )
        require(self.owner_gid != self.transport_gid, "endpoint-groups")

    def validate(self, value, *, exists):
        path = Path(value)
        require(path.is_absolute() and path.resolve() == path, "endpoint-path")
        require(len(os.fsencode(path)) <= 107, "endpoint-path")
        require(all(not p.is_symlink() for p in (path, *path.parents)), "endpoint-path")
        parent = path.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode), "endpoint-parent")
        require(
            (parent.st_uid, parent.st_gid) == (self.owner_uid, self.transport_gid), "endpoint-owner"
        )
        require(stat.S_IMODE(parent.st_mode) == 0o2750, "endpoint-mode")
        no_acl(path.parent)
        for ancestor in path.parents[1:]:
            info = ancestor.lstat()
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and not stat.S_IMODE(info.st_mode) & 0o022,
                "endpoint-ancestor",
            )
            no_acl(ancestor)
        if exists:
            info = path.lstat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_nlink == 1, "endpoint-type")
            require(
                (info.st_uid, info.st_gid) == (self.owner_uid, self.transport_gid), "endpoint-owner"
            )
            require(stat.S_IMODE(info.st_mode) == 0o660, "endpoint-mode")
            no_acl(path)
        else:
            require(not path.exists(), "endpoint-exists")
        return path

    def bind_identity(self):
        require((os.getuid(), os.getgid()) == (self.owner_uid, self.owner_gid), "endpoint-owner")
        require(self.transport_gid in os.getgroups(), "endpoint-groups")
