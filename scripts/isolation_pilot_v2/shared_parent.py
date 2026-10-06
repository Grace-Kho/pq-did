"""One explicitly authorised shared parent; never chmod/chown an existing path."""

import os
from pathlib import Path

from layout import protected

PARENT = Path("/etc/sysusers.d")


def inspect_parent():
    protected(PARENT.parent, directory=True, gid=0)
    if PARENT.exists() or PARENT.is_symlink():
        protected(PARENT, directory=True, gid=0)
        return True
    return False


def ensure_parent():
    existed = inspect_parent()
    if existed:
        return False
    # Exclusive mkdir: a race is a failure, never automatic adoption or repair.
    parent = os.open(PARENT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(PARENT.name, mode=0o755, dir_fd=parent)
        fd = os.open(PARENT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    protected(PARENT, directory=True, uid=0, gid=0, mode=0o755)
    return True
